import asyncio
import hmac
import os

import aiohttp
from aiohttp import web

import builder

PORT = int(os.environ.get("LOG_PORT", "8080"))
pg = None
sg = None


def page(u, k):
	global pg
	if pg is None:
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "terminal.html")) as f:
			pg = f.read()
	return pg.replace("__U__", u).replace("__K__", k)


def shell_page():
	global sg
	if sg is None:
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "shell.html")) as f:
			sg = f.read()
	return sg


def check(u, k):
	return u and k and hmac.compare_digest(builder.link_token(u), k)


async def index(request):
	u = request.query.get("u", "")
	k = request.query.get("k", "")
	if not check(u, k):
		raise web.HTTPNotFound
	return web.Response(text=page(u, k), content_type="text/html")


async def shell_page_handler(request):
	claims = builder.verify_shell(request.query.get("t", ""))
	if not claims:
		raise web.HTTPNotFound
	return web.Response(text=shell_page(), content_type="text/html")


async def shell_ws(request):
	claims = builder.verify_shell(request.query.get("t", ""))
	if not claims:
		raise web.HTTPNotFound

	ws = web.WebSocketResponse()
	await ws.prepare(request)

	import mqtt
	loop = asyncio.get_event_loop()
	try:
		session = await loop.run_in_executor(None,
			lambda: mqtt.Session(claims["m"], claims.get("pub")))
	except OSError as e:
		await ws.send_str(f"!! {e}")
		return ws

	chunk_q = asyncio.Queue()

	# chunk it greedily instead of waiting; otherwise something like ls -aril /* will take forever to fully chunk and potentially TO
	last_seen = asyncio.Event()
	def on_chunk(data):
		loop.call_soon_threadsafe(chunk_q.put_nowait, data)
	session.on_output = on_chunk

	cmd_state = {"done": True}

	async def drain():
		while True:
			chunk = await chunk_q.get()
			if chunk is None:
				break
			if cmd_state["done"]:
				continue
			text = chunk[1:].decode(errors="replace")
			if text:
				await ws.send_str(text)
			if chunk[0] == 0:
				await ws.send_str("\x00")
				last_seen.set()
				cmd_state["done"] = True

	drainer = asyncio.create_task(drain())

	await ws.send_str(f"+ shell on {claims['n']} have fun")
	await ws.send_str("\x00")

	try:
		async for msg in ws:
			line = msg.data.strip()
			if not line:
				continue
			if line == "exit":
				break
			last_seen.clear()
			cmd_state["done"] = False
			await loop.run_in_executor(None, session.send, line)
			try:
				await asyncio.wait_for(last_seen.wait(), timeout=120)
			except asyncio.TimeoutError:
				await ws.send_str("\x00")
	except Exception:
		pass
	finally:
		session.on_output = None
		chunk_q.put_nowait(None)
		drainer.cancel()
		session.close()
	return ws


async def ws(request):
	if not check(request.match_info["u"], request.match_info["k"]):
		raise web.HTTPNotFound
	ws = web.WebSocketResponse()

	await ws.prepare(request)

	builder.ws_clients.add(ws)
	try:
		await ws.send_str(builder.live_title)
		for line in builder.live[-400:]:
			await ws.send_str(line)
		async for _ in ws:
			pass
	finally:
		builder.ws_clients.discard(ws)
	return ws


async def start():
	app = web.Application()
	app.router.add_get("/", index)
	app.router.add_get("/s", shell_page_handler)
	app.router.add_get("/sws", shell_ws)
	app.router.add_get("/ws/{u}/{k}", ws)
	runner = web.AppRunner(app)

	await runner.setup()
	print("! ok")

	await web.TCPSite(runner, "127.0.0.1", PORT).start()
