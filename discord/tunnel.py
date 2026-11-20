# create a quick cf tunnel

import asyncio
import logging, re
import shutil
import subprocess, threading
import logserv

log = logging.getLogger("rktunnel")

cloudflaredregex = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def start(bot):
	asyncio.run_coroutine_threadsafe(logserv.start(), bot.loop)
	threading.Thread(target=makecloudflared, args=(bot,), daemon=True).start()


def makecloudflared(bot):
	if not shutil.which("cloudflared"):
		log.info("no cloudflared wtf")
		return
	
	p = subprocess.Popen(
		["cloudflared", "tunnel", "--url", f"http://localhost:{logserv.PORT}", "--no-autoupdate"],
		stdout=subprocess.PIPE, 
		stderr=subprocess.STDOUT, 
		text=True
	)
	found = False
	for line in p.stdout:
		if not found:
			m = cloudflaredregex.search(line)
			if m:
				bot.tunnel_url = m.group(0)
				log.info(f"live cf: {bot.tunnel_url}")
				found = True
	p.wait()
