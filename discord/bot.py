import glob, logging, os, sys, threading

import discord
from discord.ext import commands

import tunnel

log = logging.getLogger("rkbot")


class Bot(commands.Bot):
	def __init__(self):
		super().__init__(command_prefix="!", intents=discord.Intents.default())
		self.tunnel_url = None

	async def setup_hook(self):
		here = os.path.dirname(os.path.abspath(__file__))
		for path in sorted(glob.glob(f"{here}/cogs/[!_]*.py")):
			name = "cogs." + os.path.basename(path)[:-3]
			await self.load_extension(name)
			log.info(f"cmd loaded {name}")

		guild = os.environ.get("GUILD_ID")
		if guild:
			synced = await self.tree.sync(discord.Object(id=int(guild)))
		else:
			synced = await self.tree.sync()
		log.info(f"{len(synced)} loaded")

	async def on_ready(self):
		threading.Thread(target=tunnel.start, args=(self,), daemon=True).start()
		log.info(f"{self.user}")


def main():
	logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
	token = os.environ.get("DISCORD_TOKEN")
	if not token:
		print("DISCORD_TOKEN not set", file=sys.stderr)
		return 1
	Bot().run(token)


if __name__ == "__main__":
	raise SystemExit(main())
