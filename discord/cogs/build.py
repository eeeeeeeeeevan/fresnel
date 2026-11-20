import asyncio
import hashlib
import os
import time

import builder
import discord
import features
import machines
from discord import app_commands
from discord.ext import commands


class Wizard(discord.ui.View):
	def __init__(self, cog, user):
		super().__init__(timeout=600)
		self.cog = cog
		self.user_id = user
		self.features = {}

		for i, feat in enumerate(features.all[:5]):
			self.add_item(toggle(self, feat, 1))
		self.add_item(button("start build", discord.ButtonStyle.primary, self.confirm, 2))
		self.add_item(button("nvm", discord.ButtonStyle.danger, self.cancel, 2))

	async def confirm(self, interaction):
		for c in self.children:
			c.disabled = True
		await interaction.response.edit_message(view=self)
		await self.cog.start_build(interaction, self.features)

	async def cancel(self, interaction):
		for c in self.children:
			c.disabled = True
		await interaction.response.edit_message(content="cancelled", view=self)

	async def interaction_check(self, interaction):
		return interaction.user.id == self.user_id


def toggle(wizard, feat, row):
	btn = discord.ui.Button(label=f"{feat.LABEL}: OFF", style=discord.ButtonStyle.secondary, row=row)

	async def cb(interaction):
		wizard.features[feat.KEY] = not wizard.features.get(feat.KEY, False)
		btn.label = f"{feat.LABEL}: {'ON' if wizard.features[feat.KEY] else 'OFF'}"
		btn.style = discord.ButtonStyle.success if wizard.features[feat.KEY] else discord.ButtonStyle.secondary
		await interaction.response.edit_message(view=wizard)

	btn.callback = cb
	return btn


def button(label, style, fn, row):
	btn = discord.ui.Button(label=label, style=style, row=row)
	btn.callback = fn
	return btn


class BuildCog(commands.Cog):
	def __init__(self, bot):
		self.bot = bot

	@app_commands.command(name="build", description="build and spit out tarball")
	async def build(self, interaction):
		if not builder.allowed(interaction.user.id):
			await interaction.response.send_message("not whitelisted", ephemeral=True)
			return

		embed = discord.Embed(
			title="kit builder",
			description="targets FreeBSD 14.5 amd64. best works on UFS but other fs magic is handle via vfs magic too",
			color=0x000000)
		embed.add_field(name="queue", value=f"{builder.queue_len()} waiting")
		await interaction.response.send_message(embed=embed, view=Wizard(self, interaction.user.id), ephemeral=True)

	async def start_build(self, interaction, features):
		alias = machines.random_alias()
		name = f"{alias}-{int(time.time())}"

		if getattr(self.bot, "tunnel_url", None):
			url = self.bot.tunnel_url
			await interaction.followup.send(
				f"<@{interaction.user.id}> queued\n"
				f"read logs: {url}/?u={interaction.user.id}&k={builder.link_token(interaction.user.id)}")
		else:
			await interaction.followup.send(f"<@{interaction.user.id}> queued")

		try:
			tar, _, dd, pub = await builder.run(interaction.user.id, name, features)
		except builder.QueueFull:
			await interaction.followup.send("queue full (max 3 waiting), try again later")
			return
		except builder.BuildError as e:
			await interaction.followup.send(content=f"build failed\n```{e.log_tail[-1400:]}```")
			return

		machines.add(interaction.user.id, alias, dd, pub)

		extra = f"\nmachine name `{alias}` mid (machine id) `{dd}`"
		await interaction.followup.send(
			content=f"<@{interaction.user.id}> built `{name}`{extra}",
			file=discord.File(tar, filename=f"{name}.tar"))

		await asyncio.sleep(10)
		try:
			os.remove(tar)
		except OSError:
			pass


async def setup(bot):
	await bot.add_cog(BuildCog(bot))
