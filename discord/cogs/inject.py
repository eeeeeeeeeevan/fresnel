import asyncio
import secrets
import shlex
import discord
from discord import app_commands
from discord.ext import commands
import machines
import mqtt


PROGOK = "█"
PROGBAD = "░"


def isanelf(data):
	if len(data) < 64 or data[:4] != b"\x7fELF":
		return False
	if data[4] != 2 or data[5] != 1:
		return False
	if int.from_bytes(data[16:18], "little") != 1:
		return False
	if int.from_bytes(data[18:20], "little") != 62:
		return False
	return True


def bar(pct):
	filled = pct * 20 // 100
	return PROGOK * filled + PROGBAD * (20 - filled)


def inject_embed(alias, pct=0, note=None):
	embed = discord.Embed(
		title="sideloading kernel module",
		description=f"on: `{discord.utils.escape_markdown(alias)}`",
		color=0x000000)
	value = f"`{bar(pct)}` **{pct}%**"
	if note:
		value += f"\n{note[:500]}"
	embed.add_field(name="progress", value=value, inline=False)
	return embed


class InjectCog(commands.Cog):
	def __init__(self, bot):
		self.bot = bot

	@app_commands.command(name="inject", description="remote kernel module injection")
	@app_commands.describe(alias="machine name", file="kernel module")
	async def inject(self, interaction, alias: str, file: discord.Attachment):
		m = machines.get(alias, interaction.user.id)
		if not m:
			await interaction.response.send_message("wtf is this machine", ephemeral=True)
			return
		if file.size > 25 * 1024 * 1024:
			await interaction.response.send_message("module too large. wtf", ephemeral=True)
			return

		await interaction.response.defer(ephemeral=True, thinking=True)

		tag = secrets.token_hex(4)
		dirpath = f"/tmp/.inj{tag}"
		path = f"{dirpath}/m"
		d = shlex.quote(dirpath)
		p = shlex.quote(path)
		sess = None

		msg = await interaction.followup.send(embed=inject_embed(alias))

		async def render(pct=0, note=None):
			await msg.edit(embed=inject_embed(alias, pct, note))

		try:
			# prehaps this is retarded
			data = await file.read()
			if not isanelf(data):
				await render(note="not an elf you retard")
				return

			await machines.wake(m["mid"])
			try:
				sess = await asyncio.to_thread(mqtt.Session, m["mid"], m.get("pub"))
			except OSError as e:
				await render(note=f"cant get targ: {e}")
				return
			last = -1

			async def progress(done, total):
				nonlocal last
				pct = done * 100 // total
				if pct == last or (pct < 100 and pct - last < 5):
					return
				last = pct
				await render(pct)

			await sess.upload(path, data, on_progress=progress)

			old = sess
			sess = None
			try:
				sess = await asyncio.to_thread(mqtt.Session, m["mid"], m.get("pub"))
			except OSError as e:
				await asyncio.to_thread(old.close)
				await render(note=f"reconnect failed: {e}")
				return
			await asyncio.to_thread(old.close)

			mount = (await asyncio.to_thread(
				sess.send,
				f"mkdir -p {d} && mount -t tmpfs tmpfs {d} && echo OKWEGOOD",
				timeout=30)).decode(errors="replace")
			if "OKWEGOOD" not in mount:
				await render(100, f"mount failed: {mount[-300:]}".strip())
				return

			await asyncio.to_thread(sess.finish_upload)
			"""
			this expects use of the ef.object trick, which is why it grabs the id from kldload -v
			then unloads it with kldunload -i to trigger it so your shit remains
			"""
			cmd = f"""sleep 1; out=$(kldload -v {p} 2>&1); echo "$out"; kid=$(printf '%s\\n' "$out" | sed -n 's/.*id=\\([0-9][0-9]*\\).*/\\1/p'); [ -n "$kid" ] && kldunload -i "$kid" || true; rm -f {p}; umount {d} 2>/dev/null || true; rmdir {d} 2>/dev/null || true"""
			await asyncio.to_thread(sess.send, cmd, timeout=120)
			await render(100)
		except Exception as e:
			await render(note=f"{type(e).__name__}: {e}")
		finally:
			if sess is not None:
				await asyncio.to_thread(sess.close)


async def setup(bot):
	await bot.add_cog(InjectCog(bot))
