module.exports = {
	apps: [{
		name: "bot",
		script: "python3",
		args: "bot.py",
		cwd: "/app/discord",
		max_restarts: 10,
		restart_delay: 5000,
	}],
};
