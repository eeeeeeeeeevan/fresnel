// catch me if you can
import { connect } from "cloudflare:sockets";

const BROKER = { hostname: "test.mosquitto.org", port: 1883 };

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (!env.TOKEN || url.searchParams.get("t") !== env.TOKEN) {
			return new Response("no", { status: 403 });
		}
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("ws required", { status: 400 });
		}

		const [client, server] = new WebSocketPair();
		server.accept();

		let socket;
		try {
			socket = connect(BROKER, { allowHalfOpen: false });
			await socket.opened;
		} catch (e) {
			try { server.close(1011, "broker connect failed"); } catch {}
			return new Response(null, { status: 101, webSocket: client });
		}

		const writer = socket.writable.getWriter();

		server.addEventListener("message", (ev) => {
			// cool ws to tcp stream trick
			writer.write(new Uint8Array(ev.data)).catch(() => {});
		});

		(async () => {
			const reader = socket.readable.getReader();
			try {
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					server.send(value);
				}
			} catch {}
			try { server.close(1000); } catch {}
		})();

		const teardown = () => {
			try { socket.close(); } catch {}
		};
		server.addEventListener("close", teardown);
		server.addEventListener("error", teardown);

		return new Response(null, { status: 101, webSocket: client });
	},
};
