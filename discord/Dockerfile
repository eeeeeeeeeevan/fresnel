FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
	python3 python3-pip golang-go \
	qemu-system-x86 qemu-utils \
	libsodium23 libsodium-dev \
	openssh-client perl curl xz-utils procps \
	&& rm -rf /var/lib/apt/lists/*

RUN npm install -g pm2

COPY --from=cloudflare/cloudflared:latest /usr/local/bin/cloudflared /usr/local/bin/cloudflared
RUN chmod +x /usr/local/bin/cloudflared

WORKDIR /app
COPY discord/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

COPY . /app
WORKDIR /app

CMD ["pm2-runtime", "start", "discord/ecosystem.config.js"]
