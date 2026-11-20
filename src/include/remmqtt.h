#ifndef REMMQTT_H
#define REMMQTT_H

#include <sys/param.h>
#include "remsocket.h"

typedef void (*remmqtt_publish_fn) (const char* topic, const u8* payload, int len);

struct remmqtt {
	struct remconn rc;
	void* client;
	u8* sendbuf;
	u8* recvbuf;
	remmqtt_publish_fn on_publish;
};

int remmqtt_connect (struct remmqtt* m, const char* host, const char* http_host, const char* path, const char* client_id);
void remmqtt_sub (struct remmqtt* m, const char* topic);
int remmqtt_pub (struct remmqtt* m, const char* topic, const u8* payload, int len, int retain);
void remmqtt_flush (struct remmqtt* m);
int remmqtt_sync (struct remmqtt* m);
void remmqtt_close (struct remmqtt* m);

#endif
