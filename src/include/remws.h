#ifndef REMWS_H
#define REMWS_H

#include <sys/param.h>
#include "remsocket.h"

struct bqws_socket;

struct remws {
	struct remconn* rc;
	struct bqws_socket* ws;
	u8* rx;
	int rxlen;
	int rxoff;
	char host[256];
	char path[512];
};

int remws_connect (struct remws* ws, struct remconn* rc,
    const char* host, const char* path);
int remws_send (struct remws* ws, const void* data, int len);
int remws_recv (struct remws* ws, void* data, int len);
void remws_close (struct remws* ws);

#endif
