#ifndef REMSOCKET_H
#define REMSOCKET_H

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/types.h>

#ifndef U8_TYPEDEF
#define U8_TYPEDEF
typedef unsigned char u8;
#endif

struct remconn {
	struct socket* so;
	struct thread* td;
};

int rem_connect_tcp (struct remconn * rc, const char* ip, int port);
int rem_bind_udp (struct remconn * rc, const char* ip, int port);
int rem_recv_dgram (struct remconn * rc, u8* buf, int bufsz);
void rem_close (struct remconn * rc);
void rem_timeout (struct remconn * rc, int sec);
int rem_send_n (struct remconn * rc, const void* data, int n);
int rem_recv_n (struct remconn * rc, u8* buf, int n);
int rem_recv_some (struct remconn * rc, void* buf, int n);

#endif
