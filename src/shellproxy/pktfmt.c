#include "shellproxy.h"

int proxy_send_n (struct socket* so, const void* data, int n)
{
	struct iovec iov;
	struct uio uio;

	iov.iov_base = __DECONST(void*, data);
	iov.iov_len = n;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = n;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = curthread;

	return sosend(so, NULL, &uio, NULL, NULL, 0, curthread);
}
