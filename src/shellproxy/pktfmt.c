#include "shellproxy.h"

int proxy_recv_n (struct socket* so, u8* buf, int n)
{
	struct iovec iov;
	struct uio uio;
	int error, flags = 0;
	int got = 0;

	while (got<n) {
		size_t want;
		iov.iov_base = buf+got;
		iov.iov_len = n-got;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = n-got;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = curthread;

		want = n-got;
		error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
		if (error!=0)
			return (error);
		if (uio.uio_resid==want)
			return (ECONNRESET);
		got += (int)(want-uio.uio_resid);
	}
	return (0);
}

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

int proxy_set_rcvtimeo (struct socket* so, int sec)
{
	struct sockopt sopt;
	struct timeval tv = { .tv_sec = sec };

	memset(&sopt, 0, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_RCVTIMEO;
	sopt.sopt_val = &tv;
	sopt.sopt_valsize = sizeof(tv);
	return sosetopt(so, &sopt);
}

