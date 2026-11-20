#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/libkern.h>
#include <sys/sockopt.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

#include "remsocket.h"

static
void rem_hide_socket (struct socket* so)
{
	struct inpcb* inp = sotoinpcb(so);

	if (inp!=NULL)
		inp->inp_gencnt = ~0ULL;
}

int rem_connect_tcp (struct remconn * rc, const char* ip, int port)
{
	struct sockaddr_in sa;

	rc->so = NULL;
	rc->td = curthread;

	if (socreate(AF_INET, &rc->so, SOCK_STREAM, IPPROTO_TCP,
	    rc->td->td_ucred, rc->td)!=0)
		return (1);
	rem_hide_socket(rc->so);

	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_aton(ip, &sa.sin_addr)==0) {
		soclose(rc->so);
		rc->so = NULL;
		return (1);
	}

	if (soconnect(rc->so, (struct sockaddr*)&sa, rc->td)!=0) {
		soclose(rc->so);
		rc->so = NULL;
		return (1);
	}

	for (int i = 0; i<50; i++) {
		SOCK_LOCK(rc->so);
		// god what a shit lib
		if (rc->so->so_state & (SS_ISCONNECTED | SS_ISDISCONNECTED)) {

			int bad = !(rc->so->so_state & SS_ISCONNECTED);
			SOCK_UNLOCK(rc->so);
			if (bad) {
				soclose(rc->so);
				rc->so = NULL;
				return (1);
			}
			return (0);
		}
		SOCK_UNLOCK(rc->so);
		tsleep(&rc->so->so_timeo, PWAIT, "remconn", hz/20);
	}

	soclose(rc->so);
	rc->so = NULL;
	return (1);
}

void rem_close (struct remconn * rc)
{
	if (rc->so!=NULL) {
		if (rc->so->so_type==SOCK_STREAM) {
			struct linger linger = { .l_onoff = 1, .l_linger = 0 };
			struct sockopt sopt;

			memset(&sopt, 0, sizeof(sopt));
			sopt.sopt_dir = SOPT_SET;
			sopt.sopt_level = SOL_SOCKET;
			sopt.sopt_name = SO_LINGER;
			sopt.sopt_val = &linger;
			sopt.sopt_valsize = sizeof(linger);
			(void)sosetopt(rc->so, &sopt);
		}
		soclose(rc->so);
		rc->so = NULL;
	}
}

int
rem_bind_udp (struct remconn* rc, const char* ip, int port)
{
	struct sockaddr_in sa;

	rc->so = NULL;
	rc->td = curthread;

	if (socreate(AF_INET, &rc->so, SOCK_DGRAM, IPPROTO_UDP,
	    rc->td->td_ucred, rc->td)!=0)
		return (1);
	rem_hide_socket(rc->so);

	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_aton(ip, &sa.sin_addr)==0) {
		soclose(rc->so);
		rc->so = NULL;
		return (1);
	}
	if (sobind(rc->so, (struct sockaddr*)&sa, rc->td)!=0) {
		soclose(rc->so);
		rc->so = NULL;
		return (1);
	}
	return (0);
}

int rem_recv_dgram (struct remconn * rc, u8* buf, int bufsz)
{
	struct iovec iov;
	struct uio uio;
	struct sockaddr* from = NULL;
	size_t want = bufsz;

	iov.iov_base = buf;
	iov.iov_len = bufsz;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = bufsz;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = rc->td;

	if (soreceive(rc->so, &from, &uio, NULL, NULL, NULL)!=0) {
		if (from!=NULL)
			free(from, M_SONAME);
		return (-1);
	}
	if (from!=NULL)
		free(from, M_SONAME);
	return (int)(want-uio.uio_resid);
}

void rem_timeout (struct remconn * rc, int sec)
{
	struct sockopt sopt;
	struct timeval tv = { .tv_sec = sec };

	memset(&sopt, 0, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_RCVTIMEO;
	sopt.sopt_val = &tv;
	sopt.sopt_valsize = sizeof(tv);
	(void)sosetopt(rc->so, &sopt);
}

int rem_send_n (struct remconn * rc, const void* data, int n)
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
	uio.uio_td = rc->td;

	return sosend(rc->so, NULL, &uio, NULL, NULL, 0, rc->td);
}

int rem_recv_some (struct remconn * rc, void* buf, int n)
{
	struct iovec iov;
	struct uio uio;
	int flags = 0;
	int error;

	iov.iov_base = buf;
	iov.iov_len = n;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = n;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = rc->td;

	error = soreceive(rc->so, NULL, &uio, NULL, NULL, &flags);
	if (error == EWOULDBLOCK || error == EAGAIN)
		return (0);
	if (error != 0)
		return (-1);
	return (n - (int)uio.uio_resid);
}

int rem_recv_n (struct remconn * rc, u8* buf, int n)
{
	struct iovec iov;
	struct uio uio;
	int error;
	int flags = 0;
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
		uio.uio_td = rc->td;

		want = n-got;
		error = soreceive(rc->so, NULL, &uio, NULL, NULL, &flags);
		if (error!=0)
			return (error);
		if (uio.uio_resid==want)
			return (ECONNRESET);
		got += (int)(want-uio.uio_resid);
	}
	return (0);
}
