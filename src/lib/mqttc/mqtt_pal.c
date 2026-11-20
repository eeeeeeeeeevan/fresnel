#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/systm.h>
#include <sys/proc.h>

#include "mqtt.h"
#include "remws.h"

ssize_t mqtt_pal_sendall (mqtt_pal_socket_handle s, const void* buf, size_t len, int flags)
{
	struct iovec iov;
	struct uio uio;

	if (s->ws != NULL) {
		int n = remws_send(s->ws, buf, (int)len);
		return (n < 0 ? MQTT_ERROR_SOCKET_ERROR : n);
	}

	iov.iov_base = __DECONST(void*, buf);
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = s->td;

	if (sosend(s->so, NULL, &uio, NULL, NULL, 0, s->td)!=0)
		return MQTT_ERROR_SOCKET_ERROR;
	return (ssize_t)len;
}

ssize_t mqtt_pal_recvall (mqtt_pal_socket_handle s, void* buf, size_t bufsz, int flags)
{
	struct iovec iov;
	struct uio uio;
	size_t want = bufsz;
	int error;
	int rflags = 0;

	if (s->ws != NULL) {
		int n = remws_recv(s->ws, buf, (int)bufsz);
		return (n < 0 ? MQTT_ERROR_SOCKET_ERROR : n);
	}

	iov.iov_base = buf;
	iov.iov_len = bufsz;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = bufsz;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = s->td;

	error = soreceive(s->so, NULL, &uio, NULL, NULL, &rflags);
	if (error==EWOULDBLOCK || error==EAGAIN)
		return 0;
	if (error!=0)
		return MQTT_ERROR_SOCKET_ERROR;
	if (uio.uio_resid==want)
		return 0;
	return (ssize_t)(want-uio.uio_resid);
}
