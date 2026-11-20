#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/libkern.h>

#include "bq_websocket.h"
#include "remws.h"

#define WS_RXBUF (32*1024*1024)

// i cbf importig common.h

static
size_t ws_io_send (void* user, bqws_socket* ws, const void* data, size_t size)
{
	struct remws* rw = user;
	int error;

	error = rem_send_n(rw->rc, data, (int)size);
	if (error != 0)
		return (SIZE_MAX);
	return (size);
}

static
size_t ws_io_recv (void* user, bqws_socket* ws, void* data, size_t max, size_t min)
{
	struct remws* rw = user;
	int n;

	(void)min;
	n = rem_recv_some(rw->rc, data, (int)max);
	if (n < 0)
		return (SIZE_MAX);
	return (n);
}

static
void ws_io_notify (void* user, bqws_socket* ws)
{
	// todo 
}

static
bool ws_io_flush (void* user, bqws_socket* ws)
{
	return (true);
}

static
void ws_io_close (void* user, bqws_socket* ws)
{
	// todo
}

static
void ws_io_init (void* user, bqws_socket* ws)
{
	// todo
}

static
void ws_error (void* user, bqws_socket* ws, bqws_error error)
{
}

// read docs to see how bqws works if you wanna touch the code please
// https://github.com/bqqbarbhg/bq_websocket
int remws_connect (struct remws * ws, struct remconn * rc, const char* host, const char* path)
{
	bqws_opts opts;
	bqws_client_opts client;
	bqws_state state;

	memset(ws, 0, sizeof(*ws));
	ws->rc = rc;
	strlcpy(ws->host, host, sizeof(ws->host));
	strlcpy(ws->path, path, sizeof(ws->path));
	ws->rx = malloc(WS_RXBUF, M_TEMP, M_WAITOK);

	memset(&opts, 0, sizeof(opts));
	opts.io.user = ws;
	opts.io.init_fn = ws_io_init;
	opts.io.send_fn = ws_io_send;
	opts.io.recv_fn = ws_io_recv;
	opts.io.notify_fn = ws_io_notify;
	opts.io.flush_fn = ws_io_flush;
	opts.io.close_fn = ws_io_close;
	opts.connect_timeout = 5000;
	opts.limits.max_memory_used = 64*1024*1024;
	opts.limits.max_recv_msg_size = 32*1024*1024;
	opts.limits.max_recv_queue_size = 64*1024*1024;
	opts.limits.max_recv_queue_messages = 65536;
	opts.error_fn = ws_error;

	memset(&client, 0, sizeof(client));
	client.path = ws->path;
	client.host = ws->host;

	ws->ws = bqws_new_client(&opts, &client);
	if (ws->ws == NULL)
		return (1);

	for (int i = 0; i < 50; i++) {
		bqws_update(ws->ws);
		state = bqws_get_state(ws->ws);
			if (state == BQWS_STATE_OPEN)
			return (0);
		if (state == BQWS_STATE_CLOSED || state == BQWS_STATE_CLOSING)
			break;
	}
	return (1);
}

int remws_send (struct remws * ws, const void* data, int len)
{
	if (ws->ws == NULL || bqws_is_closed(ws->ws)) return (-1);
	bqws_send_binary(ws->ws, data, len);
	bqws_update(ws->ws);
	return (bqws_is_closed(ws->ws) ? -1 : len);
}

int remws_recv (struct remws * ws, void* data, int len)
{
	bqws_msg* msg;

	if (ws->rxoff >= ws->rxlen) {
		if (ws->ws == NULL || bqws_is_closed(ws->ws))
			return (-1);
		bqws_update(ws->ws);
		// this is the worst fucking lib i done bombaclat pussyclat used
		while ((msg = bqws_recv(ws->ws))) {
			if (msg->type == BQWS_MSG_BINARY || msg->type == BQWS_MSG_TEXT) {
				if (msg->size > WS_RXBUF) {
					bqws_free_msg(msg);
					return (-1);
				}
				// ohmy god bro msg.size ddont do this bro
				memcpy(ws->rx, msg->data, msg->size);
				ws->rxlen = (int)msg->size;
				ws->rxoff = 0;
				bqws_free_msg(msg);
				break;
			}
			bqws_free_msg(msg);
		}
	}

	if (ws->rxoff >= ws->rxlen)
		return (bqws_is_closed(ws->ws) ? -1 : 0);

	// this might fuck something up. maybe a logic bug here idk
	int n = ws->rxlen - ws->rxoff;
	if (n > len) n = len;

	memcpy(data, ws->rx + ws->rxoff, n);
	ws->rxoff += n;
	return (n);
}

// do not be retarded
void remws_close (struct remws * ws)
{
	if (ws->ws != NULL) {
		bqws_free_socket(ws->ws);
		ws->ws = NULL;
	}
	if (ws->rx != NULL) {
		free(ws->rx, M_TEMP);
		ws->rx = NULL;
	}
}
