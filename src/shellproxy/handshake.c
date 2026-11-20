#include "shellproxy.h"

int proxy_handshake (struct socket* so, u8 tx[32], u8 rx[32])
{
	u8 hello[8+24];
	u8 nonce_r[24];
	u8 resp[8+8+16+16+32+16+24];

	proxy_hello(hello, nonce_r);
	if (proxy_send_n(so, hello, sizeof(hello))!=0)
		return (1);

	if (proxy_recv_n(so, resp, sizeof(resp))!=0)
		return (1);

	return proxy_session_keys(resp, nonce_r, tx, rx);
}
