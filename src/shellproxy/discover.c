#include "config.h"
#include "shellproxy.h"
#include "subnet.h"

#ifdef CFG_SUBNET_ROUTER

#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>

int
subnet_discover (char* resp, int rsz)
{
	struct inpcb* inp;
	char lbuf[16];
	char fbuf[16];
	int off = 0;

	off += snprintf(resp+off, rsz-off, "tcp:");
	mtx_lock(&V_tcbinfo.ipi_lock);
	int first = 1;
	CK_LIST_FOREACH(inp, &V_tcbinfo.ipi_listhead, inp_list) {
		if (inp->inp_gencnt==~0ULL)
			continue;
		inet_ntoa_r(inp->inp_inc.inc_laddr, lbuf);
		inet_ntoa_r(inp->inp_inc.inc_faddr, fbuf);
		off += snprintf(resp+off, rsz-off, "%s%s:%d|%s:%d",
		    first ? "" : ",", lbuf, ntohs(inp->inp_inc.inc_lport),
		    fbuf, ntohs(inp->inp_inc.inc_fport));
		first = 0;
		if (off>=rsz-128)
			break;
	}
	mtx_unlock(&V_tcbinfo.ipi_lock);

	off += snprintf(resp+off, rsz-off, "\nudp:");
	mtx_lock(&V_udbinfo.ipi_lock);
	first = 1;
	CK_LIST_FOREACH(inp, &V_udbinfo.ipi_listhead, inp_list) {
		if (inp->inp_gencnt==~0ULL)
			continue;
		inet_ntoa_r(inp->inp_inc.inc_laddr, lbuf);
		off += snprintf(resp+off, rsz-off, "%s%s:%d",
		    first ? "" : ",", lbuf, ntohs(inp->inp_inc.inc_lport));
		first = 0;
		if (off>=rsz-128)
			break;
	}
	mtx_unlock(&V_udbinfo.ipi_lock);
	return (off);
}

#endif
