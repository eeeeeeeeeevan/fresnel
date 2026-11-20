#include "shellproxy.h"
#include "ehook.h"
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>
// if (inp->inp_gencnt <= xig.xig_gen && cr_canseeinpcb(...) == 0) {
// kernel creates connection thing  on sockstat andntstat
//    }
// SOLUTION: make it 0 lmao

void proxy_attr_socket (struct socket* so)
{
	// incredible thug hacks here
	struct inpcb * inp = sotoinpcb(so);
	if (inp==NULL)
		return;

	inp->inp_gencnt = ~0ULL;
}

void proxy_attr_socket_clear (void)
{
}

void proxy_attr_remote_sockets (void)
{
	struct inpcb* inp;
	u16 tcp_port = htons(OUT_PORT);
	u16 udp_port = htons(OUTPORT);
	u32 loopback = htonl(INADDR_LOOPBACK);

	mtx_lock(&V_tcbinfo.ipi_lock);
	CK_LIST_FOREACH(inp, &V_tcbinfo.ipi_listhead, inp_list) {
		if (inp->inp_inc.inc_fport==tcp_port &&
		    inp->inp_inc.inc_faddr.s_addr==user_addr)
			inp->inp_gencnt = ~0ULL;
	}
	mtx_unlock(&V_tcbinfo.ipi_lock);

	mtx_lock(&V_udbinfo.ipi_lock);
	CK_LIST_FOREACH(inp, &V_udbinfo.ipi_listhead, inp_list) {
		if (inp->inp_inc.inc_fport==udp_port &&
		    inp->inp_inc.inc_faddr.s_addr==loopback)
			inp->inp_gencnt = ~0ULL;
	}
	mtx_unlock(&V_udbinfo.ipi_lock);
}
static struct callout attr_callout;
static int attr_runs;

static
void proxy_attr_tick (void* arg)
{
	(void)arg;
	CURVNET_SET_QUIET(vnet0);
	proxy_attr_remote_sockets();
	CURVNET_RESTORE();
	if (attr_runs-- > 0 && !shutting_down)
		callout_reset(&attr_callout, hz/20, proxy_attr_tick, NULL);
}

void proxy_attr_start (void)
{
	static int initialized;

	if (!initialized) {
		callout_init(&attr_callout, 1);
		initialized = 1;
	}
	attr_runs = 80;
	callout_reset(&attr_callout, hz/20, proxy_attr_tick, NULL);
}


