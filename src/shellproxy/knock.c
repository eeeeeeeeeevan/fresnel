#include "shellproxy.h"
#include "opt_global.h"

#define V_icmpstat VNET(icmpstat)

static
u_long icmp_echo_in (void)
{
	return counter_u64_fetch(V_icmpstat[
	    offsetof(struct icmpstat, icps_inhist)/sizeof(u64)+ICMP_ECHO]);
}

void proxy_knock_tick (void* arg)
{
	static struct bintime seen[KNOCK_COUNT];
	static int nseen;
	static u_long last;
	u_long now;
	struct bintime span;
	int newest, oldest;

	(void)arg;

	CURVNET_SET_QUIET(vnet0);

	now = icmp_echo_in();
	if (now!=last) {
		last = now;
		getbinuptime(&seen[nseen%KNOCK_COUNT]);
		nseen++;
		if (nseen>=KNOCK_COUNT) {
			newest = (nseen-1)%KNOCK_COUNT;
			oldest = nseen%KNOCK_COUNT;
			span = seen[newest];
			bintime_sub(&span, &seen[oldest]);
			if (span.sec<KNOCK_WINDOW_S) {
				mtx_lock(&proxy_mtx);
				fire++;
				mtx_unlock(&proxy_mtx);
				wakeup(&fire);
				nseen = 0;
			}
		}
	}

	CURVNET_RESTORE();

	if (!shutting_down)
		callout_schedule_sbt(&knock_callout, TICK_MS*SBT_1MS, 0, 0);
}

