#ifndef EHOOK_H
#define EHOOK_H

// single header library
// eventhandler callbacks is essentially freebsd nirvana hooking/instrumentation callbacks.

// this lets you create an eventhandler hook or ehook *easily*
// plz download freebsd source tree and ripgrep for eventhandler* to find cool events to make ehooks on. otherwise just use the ones i found so far

// we search for eventhandler list, append a handler and we can remove it later

// for kernel: ehook_on("process_exec", blah)
// for userspace please use uehook instead (for detectors at least imo)

#include <sys/eventhandler.h>

#define EHOOK_MAX 8

static struct {
	const char* name;
	eventhandler_tag tag;
} ehook_slots[EHOOK_MAX];

static 
eventhandler_tag ehook_on (const char* name, void* func)
{
	for (int i=0; i<EHOOK_MAX; i++) {
		if (ehook_slots[i].tag == NULL) {
			ehook_slots[i].tag = eventhandler_register(NULL, name, func, NULL, EVENTHANDLER_PRI_LAST);
			ehook_slots[i].name = name;
			return (ehook_slots[i].tag);
		}
	}
	return (NULL);
}

static 
eventhandler_tag ehook_on_arg (const char* name, void* func, void* arg, int priority)
{
	for (int i=0; i<EHOOK_MAX; i++) {
		if (ehook_slots[i].tag == NULL) {
			ehook_slots[i].tag = eventhandler_register(NULL, name, func, arg, priority);
			ehook_slots[i].name = name;
			return (ehook_slots[i].tag);
		}
	}
	return (NULL);
}

static 
void ehook_off (const char* name)
{
	for (int i=0; i<EHOOK_MAX; i++) {
		if (ehook_slots[i].tag && strcmp(ehook_slots[i].name, name) == 0) {
			EVENTHANDLER_DEREGISTER(ehook_slots[i].name, ehook_slots[i].tag);
			ehook_slots[i].tag = NULL;
			return;
		}
	}
}

static
void ehook_off_all(void)
{
	for (int i=0; i<EHOOK_MAX; i++) {
		if (ehook_slots[i].tag) {
			EVENTHANDLER_DEREGISTER(ehook_slots[i].name, ehook_slots[i].tag);
			ehook_slots[i].tag = NULL;
		}
	}
}

#endif
