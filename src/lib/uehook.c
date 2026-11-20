#include <stdio.h>
#include <string.h>
#include "uehook.h"
#include "spinneret.h"

// ok obviously these offsets are all fucking wrong beyond 14.5
// but wtv

// CHANGE ME FOR OTHER VERISONS OBV go grep them yourself
#define EL_ENTRIES_FIRST 64
#define EL_ENTRIES_LAST 72
#define EE_NEXT 0
#define EE_PREV 8
#define EE_PRIORITY 16
#define EE_ARG 24
#define EE_FUNC 32
#define EE_SIZE 40

u_long uehook_find (const char* name)
{
	char symname[128];
	u_long var, list;

	snprintf(symname, sizeof(symname), "_eventhandler_list_%s", name);
	var = sp_sym(symname);
	if (var && sp_read(var, &list, 8) && list) return (list);

	u_long lists = sp_sym("eventhandler_lists");
	if (!lists)
		return (0);

	u_long cur;
	sp_read(lists, &cur, 8);
	while (cur) {
		u_long namep;
		sp_read(cur, &namep, 8);
		if (namep) {
			char cmp[64];
			sp_read(namep, cmp, sizeof(cmp) - 1);
			cmp[sizeof(cmp) - 1] = 0;
			if (strcmp(cmp, name) == 0) return (cur);
		}
		u_long next;
		sp_read(cur + 48, &next, 8);
		cur = next;
	}
	return (0);
}

u_long uehook_register (u_long list, u_long func, void* arg, u_int priority)
{
	u_long entry;
	u_long prev_next_addr;
	u_long zero = 0;

	entry = sp_kalloc(EE_SIZE);
	if (!entry)
		return (0);

	// fill the entry VERY FUCKING CAREFULLY
	// +0, +16, +24, +32
	sp_write(entry+EE_NEXT, &zero, 8);
	sp_write(entry+EE_PRIORITY, &priority, 4);
	sp_write(entry+EE_ARG, &arg, 8);
	sp_write(entry+EE_FUNC, &func, 8);

	prev_next_addr = 0;
	sp_read(list+EL_ENTRIES_LAST, &prev_next_addr, 8);

	if (prev_next_addr == 0) {
		// list never initialized, write tqh_first directly
		u_long head = list + EL_ENTRIES_FIRST;
		sp_write(list + EL_ENTRIES_FIRST, &entry, 8);
		sp_write(list + EL_ENTRIES_LAST, &head, 8);
		sp_write(entry + EE_PREV, &head, 8);
	} else {
		// link prev to us, us to prev, head to us
		sp_write(prev_next_addr, &entry, 8);
		sp_write(entry + EE_PREV, &prev_next_addr, 8);
		sp_write(list + EL_ENTRIES_LAST, &entry, 8);
	}

	return (entry);
}

int uehook_unregister (u_long list, u_long entry)
{
	u_long next, prev;

	sp_read(entry + EE_NEXT, &next, 8);
	sp_read(entry + EE_PREV, &prev, 8);

	sp_write(prev, &next, 8);
	if (next)
		sp_write(next + EE_PREV, &prev, 8);
	else
		sp_write(list + EL_ENTRIES_LAST, &prev, 8);

	return (0);
}

int uehook_walk (u_long list, uehook_cb cb, void* ctx)
{
	struct uehook_entry e;
	u_long cur;
	int n = 0;

	sp_read(list + EL_ENTRIES_FIRST, &cur, 8);
	while (cur) {
		e.addr = cur;
		sp_read(cur + EE_FUNC, &e.func, 8);
		sp_read(cur + EE_ARG, &e.arg, 8);
		sp_read(cur + EE_PRIORITY, &e.priority, 4);
		if (cb(&e, ctx))
			break;
		n++;
		sp_read(cur + EE_NEXT, &cur, 8);
	}
	return (n);
}

int uehook_walk_all (uehook_all_cb cb, void* ctx)
{
	u_long lists_head = sp_sym("eventhandler_lists");
	if (!lists_head)
		return (0);

	u_long cur_list;
	sp_read(lists_head, &cur_list, 8);

	int total = 0;
	while (cur_list) {
		u_long namep;
		sp_read(cur_list, &namep, 8);
		char name[64] = {0};
		if (namep)
			sp_read(namep, name, sizeof(name) - 1);

		u_long cur;
		sp_read(cur_list + EL_ENTRIES_FIRST, &cur, 8);
		while (cur) {
			struct uehook_entry e;
			e.addr = cur;
			sp_read(cur + EE_FUNC, &e.func, 8);
			sp_read(cur + EE_ARG, &e.arg, 8);
			sp_read(cur + EE_PRIORITY, &e.priority, 4);
			if (cb(name, &e, ctx))
				return (total);
			total++;
			sp_read(cur + EE_NEXT, &cur, 8);
		}

		sp_read(cur_list + 48, &cur_list, 8);
	}
	return (total);
}
