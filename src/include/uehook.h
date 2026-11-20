#ifndef UEHOOK_H
#define UEHOOK_H
#include <sys/types.h>

// userspace ehooks using /dev/kmem
// could be useful in the future either for the kit or for detecting/debugging.

struct uehook_entry {
	u_long addr;
	u_long func;
	u_long arg;
	u_int  priority;
};

typedef int (*uehook_cb) (struct uehook_entry* e, void* ctx);
typedef int (*uehook_all_cb) (const char* listname, struct uehook_entry* e, void* ctx);

u_long uehook_find (const char* name);
u_long uehook_register (u_long list, u_long func, void* arg, u_int priority);
int uehook_unregister (u_long list, u_long entry);
int uehook_walk (u_long list, uehook_cb cb, void* ctx);
int uehook_walk_all (uehook_all_cb cb, void* ctx);

#endif
