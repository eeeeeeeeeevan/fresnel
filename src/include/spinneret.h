#ifndef SPINNERET_H
#define SPINNERET_H
#include <sys/types.h>


// a tiny lib to interface with /dev/kmem

// spn_sym does symbol lookup, while sp_walk walks a linked list and returns a dyn arr

int sp_open (void);
int sp_read (u_long addr, void* buf, size_t len);
int sp_write (u_long addr, const void* buf, size_t len);
u_long sp_sym (const char* name);
u_long* sp_walk (u_long head, int next_off);

// use code cave in kernel to allocate stuff for our work
u_long sp_kalloc (size_t size);
void sp_kfree (u_long addr, size_t size);

void sp_free (void* ptr);

#endif
void sp_close (void);
