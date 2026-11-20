#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <kvm.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"
#include "spinneret.h"
#define KSCRATCH_RESERVE (64 * 1024)
static int kfd = -1;
static kvm_t* kh = NULL;

// symbol kv cache
static struct {
	char* key; 
	u_long value; 
} *symcache = NULL;

int sp_open (void)
{
	if (kfd < 0)
		kfd = open("/dev/kmem", O_RDWR);
	return ((kfd < 0) ? -1 : 0);
}

// read from addr len bytes into buf 
int sp_read (u_long addr, void* buf, size_t len)
{
	return (pread(kfd, buf, len, addr) == (ssize_t)len);
}

// write to addr from buf of len bytes
int sp_write (u_long addr, const void* buf, size_t len)
{
	return (pwrite(kfd, buf, len, addr) == (ssize_t)len);
}

// resolve a symbol
u_long sp_sym (const char* name)
{
	u_long cached = shget(symcache, name);

	if (cached != 0)
		return (cached);

	if (kh == NULL)
		kh = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);

	struct nlist nl[2] = { {NULL,0,0,0,0}, {NULL,0,0,0,0} };
	nl[0].n_name = (char*)name;
	if (kvm_nlist(kh, nl) < 0 || nl[0].n_value == 0)
		return (0);

	shput(symcache, name, nl[0].n_value);
	return (nl[0].n_value);
}


u_long* sp_walk (u_long head, int next_off)
{
	u_long* out = NULL;
	u_long cur;

	if (!sp_read(head, &cur, 8))
		return (NULL);

	while (cur != 0) {
		arrput(out, cur);
		u_long next;
		if (!sp_read(cur + next_off, &next, 8))
			break;
		cur = next;
	}
	return (out);
}


// allocate stuff in a massive codecave
static u_long kscratch = 0;
static u_long kscratch_used = 0;

u_long sp_kalloc (size_t size)
{
	if (kscratch == 0) {
		// nm /boot/kernel/kernel | tail
		u_long hints = sp_sym("static_hints");
		if (!hints)
			return (0);
		kscratch = (hints + 4095) & ~4095UL;
		kscratch_used = 0;
	}
	u_long addr = kscratch + kscratch_used;
	kscratch_used += (size + 7) & ~7UL;
	return (addr);
}

void sp_kfree (u_long addr, size_t size)
{
	/* bump allocator, no reclamation */
}

void sp_free (void* ptr)
{
	free(ptr);
}

void sp_close (void)
{
	if (kfd >= 0) {
		close(kfd);
		kfd = -1;
	}
	if (kh != NULL) {
		kvm_close(kh);
		kh = NULL;
	}
}
