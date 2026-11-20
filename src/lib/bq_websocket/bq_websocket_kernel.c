#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/libkern.h>

#define BQWS_SINGLE_THREAD 1
#define BQWS_DEBUG 0
#define BQWS_NO_SSE 1
#define bqws_assert(x) KASSERT((x), ("bqws assertion failed"))
#define bqws_malloc(size) bqws_kernel_malloc(size)
#define bqws_realloc(ptr, old_size, new_size) bqws_kernel_realloc((ptr), (old_size), (new_size))
#define bqws_free(ptr, size) bqws_kernel_free((ptr))

static void bqws_kernel_free (void *ptr);

static void *
bqws_kernel_malloc (size_t size)
{
	return (malloc(size, M_TEMP, M_WAITOK));
}

static void *
bqws_kernel_realloc (void *ptr, size_t old_size, size_t new_size)
{
	void *next;

	if (ptr == NULL)
		return (bqws_kernel_malloc(new_size));
	if (new_size == 0) {
		bqws_kernel_free(ptr);
		return (NULL);
	}
	next = bqws_kernel_malloc(new_size);
	if (next == NULL)
		return (NULL);
	memcpy(next, ptr, old_size < new_size ? old_size : new_size);
	free(ptr, M_TEMP);
	return (next);
}

static void
bqws_kernel_free (void *ptr)
{
	free(ptr, M_TEMP);
}

#include "bq_websocket.c"
