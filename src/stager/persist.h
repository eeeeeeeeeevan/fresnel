#ifndef PERSIST_H
#define PERSIST_H

#include <sys/types.h>
#include "common.h"
#include "rand.h"
#include <sys/uio.h>

#define RMAGIC_LINE RMAGIC "\n"
#define RMAGIC_LEN (sizeof(RMAGIC))

typedef struct persist_ctx PersistCtx;

struct persist_ctx {
	void* module_data;
	size module_len;

	const char* conf_path;
	void* conf_data;
	size conf_len;

	const char* helper_path;
	void* helper_data;
	size helper_len;
	const char* delim;
	size delim_len;

	int(*openat)(struct thread *, int, const char *, enum uio_seg, int, int);
	int(*pwritev)(struct thread *, int, struct uio *, off_t);
	int(*close)(struct thread *, int);
};

void persist_handler (void *, int);

#endif
