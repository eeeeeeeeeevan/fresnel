#include <sys/time.h>
#include <sys/types.h>

#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 1000
#endif

static inline clock_t
clock (void)
{
	struct timeval tv;

	microuptime(&tv);
	return ((clock_t)((int64_t)tv.tv_sec * CLOCKS_PER_SEC +
	    (int64_t)tv.tv_usec / (1000000 / CLOCKS_PER_SEC)));
}

static inline time_t
time (time_t* out)
{
	if (out != NULL)
		*out = time_second;
	return (time_second);
}
