#ifndef _TTYLOG_H_
#define _TTYLOG_H_

#include <sys/types.h>

typedef void ttylog_input_t(void* arg, const char* data, size_t len);

int ttylog_start(ttylog_input_t* input, void* arg);
void ttylog_stop(void);

#endif
