#ifndef __KERNEL_MQTT_PAL_H__
#define __KERNEL_MQTT_PAL_H__

#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/stdarg.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/proc.h>
#include <sys/mutex.h>

struct remws;

#define MQTT_PAL_HTONS(s) htons(s)
#define MQTT_PAL_NTOHS(s) ntohs(s)

#define MQTT_PAL_TIME() ((long)time_second)

typedef long mqtt_pal_time_t;
typedef struct mtx mqtt_pal_mutex_t;

#define MQTT_PAL_MUTEX_INIT(mtx_ptr) mtx_init(mtx_ptr, "mqttc", NULL, MTX_DEF)
#define MQTT_PAL_MUTEX_LOCK(mtx_ptr) mtx_lock(mtx_ptr)
#define MQTT_PAL_MUTEX_UNLOCK(mtx_ptr) mtx_unlock(mtx_ptr)

struct mqtt_kernel_sock {
	struct socket * so;
	struct thread * td;
	struct remws * ws;
};

typedef struct mqtt_kernel_sock* mqtt_pal_socket_handle;

ssize_t mqtt_pal_sendall (mqtt_pal_socket_handle fd, const void* buf, size_t len, int flags);
ssize_t mqtt_pal_recvall (mqtt_pal_socket_handle fd, void* buf, size_t bufsz, int flags);

#endif
