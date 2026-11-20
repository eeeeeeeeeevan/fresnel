// mqtt helpers, see mqtt single header libs on github for how i got this
// this should be self-explanatory im not gonna document how they work here rtfm
#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/malloc.h>

#include "remmqtt.h"
#include "remws.h"
#include "../lib/mqttc/mqtt.h"

#define SENDBUF_SZ 65536
#define RECVBUF_SZ 65536

struct remmqtt_impl {
	struct mqtt_client c;
	struct mqtt_kernel_sock h;
	struct remws ws;
};

static 
void trampoline (void** state, struct mqtt_response_publish * pub)
{
	struct remmqtt * m = state[0];

	if (m->on_publish)
		m->on_publish(pub->topic_name, pub->application_message, (int)pub->application_message_size);
}

int remmqtt_connect (struct remmqtt * m, const char* host, const char* http_host, const char* path, const char* client_id)
{
	struct remmqtt_impl* im;

	m->client = NULL;
	m->sendbuf = NULL;
	m->recvbuf = NULL;
	m->on_publish = NULL;

	if (rem_connect_tcp(&m->rc, host, 80)!=0)
		return (1);
	rem_timeout(&m->rc, 1);

	im = malloc(sizeof(*im), M_TEMP, M_WAITOK|M_ZERO);
	m->sendbuf = malloc(SENDBUF_SZ, M_TEMP, M_WAITOK|M_ZERO);
	m->recvbuf = malloc(RECVBUF_SZ, M_TEMP, M_WAITOK|M_ZERO);

	if (remws_connect(&im->ws, &m->rc, http_host, path)!=0) {
		m->client = im;
		remmqtt_close(m);
		return (1);
	}
	im->h.so = m->rc.so;
	im->h.td = m->rc.td;
	im->h.ws = &im->ws;

	if (mqtt_init(&im->c, &im->h, m->sendbuf, SENDBUF_SZ,
	    m->recvbuf, RECVBUF_SZ, trampoline)!=MQTT_OK) {
		remmqtt_close(m);
		return (1);
	}
	im->c.publish_response_callback_state = m;
	m->client = im;

	mqtt_connect(&im->c, client_id, NULL, NULL, 0, NULL, NULL, 0, 400);
	if (mqtt_sync(&im->c)!=MQTT_OK) {
		remmqtt_close(m);
		return (1);
	}
	return (0);
}

void remmqtt_sub (struct remmqtt * m, const char* topic)
{
	struct remmqtt_impl* im = m->client;

	mqtt_subscribe(&im->c, topic, 0);
	mqtt_sync(&im->c);
}

int remmqtt_pub (struct remmqtt * m, const char* topic, const u8* payload, int len, int retain)
{
	struct remmqtt_impl * im = m->client;

	return mqtt_publish(&im->c, topic, payload, len, MQTT_PUBLISH_QOS_0|(retain?MQTT_PUBLISH_RETAIN:0))!=MQTT_OK;
}

void remmqtt_flush (struct remmqtt * m)
{
	struct remmqtt_impl * im = m->client;
	struct sockopt sopt;
	struct timeval short_tv = { .tv_sec = 0, .tv_usec = 10000 };
	struct timeval normal_tv = { .tv_sec = 1 };

	memset(&sopt, 0, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_RCVTIMEO;
	sopt.sopt_val = &short_tv;
	sopt.sopt_valsize = sizeof(short_tv);
	(void)sosetopt(m->rc.so, &sopt);

	for (int i = 0; i<3; i++)
		(void)mqtt_sync(&im->c);
	mqtt_mq_clean(&im->c.mq);
	if (im->c.error==MQTT_ERROR_SEND_BUFFER_IS_FULL)
		im->c.error = MQTT_OK;

	sopt.sopt_val = &normal_tv;
	sopt.sopt_valsize = sizeof(normal_tv);
	(void)sosetopt(m->rc.so, &sopt);
}

int remmqtt_sync (struct remmqtt * m)
{
	struct remmqtt_impl * im = m->client;

	return mqtt_sync(&im->c) != MQTT_OK;
}

void remmqtt_close (struct remmqtt * m)
{
	struct remmqtt_impl* im = m->client;

	if (im!=NULL) {
		remws_close(&im->ws);
		free(im, M_TEMP);
	}
	if (m->sendbuf!=NULL) free(m->sendbuf, M_TEMP);
	if (m->recvbuf!=NULL) free(m->recvbuf, M_TEMP);

	rem_close(&m->rc);
	m->client = NULL;
	m->sendbuf = NULL;
	m->recvbuf = NULL;
}
