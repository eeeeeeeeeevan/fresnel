#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/linker.h>
#include <sys/sx.h>
#include <sys/tty.h>

#include "ttylog.h"
#include "shellproxy.h"

#define TTYLOG_MAX 64
#define TTYLOG_LINE 512

struct ttylog_list {
	struct tty* tqh_first;
	struct tty** tqh_last;
};

struct ttylog_state {
	struct tty* tp;
	void* dev;
	unsigned int gen;
	char last[TTYLOG_LINE];
	size_t lastlen;
	char line[TTYLOG_LINE];
	size_t linelen;
};

struct ttylog_iter {
	char* buf;
	size_t len;
};

static struct ttylog_state ttylog_states[TTYLOG_MAX];
static ttylog_input_t* ttylog_input;
static void* ttylog_arg;
static struct ttylog_list* ttylog_list;
static struct sx* ttylog_sx;
static unsigned int ttylog_gen;
static int ttylog_run;

static
void ttylog_input_data (const char* data, size_t len)
{
	if (ttylog_input!=NULL)
		ttylog_input(ttylog_arg, data, len);
}

static
void ttylog_line_iter (void* arg, char c, int flags)
{
	struct ttylog_iter* it = arg;

	(void)flags;
	if (it->len < TTYLOG_LINE)
		it->buf[it->len++] = c;
}

static
struct ttylog_state* ttylog_state_get (struct tty* tp, void* dev, unsigned int gen, int alloc)
{
	struct ttylog_state* free = NULL;

	for (int i=0; i<TTYLOG_MAX; i++) {
		struct ttylog_state* st = &ttylog_states[i];

		if (st->tp==tp) {
			if (st->dev!=dev) {
				memset(st, 0, sizeof(*st));
				st->tp = tp;
				st->dev = dev;
			}
			st->gen = gen;
			return (st);
		}
		if (st->tp==NULL && free==NULL)
			free = st;
	}
	if (!alloc || free==NULL)
		return (NULL);
	memset(free, 0, sizeof(*free));
	free->tp = tp;
	free->dev = dev;
	free->gen = gen;
	return (free);
}

static
void ttylog_emit (struct ttylog_state* st)
{
	if (st->linelen > 0)
		ttylog_input_data(st->line, st->linelen);
	ttylog_input_data("\n", 1);
	st->linelen = 0;
	st->lastlen = 0;
}

static
void ttylog_ingest (struct ttylog_state* st, const char* cur, size_t curlen)
{
	if (curlen==0) {
		if (st->lastlen > 0)
			ttylog_emit(st);
		return;
	}

	if (st->lastlen==0) {
		memcpy(st->line, cur, curlen);
		st->linelen = curlen;
	} else if (curlen>=st->lastlen &&
	    memcmp(cur, st->last, st->lastlen)==0) {
		if (curlen>st->lastlen && st->linelen<TTYLOG_LINE) {
			size_t n = curlen-st->lastlen;

			if (n>TTYLOG_LINE-st->linelen)
				n = TTYLOG_LINE-st->linelen;
			memcpy(st->line+st->linelen, cur+st->lastlen, n);
			st->linelen += n;
		}
	} else if (curlen<st->lastlen && memcmp(cur, st->last, curlen)==0) {
		memcpy(st->line, cur, curlen);
		st->linelen = curlen;
	} else {
		ttylog_emit(st);
		memcpy(st->line, cur, curlen);
		st->linelen = curlen;
	}

	memcpy(st->last, cur, curlen);
	st->lastlen = curlen;
}

void ttylog_poll (void)
{
	struct tty* tp;
	unsigned int gen;
	char cur[TTYLOG_LINE];

	if (!ttylog_run || ttylog_list==NULL || ttylog_sx==NULL)
		return;
	if (!sx_try_slock(ttylog_sx))
		return;

	gen = ++ttylog_gen;
	for (tp = ttylog_list->tqh_first; tp!=NULL; tp = TAILQ_NEXT(tp, t_list)) {
		struct ttylog_state* st;
		struct ttylog_iter it;
		void* dev = tp->t_dev;

		(void)ttylog_state_get(tp, dev, gen, 0);

		if (!mtx_trylock(tp->t_mtx))
			continue;
		if (!(tp->t_flags & TF_OPENED) ||
		    !(tp->t_termios.c_lflag & ICANON)) {
			mtx_unlock(tp->t_mtx);
			continue;
		}
		it.buf = cur;
		it.len = 0;
		ttyinq_line_iterate_from_linestart(&tp->t_inq, ttylog_line_iter, &it);
		mtx_unlock(tp->t_mtx);

		st = ttylog_state_get(tp, dev, gen, 1);
		if (st!=NULL)
			ttylog_ingest(st, cur, it.len);
	}

	for (int i=0; i<TTYLOG_MAX; i++) {
		if (ttylog_states[i].tp!=NULL &&
		    ttylog_states[i].gen!=gen)
			memset(&ttylog_states[i], 0, sizeof(ttylog_states[i]));
	}
	sx_sunlock(ttylog_sx);
}

int ttylog_start (ttylog_input_t* input, void* arg)
{
	ttylog_input = input;
	ttylog_arg = arg;
	ttylog_gen = 0;
	ttylog_run = 1;
	memset(ttylog_states, 0, sizeof(ttylog_states));

	ttylog_list = (struct ttylog_list*)linker_file_lookup_symbol(
	    linker_kernel_file, "tty_list", 0);
	ttylog_sx = (struct sx*)linker_file_lookup_symbol(
	    linker_kernel_file, "tty_list_sx", 0);
	if (ttylog_list==NULL || ttylog_sx==NULL) {
		ttylog_run = 0;
		ttylog_input = NULL;
		ttylog_arg = NULL;
		return (ENXIO);
	}

	proxy_attr_tty_start();
	return (0);
}

void ttylog_stop (void)
{
	ttylog_run = 0;
	ttylog_input = NULL;
	ttylog_arg = NULL;
	proxy_attr_tty_stop();
}
