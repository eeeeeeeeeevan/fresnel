#ifndef JANITOR_VFS_H
#define JANITOR_VFS_H

#include "janitor.h"

static
int janitor_vfs_snapshot (struct vnode * vp, struct janitor_snap * snap)
{
	struct vattr va;
	int error = VOP_GETATTR(vp, &va, curthread->td_ucred);

	if (error!=0)
		return (error);
	snap->atime = va.va_atime;
	snap->mtime = va.va_mtime;
	snap->ctime = va.va_ctime;
	snap->modrev = 0;
	snap->size = va.va_size;
	return (0);
}

static
int janitor_vfs_restore_times (struct vnode * vp,
    const struct janitor_snap * snap)
{
	struct vattr va;

	VATTR_NULL(&va);
	va.va_atime = snap->atime;
	va.va_mtime = snap->mtime;
	return (VOP_SETATTR(vp, &va, curthread->td_ucred));
}

static
int janitor_vfs_restore (struct vnode * vp, const struct janitor_snap * snap)
{
	return (janitor_vfs_restore_times(vp, snap));
}

#endif
