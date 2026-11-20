#ifndef JANITOR_UFS_H
#define JANITOR_UFS_H

#include "janitor.h"

#include <ufs/ufs/quota.h>
#include <ufs/ufs/extattr.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>

static
int janitor_ufs_snapshot (struct vnode * vp, struct janitor_snap * snap)
{
	struct inode * ip = VTOI(vp);

	VI_LOCK(vp);
	// here goes
	snap->atime.tv_sec = DIP(ip, i_atime);
	snap->atime.tv_nsec = DIP(ip, i_atimensec);
	snap->mtime.tv_sec = DIP(ip, i_mtime);
	snap->mtime.tv_nsec = DIP(ip, i_mtimensec);
	snap->ctime.tv_sec = DIP(ip, i_ctime);
	snap->ctime.tv_nsec = DIP(ip, i_ctimensec);
	snap->modrev = DIP(ip, i_modrev);
	snap->size = ip->i_size;
	VI_UNLOCK(vp);
	return (0);
}

// write attribs/metadata directly into the ufs inode
// then clear flags so UFS_UPDATE doesnt race us again
static
int janitor_ufs_restore_times (struct vnode * vp,
    const struct janitor_snap * snap)
{
	struct inode * ip = VTOI(vp);
	int error;

	VI_LOCK(vp);
	DIP_SET(ip, i_atime, snap->atime.tv_sec);
	DIP_SET(ip, i_atimensec, snap->atime.tv_nsec);
	DIP_SET(ip, i_mtime, snap->mtime.tv_sec);
	DIP_SET(ip, i_mtimensec, snap->mtime.tv_nsec);
	DIP_SET(ip, i_ctime, snap->ctime.tv_sec);
	DIP_SET(ip, i_ctimensec, snap->ctime.tv_nsec);
	ip->i_flag &= ~(IN_ACCESS|IN_UPDATE|IN_CHANGE);
	UFS_INODE_SET_FLAG(ip, IN_MODIFIED);
	VI_UNLOCK(vp);
	// go and do it bradar
	error = UFS_UPDATE(vp, 0);
	return (error);
}

// similar to restore_times but restores modrev too
static
int janitor_ufs_restore (struct vnode * vp,
    const struct janitor_snap * snap)
{
	struct inode * ip = VTOI(vp);
	int error;

	VI_LOCK(vp);
	DIP_SET(ip, i_atime, snap->atime.tv_sec);
	DIP_SET(ip, i_atimensec, snap->atime.tv_nsec);
	DIP_SET(ip, i_mtime, snap->mtime.tv_sec);
	DIP_SET(ip, i_mtimensec, snap->mtime.tv_nsec);
	DIP_SET(ip, i_ctime, snap->ctime.tv_sec);
	DIP_SET(ip, i_ctimensec, snap->ctime.tv_nsec);
	DIP_SET(ip, i_modrev, snap->modrev);
	ip->i_flag &= ~(IN_ACCESS|IN_UPDATE|IN_CHANGE);
	UFS_INODE_SET_FLAG(ip, IN_MODIFIED);
	VI_UNLOCK(vp);
	error = UFS_UPDATE(vp, 0);
	return (error);
}

#endif
