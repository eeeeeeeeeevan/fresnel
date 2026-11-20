// kprobe: the kernel half of detect. read only, never writes kernel memory
// prints "STRONG <check>" or "WEAK <check>" per finding and nothing else
// cc -O1 -o kprobe kprobe.c -lkvm -lprocstat

#define _WANT_UCRED
#define _KVM_VNODE

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ucred.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_task.h>
#include <sys/cpuset.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/elf64.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <libprocstat.h>
#include <limits.h>
#include <nlist.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXFILES	512
#define MAXMODS		4096
#define MAXCAND		32
#define PROLOGUE	16

#define STRONG(c)	printf("STRONG %s\n", c)
#define WEAK(c)		printf("WEAK %s\n", c)

static int has_prefix(const char *s, const char *const *prefixes)
{
	for (; *prefixes != NULL; prefixes++)
		if (strncmp(s, *prefixes, strlen(*prefixes)) == 0)
			return (1);
	return (0);
}

static int contains(const uintptr_t *v, int n, uintptr_t x)
{
	while (n-- > 0)
		if (v[n] == x)
			return (1);
	return (0);
}

// run find a few more times and keep only what shows up every time,
// so we dont flag a module or process caught halfway through loading/forking
typedef int finder_fn(uintptr_t *out, int max);

static int persistent(finder_fn *find, int rounds, int pause_ms)
{
	uintptr_t cand[MAXCAND], again[MAXCAND];
	int n, m, i, keep;

	n = find(cand, MAXCAND);
	while (rounds-- > 0 && n > 0) {
		usleep((useconds_t)pause_ms * 1000);
		m = find(again, MAXCAND);
		for (i = keep = 0; i < n; i++)
			if (contains(again, m, cand[i]))
				cand[keep++] = cand[i];
		n = keep;
	}
	return (n);
}

// names from the midpoint docs
static const char *const bad_names[] = {
	"rk", "rk_core", "rkx", "rkd", "rkmod", "frk", "kelevate",
	"privesc", "elevate", "elevate_dev", "cockatoo", "sys_drv",
	"hiding", "kld_hiding", "port_hiding", "hide_kld", "escalate",
	"rootkit", "rootkit_lab", "rootkit_module_name", NULL
};

static int is_bad_name(const char *raw)
{
	char buf[MAXPATHLEN];
	const char *base = strrchr(raw, '/');
	size_t n;
	int i;

	// basename, drop .ko, lowercase
	strlcpy(buf, base != NULL ? base + 1 : raw, sizeof(buf));
	n = strlen(buf);
	if (n > 3 && strcmp(buf + n - 3, ".ko") == 0)
		buf[n - 3] = '\0';
	for (n = 0; buf[n] != '\0'; n++)
		buf[n] = (char)tolower((unsigned char)buf[n]);

	if (strncmp(buf, "rootkit", 7) == 0 || strncmp(buf, ".rk_", 4) == 0)
		return (1);
	for (i = 0; bad_names[i] != NULL; i++)
		if (strcmp(buf, bad_names[i]) == 0)
			return (1);
	return (0);
}

// linker files the way kldstat sees them (kldnext)
static struct kfile {
	int		id;
	uintptr_t	addr;
	size_t		size;
	char		name[MAXPATHLEN];
	char		path[MAXPATHLEN];
} files[MAXFILES];
static int nfiles, kernel_idx = -1;

static void load_files(void)
{
	struct kld_file_stat st;
	int id, n;

	nfiles = 0;
	kernel_idx = -1;
	for (id = kldnext(0), n = 0; id > 0 && nfiles < MAXFILES &&
	    n < 4 * MAXFILES; id = kldnext(id), n++) {
		memset(&st, 0, sizeof(st));
		st.version = sizeof(st);
		if (kldstat(id, &st) != 0)
			continue;
		files[nfiles].id = st.id;
		files[nfiles].addr = (uintptr_t)st.address;
		files[nfiles].size = st.size;
		strlcpy(files[nfiles].name, st.name, MAXPATHLEN);
		strlcpy(files[nfiles].path, st.pathname, MAXPATHLEN);
		if (st.id == 1)
			kernel_idx = nfiles;
		nfiles++;
	}
}

// which visible file holds this address, -1 if none
// modules first so a too-big kernel range cant swallow them
static int owner_of(uintptr_t a)
{
	int i;

	for (i = 0; i < nfiles; i++)
		if (i != kernel_idx && a >= files[i].addr &&
		    a < files[i].addr + files[i].size)
			return (i);
	if (kernel_idx >= 0 && a >= files[kernel_idx].addr &&
	    a < files[kernel_idx].addr + files[kernel_idx].size)
		return (kernel_idx);
	return (-1);
}

static void check_kld_names(void)
{
	static const char *const modnames[] = {
		"sys/privesc", "sys/kld_hiding", "sys/port_hiding", NULL
	};
	struct module_stat ms;
	char probe[MAXPATHLEN];
	const char *base;
	struct kfile *f;
	int i, m, n;

	for (i = 0; i < nfiles; i++) {
		f = &files[i];
		// only id 1 gets to be called kernel
		if (f->id != 1 && (strcmp(f->name, "kernel") == 0 ||
		    is_bad_name(f->name)))
			STRONG("kld-name");
		base = strrchr(f->path, '/');
		base = base != NULL ? base + 1 : f->path;
		if (f->path[0] != '\0' && strcmp(base, f->name) != 0)
			WEAK("kld-namepath");
		for (m = kldfirstmod(f->id), n = 0; m > 0 && n < MAXMODS;
		    m = modfnext(m), n++) {
			memset(&ms, 0, sizeof(ms));
			ms.version = sizeof(ms);
			if (modstat(m, &ms) == 0 && is_bad_name(ms.name))
				STRONG("kld-name");
		}
	}

	// kldfind/modfind search by name with different code to kldnext,
	// so a kit that only filters kldnext still answers to its name
	for (i = 0; bad_names[i] != NULL; i++) {
		snprintf(probe, sizeof(probe), "%s.ko", bad_names[i]);
		if (modfind(bad_names[i]) > 0 || kldfind(probe) > 0)
			STRONG("kld-lookup");
	}
	for (i = 0; modnames[i] != NULL; i++)
		if (modfind(modnames[i]) > 0)
			STRONG("kld-lookup");
}

// every module lives in some file, so a module that isnt inside any
// visible file means its file got unlinked
static int find_orphan_modules(uintptr_t *out, int max)
{
	static uintptr_t inview[MAXMODS];
	int nin = 0, n = 0, i, m, guard;

	load_files();
	for (i = 0; i < nfiles; i++)
		for (m = kldfirstmod(files[i].id), guard = 0; m > 0 &&
		    nin < MAXMODS && guard < MAXMODS; m = modfnext(m), guard++)
			inview[nin++] = (uintptr_t)m;
	for (m = modnext(0), guard = 0; m > 0 && n < max && guard < MAXMODS;
	    m = modnext(m), guard++)
		if (!contains(inview, nin, (uintptr_t)m))
			out[n++] = (uintptr_t)m;
	return (n);
}

static kvm_t *kd;

static int kread(uintptr_t addr, void *buf, size_t len)
{
	return (addr != 0 &&
	    kvm_read(kd, (unsigned long)addr, buf, len) == (ssize_t)len ? 0 : -1);
}

static uintptr_t ksym(const char *name)
{
	struct nlist nl[2] = { { .n_name = name } };

	return (kvm_nlist(kd, nl) == 0 ? (uintptr_t)nl[0].n_value : 0);
}

// the kernel file on disk is our known good copy of sysent and the code
static const unsigned char *kimg;
static size_t kimg_len;
static const Elf64_Ehdr *eh;
static int baseline_ok;

static int elf_open(const char *path)
{
	struct stat sb;
	void *p;
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (-1);
	p = fstat(fd, &sb) == 0 && sb.st_size > (off_t)sizeof(*eh) ?
	    mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0) :
	    MAP_FAILED;
	close(fd);
	if (p == MAP_FAILED)
		return (-1);
	kimg = p;
	kimg_len = (size_t)sb.st_size;
	eh = p;
	return (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
	    eh->e_ident[EI_CLASS] == ELFCLASS64 &&
	    eh->e_shoff + eh->e_shnum * sizeof(Elf64_Shdr) <= kimg_len &&
	    eh->e_phoff + eh->e_phnum * sizeof(Elf64_Phdr) <= kimg_len ? 0 : -1);
}

// pointer into the mapped file for kernel address va
static const unsigned char *elf_va(uintptr_t va, size_t len)
{
	const Elf64_Phdr *ph = (const Elf64_Phdr *)(kimg + eh->e_phoff);
	size_t off;
	int i;

	for (i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD || va < ph[i].p_vaddr ||
		    va + len > ph[i].p_vaddr + ph[i].p_filesz)
			continue;
		off = ph[i].p_offset + (va - ph[i].p_vaddr);
		return (off + len <= kimg_len ? kimg + off : NULL);
	}
	return (NULL);
}

// the kernel is linked -z notext -z ifunc-noplt, so it patches calls to
// memcpy/copyin/etc into its own code at boot. those bytes never match the
// file, so grab every relocation address and skip the 8 bytes after it
static uintptr_t *relocs;
static size_t nrelocs;

static int cmp_uptr(const void *a, const void *b)
{
	uintptr_t x = *(const uintptr_t *)a, y = *(const uintptr_t *)b;

	return (x < y ? -1 : x > y);
}

static void elf_load_relocs(void)
{
	const Elf64_Shdr *sh = (const Elf64_Shdr *)(kimg + eh->e_shoff);
	uintptr_t *grown;
	size_t ent, n, j;
	int i;

	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type == SHT_RELA)
			ent = sizeof(Elf64_Rela);
		else if (sh[i].sh_type == SHT_REL)
			ent = sizeof(Elf64_Rel);
		else
			continue;
		if (sh[i].sh_offset + sh[i].sh_size > kimg_len)
			continue;
		n = sh[i].sh_size / ent;
		if ((grown = realloc(relocs, (nrelocs + n) * sizeof(*relocs))) == NULL)
			break;
		relocs = grown;
		// r_offset comes first in both Rel and Rela
		for (j = 0; j < n; j++)
			relocs[nrelocs++] = ((const Elf64_Rel *)(kimg +
			    sh[i].sh_offset + j * ent))->r_offset;
	}
	qsort(relocs, nrelocs, sizeof(*relocs), cmp_uptr);
}

static int relocated(uintptr_t va)
{
	size_t lo = 0, hi = nrelocs, mid;

	// binary search for the first reloc past va
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (relocs[mid] <= va)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (lo > 0 && va - relocs[lo - 1] < 8);
}

// only trust the file if its the kernel thats actually running: the live
// version string has to be sitting at the same address in the file
static void setup_baseline(void)
{
	char bootfile[MAXPATHLEN] = "/boot/kernel/kernel", live[256] = "";
	size_t len = sizeof(bootfile);
	const unsigned char *disk;
	uintptr_t v;

	sysctlbyname("kern.bootfile", bootfile, &len, NULL, 0);
	if (elf_open(bootfile) != 0)
		return;
	elf_load_relocs();
	v = ksym("version");
	baseline_ok = kread(v, live, sizeof(live) - 1) == 0 &&
	    (disk = elf_va(v, sizeof(live) - 1)) != NULL &&
	    strncmp(live, (const char *)disk, sizeof(live) - 1) == 0;
}

// syscall table: every slot has to point into the kernel or a visible
// module, and a slot the disk kernel fills in has to still match it
static struct sysent live_sysent[SYS_MAXSYSCALL];

static void check_sysent(void)
{
	uintptr_t sv = ksym("sysent");
	uintptr_t empty[] = { ksym("nosys"), ksym("lkmnosys"),
	    ksym("lkmressys") };
	const struct sysent *disk = NULL;
	uintptr_t f, orig;
	int i, own, changed = 0, hooked = 0;

	if (kread(sv, live_sysent, sizeof(live_sysent)) != 0)
		return;
	if (baseline_ok)
		disk = (const struct sysent *)elf_va(sv, sizeof(live_sysent));

	for (i = 0; i < SYS_MAXSYSCALL; i++) {
		if ((f = (uintptr_t)live_sysent[i].sy_call) == 0)
			continue;
		// pointing at nothing visible = code from a hidden module
		if ((own = owner_of(f)) < 0) {
			STRONG("sysent");
			continue;
		}
		if (disk == NULL)
			continue;
		orig = (uintptr_t)disk[i].sy_call;
		if (f == orig || relocated(sv + i * sizeof(struct sysent) +
		    offsetof(struct sysent, sy_call)))
			continue;
		// empty slot a loadable syscall filled in, fine unless its in
		// the lkm range and came from outside /boot
		if (contains(empty, nitems(empty), orig)) {
			if (own != kernel_idx && i >= 210 && i <= 219 &&
			    strncmp(files[own].path, "/boot/", 6) != 0)
				WEAK("sysent-dyn");
			continue;
		}
		changed++;
		if (own != kernel_idx)
			hooked++;
	}
	// NOTE: a kit rewrites a handful of slots, dozens means the baseline is off
	if (changed > 40)
		return;
	if (hooked > 0)
		STRONG("sysent");
	if (changed > hooked)
		WEAK("sysent");
}

// inline hooks: first bytes of syscall handlers and popular hook targets
// vs the same bytes in the disk kernel
static const char *const inline_targets[] = {
	"kern_fcntl", "kern_getdirentries", "ttydisc_read", "kern_kill",
	"kern_execve", "kern_openat", "kern_statat", "kern_kldload",
	"kern_kldunload", "kern_rmdirat", "kern_setuid", "kern_kldstat",
	"sys_getdirentries", "sys_kill", "sys_read", "sys_execve",
	"sys_kldnext", "sys_kldstat", "sys_kldfind", "sys___sysctl",
	"userland_sysctl", "sysctl_root", "namei", "vn_open", "ufs_lookup",
	"vfs_cache_lookup", "devfs_lookup", "tcp_input", "udp_input",
	"icmp_input", "ip_input", "tty_rint", "ttydisc_rint", "kbdmux_read",
	"proc_set_cred", "crcopy", "linker_file_foreach",
	"linker_find_file_by_name", "pfind", "kern_proc_out", NULL
};

static int add_target(uintptr_t *t, int n, uintptr_t a)
{
	if (a == 0 || owner_of(a) != kernel_idx || contains(t, n, a))
		return (n);
	t[n] = a;
	return (n + 1);
}

// jmp rel8/rel32, movabs rax/r11 imm64, jmp [rip+x], push imm32; ret
static int looks_like_jump(const unsigned char *b)
{
	return (b[0] == 0xe9 || b[0] == 0xeb ||
	    (b[0] == 0x48 && b[1] == 0xb8) || (b[0] == 0x49 && b[1] == 0xbb) ||
	    (b[0] == 0xff && b[1] == 0x25) || (b[0] == 0x68 && b[5] == 0xc3));
}

static void check_inline(void)
{
	uintptr_t t[SYS_MAXSYSCALL + nitems(inline_targets)];
	unsigned char live[PROLOGUE];
	const unsigned char *disk;
	int i, j, n = 0, compared = 0, changed = 0, jumps = 0;

	if (!baseline_ok || kernel_idx < 0)
		return;
	for (i = 0; i < SYS_MAXSYSCALL; i++)
		n = add_target(t, n, (uintptr_t)live_sysent[i].sy_call);
	for (i = 0; inline_targets[i] != NULL; i++)
		n = add_target(t, n, ksym(inline_targets[i]));

	for (i = 0; i < n; i++) {
		if ((disk = elf_va(t[i], PROLOGUE)) == NULL ||
		    kread(t[i], live, PROLOGUE) != 0)
			continue;
		compared++;
		// ignore relocs and dtrace's int3 (0xcc) breakpoints
		for (j = 0; j < PROLOGUE; j++)
			if (live[j] != disk[j] && live[j] != 0xcc &&
			    !relocated(t[i] + j))
				break;
		if (j == PROLOGUE)
			continue;
		changed++;
		if (looks_like_jump(live) && !relocated(t[i]))
			jumps++;
	}
	// NOTE: same idea as the sysent cutoff
	if (changed > 20 && changed * 4 > compared)
		return;
	// every midpoint inline hook starts with a jump, anything else is weak
	if (jumps > 0)
		STRONG("inline");
	if (changed > jumps)
		WEAK("inline-modified");
}

// what ps sees (the kern.proc sysctl)
static struct procstat *pss;
static struct kinfo_proc *vis;
static unsigned int nvis;

static int snapshot_procs(void)
{
	if (vis != NULL)
		procstat_freeprocs(pss, vis);
	vis = procstat_getprocs(pss, KERN_PROC_PROC, 0, &nvis);
	return (vis == NULL ? -1 : 0);
}

static int visible_pid(pid_t p)
{
	unsigned int i;

	for (i = 0; i < nvis; i++)
		if (vis[i].ki_pid == p)
			return (1);
	return (0);
}

// children of visible procs that ps cant see. keyed on pid not the proc
// address, procs get reused so a fork loop can land on the same address
static int find_unlisted_children(uintptr_t *out, int max)
{
	uintptr_t child;
	pid_t pid;
	int n = 0, state, guard;
	unsigned int i;

	if (snapshot_procs() != 0)
		return (0);
	for (i = 0; i < nvis && n < max; i++) {
		if (kread((uintptr_t)vis[i].ki_paddr +
		    offsetof(struct proc, p_children), &child, sizeof(child)) != 0)
			continue;
		for (guard = 0; child != 0 && n < max && guard < 100000;
		    guard++) {
			if (kread(child + offsetof(struct proc, p_pid), &pid,
			    sizeof(pid)) != 0 ||
			    kread(child + offsetof(struct proc, p_state), &state,
			    sizeof(state)) != 0)
				break;
			if (state != PRS_NEW && !visible_pid(pid) &&
			    !contains(out, n, (uintptr_t)pid))
				out[n++] = (uintptr_t)pid;
			if (kread(child + offsetof(struct proc, p_sibling),
			    &child, sizeof(child)) != 0)
				break;
		}
	}
	return (n);
}

static int pid_max = 99999;

// kill(pid, 0) sends nothing, it just asks if the pid exists
static int find_unlisted_pids(uintptr_t *out, int max)
{
	pid_t p;
	int n = 0;

	if (snapshot_procs() != 0)
		return (0);
	for (p = 1; p <= pid_max && n < max; p++)
		if ((kill(p, 0) == 0 || errno == EPERM) && !visible_pid(p))
			out[n++] = (uintptr_t)p;
	return (n);
}

// kernels own process counter vs what ps shows, weak cos procs come and go
static void check_nprocs(void)
{
	uintptr_t a = ksym("nprocs");
	int k, n, first = 0;

	for (k = 0; k < 5; k++) {
		if (kread(a, &n, sizeof(n)) != 0 || snapshot_procs() != 0)
			return;
		if (k == 0)
			first = n - (int)nvis;
		else if (n - (int)nvis != first)
			return;
		usleep(150 * 1000);
	}
	if (first > 0)
		WEAK("nprocs");
}

// sysctls anyone can write are a free privesc door. stock freebsd only has
// a few and theyre all under anybody_ok
static int oid_query(int op, const int *oid, size_t len, void *buf,
    size_t *buflen)
{
	int q[CTL_MAXNAME + 2] = { CTL_SYSCTL, op };

	memcpy(q + 2, oid, len * sizeof(int));
	return (sysctl(q, (u_int)(len + 2), buf, buflen, NULL, 0));
}

static void check_sysctl_anybody(void)
{
	static const char *const anybody_ok[] = { "kern.devname",
	    "kern.proc.", "kern.binmisc.", "hw.", "dev.", "sysctl.", NULL };
	static const char *const sensitive[] = { "kern.", "debug.",
	    "security.", "vfs.", "vm.", "net.", "user.", NULL };
	const u_int wanted = CTLFLAG_ANYBODY | CTLFLAG_WR;
	int oid[CTL_MAXNAME] = { CTL_KERN }, next[CTL_MAXNAME];
	char buf[BUFSIZ];
	size_t len = 1, blen;
	u_int kind;
	int guard;

	// NOSKIP so we also walk the ones hidden from sysctl -a
	for (guard = 0; guard < 200000; guard++) {
		blen = sizeof(next);
		if (oid_query(CTL_SYSCTL_NEXTNOSKIP, oid, len, next, &blen) != 0)
			break;
		len = blen / sizeof(int);
		if (len == 0 || len > CTL_MAXNAME)
			break;
		memcpy(oid, next, blen);

		blen = sizeof(buf);
		if (oid_query(CTL_SYSCTL_OIDFMT, oid, len, buf, &blen) != 0 ||
		    blen < sizeof(kind))
			continue;
		memcpy(&kind, buf, sizeof(kind));
		if ((kind & wanted) != wanted)
			continue;

		memset(buf, 0, sizeof(buf));
		blen = sizeof(buf) - 1;
		if (oid_query(CTL_SYSCTL_NAME, oid, len, buf, &blen) != 0 ||
		    has_prefix(buf, anybody_ok))
			continue;
		if (has_prefix(buf, sensitive))
			STRONG("sysctl-anybody");
		else
			WEAK("sysctl-anybody");
	}
}

// a dirs v_op table should be static data in the kernel or a fs module.
// anywhere else means someone built a copy at runtime and swapped entries
static void check_vnode_ops(void)
{
	static const char *const dirs[] = { "/", "/tmp", "/tmp/cockatoo",
	    "/dev", "/boot", "/boot/kernel", "/boot/modules", "/etc", "/root",
	    "/home", "/usr", "/usr/local", "/var", "/bin", "/sbin" };
	int fds[nitems(dirs)];
	struct procstat *ps;
	struct kinfo_proc *kp;
	struct filestat_list *fl = NULL;
	struct filestat *fst;
	unsigned int cnt;
	uintptr_t vop;
	size_t i;

	for (i = 0; i < nitems(dirs); i++)
		fds[i] = open(dirs[i], O_RDONLY | O_DIRECTORY);
	// procstat over kvm hands us the vnode pointer behind each fd
	if ((ps = procstat_open_kvm(NULL, NULL)) == NULL)
		goto out;
	kp = procstat_getprocs(ps, KERN_PROC_PID, getpid(), &cnt);
	if (kp != NULL && cnt > 0)
		fl = procstat_getfiles(ps, kp, 0);
	if (fl != NULL) {
		STAILQ_FOREACH(fst, fl, next) {
			if (fst->fs_type != PS_FST_TYPE_VNODE ||
			    fst->fs_typedep == NULL || fst->fs_fd < 0)
				continue;
			for (i = 0; i < nitems(dirs) && fds[i] != fst->fs_fd; i++)
				;
			if (i < nitems(dirs) && kread((uintptr_t)fst->fs_typedep +
			    offsetof(struct vnode, v_op), &vop, sizeof(vop)) == 0 &&
			    vop != 0 && owner_of(vop) < 0)
				STRONG("vnode-ops");
		}
		procstat_freefiles(ps, fl);
	}
	if (kp != NULL)
		procstat_freeprocs(ps, kp);
	procstat_close(ps);
out:
	for (i = 0; i < nitems(dirs); i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

int main(void)
{
	char errbuf[_POSIX2_LINE_MAX];
	size_t len = sizeof(pid_max);
	uintptr_t end;

	if (geteuid() != 0 || (pss = procstat_open_sysctl()) == NULL)
		return (0);
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGSYS, SIG_IGN);

	load_files();
	if (nfiles == 0)
		return (0);
	check_kld_names();
	if (persistent(find_orphan_modules, 2, 200) > 0)
		STRONG("kld-crossview");
	sysctlbyname("kern.pid_max", &pid_max, &len, NULL, 0);
	if (persistent(find_unlisted_pids, 3, 250) > 0)
		STRONG("pid-sweep");
	check_sysctl_anybody();

	if ((kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf)) == NULL)
		return (0);
	load_files();
	// the kernels own size can come back as all of kernel space, which
	// makes "inside the kernel" meaningless. cut it off at `end`
	if (kernel_idx >= 0 && files[kernel_idx].size > (size_t)512 << 20 &&
	    (end = ksym("end")) > files[kernel_idx].addr)
		files[kernel_idx].size = end - files[kernel_idx].addr;
	setup_baseline();
	check_sysent();
	check_inline();
	if (persistent(find_unlisted_children, 2, 300) > 0)
		STRONG("proc-tree");
	check_nprocs();
	check_vnode_ops();
	return (0);
}
