#!/bin/sh
set -e
CACHE=/root/.freebsd-cache
REL=14.5-RELEASE
BASE="$CACHE/freebsd-$REL.qcow2"
IMG="$CACHE/freebsd-$REL.qcow2.tmp"

mkdir -p "$CACHE"
rm -f "$CACHE"/*.qcow2.tmp
if [ -f "$BASE" ]; then
	echo "base image already good"
	exit 0
fi

echo "downloading freebsd $REL"
[ -f "$CACHE/img.xz" ] || curl -fL "https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest/FreeBSD-$REL-amd64-ufs.qcow2.xz" -o "$CACHE/img.xz"
[ -f "$CACHE/src.txz" ] || curl -fL "https://download.freebsd.org/releases/amd64/$REL/src.txz" -o "$CACHE/src.txz"
[ -f "$CACHE/id_ed25519" ] || ssh-keygen -t ed25519 -N "" -f "$CACHE/id_ed25519" -q

echo "done,decompress"
xz -dkc "$CACHE/img.xz" > "$IMG"
qemu-img resize "$IMG" 10G

echo "booting up"
cd /app
python3 - <<EOF
import os
import sys
import time

import pexpect

CACHE = os.environ.get("VM_CACHE", os.path.expanduser("~/.freebsd-cache"))
REL = "14.5-RELEASE"
IMG = f"{CACHE}/freebsd-{REL}.qcow2.tmp"
KEY = f"{CACHE}/id_ed25519"

with open(KEY + ".pub") as f:
    PUB = f.read().strip()

accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else ["-cpu", "max"]

cmd = [
    "qemu-system-x86_64", *accel, "-m", "2048M", "-smp", "2", "-nographic",
    "-drive", f"file={IMG},format=qcow2,if=virtio",
    "-drive", f"file={CACHE}/src.txz,format=raw,if=virtio,readonly=on",
]

c = pexpect.spawn(cmd[0], cmd[1:], encoding="utf-8", timeout=600)
c.logfile_read = sys.stdout

i = c.expect(["login:", "Autoboot", "Welcome to FreeBSD"])
if i != 0:
    c.send("5")
    time.sleep(1)
    c.send("\r")
    c.expect("login:")
c.send("root\r")
i = c.expect(["#", "Password:"])
if i == 1:
    sys.exit("root login wants a password, cannot provision")


def run(line):
    c.sendline(line)
    c.expect("#")


run("service growfs onestart")
run("tar -xJf /dev/vtbd1 -C / usr/src/sys usr/src/share/mk")
run("echo 'freebsd' | pw usermod root -h 0")
run("pw useradd student -m -G wheel -s /bin/sh")
run("echo 'freebsd' | pw usermod student -h 0")
run("sysrc sshd_enable=YES")
run("echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config")
run("echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config")
run("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
run(f"echo '{PUB}' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")
run("mkdir -p /home/student/.ssh")
run(f"echo '{PUB}' > /home/student/.ssh/authorized_keys")
USERPUB = os.path.expanduser("~/.ssh/id_ed25519.pub")
if os.path.exists(USERPUB):
    with open(USERPUB) as f:
        upub = f.read().strip()
    run(f"echo '{upub}' >> /root/.ssh/authorized_keys")
    run(f"echo '{upub}' >> /home/student/.ssh/authorized_keys")
run("chown -R student:student /home/student")
run("chmod 750 /home/student && chmod 700 /home/student/.ssh && chmod 600 /home/student/.ssh/authorized_keys")
run("echo 'autoboot_delay=\"1\"' >> /boot/loader.conf")
run("echo 'console=\"comconsole,vidconsole\"' >> /boot/loader.conf")
c.sendline("poweroff")
c.expect(pexpect.EOF, timeout=120)
print("\n+ deployed")
EOF

mv "$IMG" "$BASE"
echo "done: $BASE"
