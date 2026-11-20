# vm builder
# everyone should have perl right lol


use strict;
use warnings;
use IO::Socket::INET;

my $KEY = "$ENV{HOME}/.freebsd-cache/id_ed25519";
my $VM = "root\@127.0.0.1";
my $VMDIR = "/root/build";
my $MODE = shift // "rebuild";
my $CACHE = "$ENV{HOME}/.freebsd-cache";
my $PORT_FILE = "$CACHE/lab-port";
my $PORT_EXPLICIT = exists $ENV{LAB_PORT} || exists $ENV{SSH_PORT};
my $PORT = $ENV{LAB_PORT} // $ENV{SSH_PORT} // "2222";
if (!$PORT_EXPLICIT && -f $PORT_FILE) {
    open my $port_fh, "<", $PORT_FILE or die "cannot read $PORT_FILE: $!\n";
    chomp($PORT = <$port_fh> // "");
    close $port_fh;
}
my $REL = "14.5-RELEASE";
my $BASE = "$CACHE/freebsd-$REL.qcow2";
my $OVERLAY = "$CACHE/lab-overlay.qcow2";
my $PIDFILE = "$CACHE/lab-qemu.pid";
my $CONSOLE = "$CACHE/console.log";
my $MEM = $ENV{LAB_MEM} // "2048M";
my $SMP = $ENV{LAB_SMP} // "2";
my $HOST_IP = "10.0.2.2";

my @ssh_opts = (
    "-i", $KEY,
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
);

my @scp_opts = (
    "-q", "-r",
    "-i", $KEY,
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
);

my @SRCS = (
    "build.py",
    "config.json",
    "configgen.c",
    "src/include/json.h",
    "shellcoder/pe.S",
    "shellcoder/shutdown_handler.c",
    "src/tools/privesc.c",
    "src/tools/install",
    "src/stager",
    "src/shellproxy",
    "src/include",
    "src/lib",
    "remote/remote",
    "remote/log",
    "src/lib/spinneret.c",
    "src/lib/uehook.c",
    "src/include/common.h",
    "src/include/ehook.h",
    "src/include/injector.h",
    "src/include/janitor.h",
    "src/include/janitor_ufs.h",
    "src/include/janitor_vfs.h",
    "src/include/spinneret.h",
    "src/include/uehook.h",
    "src/include/stb_ds.h",
);

sub run {
    my (@cmd) = @_;
    system(@cmd) == 0 or die "failed: @cmd\n";
}

sub port_available {
    my ($port) = @_;
    my $socket = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1",
        LocalPort => $port,
        Proto => "tcp",
        Listen => 1,
        ReuseAddr => 0,
    );
    return 0 unless $socket;
    close $socket;
    return 1;
}

sub select_port {
    die "invalid port retard\n" unless $PORT =~ /^\d+$/ && $PORT >= 1 && $PORT <= 65535;
    return if port_available($PORT);
    die "$PORT occupied bro\n" if $PORT_EXPLICIT;

    my $requested = $PORT;
    my $last = ($requested + 100 < 65535) ? $requested + 100 : 65535;
    for (my $candidate = $requested + 1; $candidate <= $last; $candidate++) {
        if (port_available($candidate)) {
            $PORT = $candidate;
            print "+ port $requested in useusing $PORT\n";
            return;
        }
    }
    die "no free ports $requested\n";
}

sub ssh_cmd {
    my ($cmd) = @_;
    return ("ssh", @ssh_opts, "-p", $PORT, $VM, $cmd);
}

sub scp_to_vm {
    my (@files) = @_;
    return ("scp", @scp_opts, "-P", $PORT, @files, "$VM:$VMDIR/");
}

sub scp_from_vm {
    my ($remote, $local) = @_;
    return ("scp", @scp_opts, "-P", $PORT, "$VM:$remote", $local);
}

sub wait_for_ssh {
    print "+ waiting for ssh...\n";
    for my $i (1..60) {
        sleep 5;
        my @cmd = ("ssh", @ssh_opts, "-p", $PORT, "-o", "ConnectTimeout=3", $VM, "true");
        return if system(@cmd) == 0;
        die "vm did not come up\n" if $i == 60;
    }
}

sub vm_pid {
    return undef unless -f $PIDFILE;
    open my $fh, "<", $PIDFILE or return undef;
    my $pid = <$fh>;
    close $fh;
    chomp $pid;
    return $pid;
}

sub vm_alive {
    my $pid = vm_pid();
    return $pid && kill(0, $pid) ? 1 : 0;
}

sub reset_vm {
    my $pid = vm_pid();
    if ($pid) {
        print "+ nuking old vm just in case\n";
        system("ssh", @ssh_opts, "-p", $PORT, $VM, "poweroff >/dev/null 2>&1");
        for (1..20) {
            last unless kill(0, $pid);
            sleep 1;
        }
        kill("KILL", $pid);
    }
    # kill just in case
    system("pkill", "-TERM", "-f", "hostfwd=tcp:127.0.0.1:$PORT-:22");
    system("pkill", "-TERM", "-f", "file=$OVERLAY");
    sleep 2;
    system("pkill", "-KILL", "-f", "hostfwd=tcp:127.0.0.1:$PORT-:22");
    system("pkill", "-KILL", "-f", "file=$OVERLAY");
    unlink $PIDFILE, $OVERLAY;
    die "no base img: $BASE\n" unless -f $BASE;

    select_port();
    open my $port_fh, ">", $PORT_FILE or die "cannot write $PORT_FILE: $!\n";
    print {$port_fh} "$PORT\n";
    close $port_fh;

    print "+ new vm coming up\n";

    run("qemu-img", "create", "-f", "qcow2", "-b", $BASE, "-F", "qcow2", $OVERLAY);

    my @accel = (-w "/dev/kvm") ? ("-enable-kvm", "-cpu", "host") : ("-cpu", "max");

    run("qemu-system-x86_64", @accel, "-m", $MEM, "-smp", $SMP,
        "-drive", "file=$OVERLAY,format=qcow2,if=virtio",
        "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22",
        "-device", "virtio-net-pci,netdev=n0",
        "-display", "none", "-serial", "file:$CONSOLE", "-monitor", "none",
        "-pidfile", $PIDFILE, "-daemonize");

    print "+ booting\n";
    wait_for_ssh();
}

sub install_tar {
    print "+ installing rootkit.tar...\n";
    run("scp", @scp_opts, "-P", $PORT, "rootkit.tar", "$VM:/root/submission.tar");
    run(ssh_cmd("rm -rf /root/rootkit /home/student/rootkit && mkdir -p /root/rootkit /home/student/rootkit"));
    run(ssh_cmd("tar -xf /root/submission.tar -C /root/rootkit"));
    run(ssh_cmd("chmod +x /root/rootkit/install && cd /root/rootkit && ./install $HOST_IP"));
    run(ssh_cmd("cp -R /root/rootkit /home/student/rootkit && chown -R student:student /home/student/rootkit"));
}

if ($MODE eq "full") {
    reset_vm();
    print "+ checking python3...\n";
    run(ssh_cmd("which python3 || (pkg update -q && pkg install -q -y python3)"));
}
elsif ($MODE eq "fresh") {
    reset_vm();
}
elsif ($MODE ne "rebuild") {
    die "perl vmbuild.pl full/fresh/rebuild\n";
}

print "+ pushing...\n";
run(ssh_cmd("rm -rf $VMDIR && mkdir $VMDIR"));
run(scp_to_vm(@SRCS));

print "+ checking python3...\n";
run(ssh_cmd("which python3 >/dev/null 2>&1 || (pkg bootstrap -y && ASSUME_ALWAYS_YES=yes pkg install -y python3)"));

print "+ building...\n";
run(ssh_cmd("cd $VMDIR && python3 build.py"));

print "+ pulling tar...\n";
run(scp_from_vm("$VMDIR/rootkit.tar", "rootkit.tar"));
#install_tar() if $MODE eq "fresh";
print "+ done\n";
