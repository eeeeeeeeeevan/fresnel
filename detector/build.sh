#!/bin/sh
# Packs detect-verbose.tar (detect + kprobe.c, with -v) and detect.tar
# (silent only). Both have the files at the archive root.
cd "$(dirname "$0")" || exit 1
pack() {
	COPYFILE_DISABLE=1 tar --no-xattrs --uid 0 --gid 0 --uname root \
		--gname wheel -cf "$1" -C "$2" detect kprobe.c
}
pack detect-verbose.tar .
pack detect.tar .
