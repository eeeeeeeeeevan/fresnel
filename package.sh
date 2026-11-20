#!/bin/sh
# package everything into assignment spec
set -e 
cd "$(dirname "$0")/src"

echo "build"
sh ./buildprivesc.sh

echo "package"
tar -cf ../rootkit.tar \
    install \
    elevate \
    log \
    remote \
    kelevate.ko

echo "done: rootkit.tar"
