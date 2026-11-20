#!/bin/sh
# package everything into assignment spec
set -e
cd "$(dirname "$0")"

perl vmbuild.pl rebuild

echo "done: rootkit.tar"
