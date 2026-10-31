#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
[ "$(uname -s)" = FreeBSD ] || { echo 'Build on FreeBSD/OPNsense.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ports_dir=${PORTSDIR:-/usr/ports}
[ -f "$ports_dir/Mk/bsd.port.mk" ] || { echo 'Set PORTSDIR to a complete FreeBSD/OPNsense ports tree.' >&2; exit 1; }
mkdir -p "$source_dir/dist"
# Extra make arguments allow use of an existing toolchain or build configuration.
make -C "$source_dir/ports/net/pangolin-newt" PORTSDIR="$ports_dir" BATCH=yes "$@" checksum package
cp "$source_dir/ports/net/pangolin-newt/work/pkg/pangolin-newt-1.18.1.pkg" "$source_dir/dist/"
(cd "$source_dir/dist" && sha256 -r pangolin-newt-1.18.1.pkg > SHA256SUMS.port)
