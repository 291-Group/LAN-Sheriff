#!/usr/bin/env bash
# Builds a Raspberry Pi capture binary from a machine that is not a Pi.
#
# # Why
#
# Patrol Mode is the half of this product that a portable build cannot show, and
# a capture build cannot be cross-compiled by `go build` alone: it needs cgo,
# which needs a C toolchain and a libpcap for the target. So the only ways to
# get one have been to run the release pipeline or to build on the Pi itself,
# and neither is convenient for testing a change made ten minutes ago.
#
# Docker has an arm64 runtime available through emulation. It is slow, several
# minutes rather than seconds, and it produces exactly the binary the release
# produces.
#
# # libpcap is built from source, deliberately
#
# Debian's libpcap-dev cannot be used. Its libpcap.a is compiled with D-Bus
# support, so linking it statically fails on undefined references to
# dbus_connection_unref, and linking it dynamically produces a binary that
# refuses to start on any Pi without libpcap installed. The release builds
# libpcap from source with the optional backends switched off for exactly this
# reason, and this does the same, so the artifact matches.
#
#   scripts/build-pi-capture.sh [output-path]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/lan-sheriff-arm64-capture}"
LIBPCAP=1.10.5

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker version >/dev/null 2>&1 || { echo "docker is not running" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/out" "$(dirname "$OUT")"

# Built from a clean export rather than the working tree, so nothing untracked
# is compiled in and nothing root-owned is left behind in the checkout.
git -C "$ROOT" archive HEAD | tar -x -C "$work/src"
commit=$(git -C "$ROOT" rev-parse --short HEAD)
# The version comes from the Makefile, which is the single place it is set.
# This script used to run its own `git describe`, which is how a build set
# ends up stamped differently from `make build` on the same tree.
version=$(make -s -C "$ROOT" print-version)
build=$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 0)

cat > "$work/build.sh" <<EOF
set -eu
apt-get update -qq
apt-get install -y -qq wget build-essential flex bison >/dev/null

cd /tmp
wget -q https://www.tcpdump.org/release/libpcap-${LIBPCAP}.tar.gz
tar xzf libpcap-${LIBPCAP}.tar.gz
cd libpcap-${LIBPCAP}
./configure --disable-dbus --disable-bluetooth --disable-usb \\
            --disable-rdma --disable-shared --without-libnl >/dev/null
make -j"\$(nproc)" >/dev/null
make install >/dev/null

cd /src
CGO_ENABLED=1 CGO_LDFLAGS=/usr/local/lib/libpcap.a \\
  go build -tags patrol -trimpath \\
  -ldflags "-s -w -X github.com/291-Group/LAN-Sheriff/internal/cli.Version=${version} -X github.com/291-Group/LAN-Sheriff/internal/cli.Commit=${commit} -X github.com/291-Group/LAN-Sheriff/internal/cli.Build=${build}" \\
  -o /out/lan-sheriff ./cmd/lan-sheriff
EOF

echo "  building arm64 capture, emulated, this takes a few minutes"
docker run --rm --platform linux/arm64 \
  -v "$work/src:/src" -v "$work/out:/out" -v "$work/build.sh:/build.sh:ro" \
  golang:1.25-bookworm bash /build.sh

# Verified in the same container, because readelf and strings have to run
# somewhere that can read an arm64 binary, and because a build that is not
# checked is a build that gets copied onto a card and fails on the Pi.
docker run --rm --platform linux/arm64 \
  -v "$work/out:/out" -v "$ROOT/scripts:/s:ro" \
  golang:1.25-bookworm bash /s/verify-linux-binary.sh /out/lan-sheriff AArch64

cp "$work/out/lan-sheriff" "$OUT"
echo "  wrote $OUT"
