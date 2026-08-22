#!/usr/bin/env bash
# Asserts a Linux capture binary is what it claims to be, before it goes
# anywhere near a test machine.
#
# The release makes this same check in CI. It is repeated here because binaries
# built by hand for testing skip CI entirely, and the failure being guarded
# against is quiet: a dynamically linked capture build runs perfectly on the
# machine that built it and refuses to start on a Raspberry Pi that has never
# installed libpcap, which is most of them.
#
# Written after getting it wrong by hand. That attempt piped readelf into grep
# and treated "no match" as success, so when the build had failed and the
# binary did not exist at all, it printed "pass". A check that cannot tell a
# clean result from a missing file is worse than no check, so every step here
# fails loudly and the file's existence is asserted first.
#
#   scripts/verify-linux-binary.sh <binary> [expected-arch]
#
# expected-arch is what readelf prints for Machine, e.g. AArch64 or X86-64.

set -euo pipefail

BIN="${1:?path to the binary}"
WANT_ARCH="${2:-}"

fail() { echo "  FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

[ -f "$BIN" ] || fail "$BIN does not exist. A build that did not produce a file is not a build that passed."
[ -s "$BIN" ] || fail "$BIN is empty"

# readelf is used rather than ldd throughout, because ldd can only inspect a
# binary the host is able to run and says nothing at all about a foreign
# architecture. An arm64 binary checked with ldd on an x86 machine reports
# nothing and looks fine.
command -v readelf >/dev/null || fail "readelf not available; run this inside a container that has binutils"

syms=$(mktemp)
trap 'rm -f "$syms"' EXIT
strings -a "$BIN" > "$syms" || fail "could not read strings from $BIN"

readelf -h "$BIN" >/dev/null 2>&1 || fail "$BIN is not an ELF binary"
arch=$(readelf -h "$BIN" | awk -F: '/Machine:/ {gsub(/^ +/, "", $2); print $2}')
pass "ELF, $arch"

if [ -n "$WANT_ARCH" ]; then
  case "$arch" in
    *"$WANT_ARCH"*) pass "architecture is $WANT_ARCH as expected" ;;
    *) fail "architecture is $arch, expected $WANT_ARCH" ;;
  esac
fi

# The whole point of the static link. gopacket declares its own -lpcap, so the
# linker takes the shared object whenever one is present unless the archive is
# named explicitly.
needed=$(readelf -d "$BIN" || true)
if printf '%s' "$needed" | grep -q 'NEEDED.*libpcap'; then
  printf '%s\n' "$needed" | grep NEEDED >&2 || true
  fail "needs libpcap at runtime; it will not start on a machine without it"
fi
pass "no runtime libpcap dependency"

# Capture has to actually be compiled in. A binary built without the tag links
# and runs and quietly only ever does Deputy Mode, which is the failure this is
# most likely to be handed.
#
# Matching on "libpcap" alone does not work, and matching on function names like
# pcap_activate does not either. The portable build contains the word libpcap in
# two places, once in the advice string telling somebody to install libpcap-dev
# and once per language in the translated Npcap hint, so a loose match calls
# every portable build a capture build. And these binaries are stripped, so
# libpcap's own function names are not present as text even when it is linked in.
#
# gopacket's import path is the honest signal: it is compiled in only under the
# patrol tag, and nothing else in the tree mentions it.
if grep -q 'gopacket/pcap' "$syms"; then
  pass "packet capture is compiled in"
else
  fail "no gopacket/pcap; this is a portable build, not a capture build"
fi

# Belt and braces on the static link. libpcap prints its own version banner, and
# that string is inside the binary only when the library itself is, rather than
# behind a shared object.
if ver=$(grep -m1 'libpcap version' "$syms"); then
  pass "carries its own libpcap: $ver"
else
  fail "no libpcap version banner; the library is not linked into this binary"
fi

# **The toolchain that actually produced it, not the one that was asked for.**
#
# Everything above proves the binary is the right shape. None of it notices a
# right-shaped binary compiled against a standard library with known advisories,
# which is what happened: the golang image sets GOTOOLCHAIN=local, the floor in
# go.mod was ignored inside the container, and two of twelve artifacts were
# built on an older Go while the build reported ok for both.
#
# Read out of the binary rather than from the environment, because the
# environment is what lied last time.
want=${WANT_GO:-go1.25.14}
if got=$(go version -m "$BIN" 2>/dev/null | awk 'NR==1 {print $2}') && [ -n "$got" ]; then
  if [ "$got" = "$want" ]; then
    pass "built with $got"
  else
    older=$(printf '%s\n%s\n' "$want" "$got" | sort -V | head -1)
    if [ "$older" = "$got" ]; then
      fail "built with $got, older than the $want floor in go.mod"
    else
      pass "built with $got, newer than the $want floor"
    fi
  fi
else
  fail "cannot read the Go build info; refusing to call this verified"
fi

echo "  $BIN verified"
