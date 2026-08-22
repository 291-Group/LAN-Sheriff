#!/usr/bin/env bash
# Builds every artifact a release contains, for testing, from one machine.
#
# Twelve binaries: five with packet capture and seven portable. The point is to
# be able to hand a beta tester the same set the release will produce, built
# from the working tree rather than from a tag, so what gets tested is what is
# about to ship.
#
# # What each target needs, and why it is not obvious
#
#   portable, all 7      Nothing. CGO_ENABLED=0 cross-compiles anywhere.
#
#   windows capture      Nothing either, which is the surprising one. gopacket's
#                        Windows path is pure syscall: it loads wpcap.dll at
#                        runtime rather than linking against it, so there is no
#                        cgo and no Npcap SDK involved in producing the binary.
#                        The release passes an Npcap SDK path and a delayload
#                        flag, and .goreleaser.yaml records that both are inert.
#
#   darwin capture       A macOS host. Native for the host architecture; the
#                        other one needs clang's -arch, which Xcode supports in
#                        both directions.
#
#   linux capture        A libpcap for the target, built from source rather than
#                        installed, because Debian's libpcap.a carries D-Bus
#                        symbols and will not link statically. Done in Docker.
#                        arm64 is emulated and slow.
#
# Everything is verified after building rather than assumed: a capture build
# that quietly lost its capture is the failure most likely to reach a tester,
# because it starts, serves, and looks correct.
#
#   scripts/build-all.sh [output-dir]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/testing}"
# Absolute, because the Linux capture builds mount this into Docker and a
# relative path is not a path to Docker: `-v dist/build:/out` is read as a
# named volume, the name is rejected for containing a slash, and the run
# fails. The documented argument is [output-dir], so somebody passing a
# relative one is following the instructions, and the failure they get is two
# targets out of twelve with "docker build or verification" against them and
# nothing pointing at the actual cause.
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LIBPCAP=1.10.5

cd "$ROOT"
commit=$(git rev-parse --short HEAD)
# Base plus commits here; see the comment on BUILD_BASE in the Makefile.
base=$(cat "$ROOT/BUILD_BASE" 2>/dev/null || echo 0)
build=$(( base + $(git rev-list --count HEAD 2>/dev/null || echo 0) ))
# The version comes from the Makefile, which is the single place it is set.
# This script used to run its own `git describe`, which is how a build set
# ends up stamped differently from `make build` on the same tree.
version=$(make -s -C "$ROOT" print-version)
CLI=github.com/291-Group/LAN-Sheriff/internal/cli
# Stamped, so every binary behaves as a download rather than as a source tree.
# An unstamped build tells the reader to run `make patrol`, which is advice for
# a developer and wrong for everyone this set is going to.
LD="-s -w -X $CLI.Version=$version -X $CLI.Commit=$commit -X $CLI.BuildDate=$(date -u +%Y-%m-%d) -X $CLI.Build=$build"

mkdir -p "$OUT"
results=$(mktemp); trap 'rm -f "$results"' EXIT

note()  { printf '  %s\n' "$*"; }
ok()    { printf '%s|%s|ok\n'   "$1" "$2" >> "$results"; note "ok    $1 $2"; }
bad()   { printf '%s|%s|FAIL\n' "$1" "$2" >> "$results"; note "FAIL  $1 $2  ($3)"; }

# ── Portable, seven of them ──────────────────────────────────────────────────
note "portable builds"
for pair in linux:amd64 linux:arm64 linux:arm windows:amd64 windows:arm64 \
            freebsd:amd64 freebsd:arm64; do
  os=${pair%%:*}; arch=${pair##*:}
  ext=""; [ "$os" = windows ] && ext=.exe
  if CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LD" \
      -o "$OUT/lan-sheriff_${os}_${arch}_portable${ext}" ./cmd/lan-sheriff 2>/dev/null; then
    ok "$os/$arch" portable
  else
    bad "$os/$arch" portable "go build"
  fi
done

# ── Windows capture ──────────────────────────────────────────────────────────
note "windows capture"
if CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags patrol -trimpath \
    -ldflags "$LD" -o "$OUT/lan-sheriff_windows_amd64.exe" ./cmd/lan-sheriff 2>/dev/null; then
  # No readelf for a PE file, so check the one thing that distinguishes it.
  #
  # Written to a file first, never piped into grep. `strings | grep -q` under
  # `set -o pipefail` reports failure when it succeeds: grep exits at the first
  # match, strings takes SIGPIPE, and the pipeline returns the signal. That is
  # what made this call a correct binary broken.
  syms=$(mktemp)
  strings -a "$OUT/lan-sheriff_windows_amd64.exe" > "$syms"
  if grep -q 'gopacket/pcap' "$syms"; then
    ok windows/amd64 capture
  else
    bad windows/amd64 capture "no gopacket/pcap in the binary"
  fi
  rm -f "$syms"
else
  bad windows/amd64 capture "go build"
fi

# ── macOS capture, both architectures ────────────────────────────────────────
if [ "$(go env GOOS)" = darwin ]; then
  note "macOS capture"
  for arch in amd64 arm64; do
    # clang targets either architecture from either host, so CC is set the same
    # way for both and there is no native special case to get wrong. Passing it
    # through a ${var:+...} expansion did not survive word splitting, so the
    # compiler was silently never handed over and the cross build failed.
    case $arch in arm64) march=arm64 ;; *) march=x86_64 ;; esac
    if CC="clang -arch $march" CGO_ENABLED=1 GOOS=darwin GOARCH=$arch \
        go build -tags patrol -trimpath -ldflags "$LD" \
        -o "$OUT/lan-sheriff_darwin_${arch}" ./cmd/lan-sheriff 2>/dev/null; then
      ok "darwin/$arch" capture
    else
      bad "darwin/$arch" capture "cgo cross-compile"
    fi
  done
else
  note "not on macOS, skipping the darwin capture builds"
fi

# ── Linux capture, in Docker, with libpcap built from source ─────────────────
if command -v docker >/dev/null && docker version >/dev/null 2>&1; then
  # **These two build from HEAD, not from the working tree.**
  #
  # git archive gives the container a clean, reproducible source tree, which is
  # the right instinct. What it also does is quietly build something different
  # from the other ten targets whenever the tree is dirty, and "quietly" is the
  # problem: you get twelve binaries, ten from what you have and two from what
  # you committed, all stamped with the same version.
  #
  # That is not hypothetical either. The dashboard fix was committed as source
  # with the built bundle left unstaged, so HEAD carried an old bundle. The ten
  # native targets embedded the fixed dashboard and these two embedded the
  # broken one, and the two were the Raspberry Pi and the Linux PC.
  #
  # Still HEAD, because reproducibility is worth keeping. Loud now, because a
  # difference you are told about is a choice and a difference you are not is a
  # trap.
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo
    echo "  ! the working tree is dirty, and the linux capture builds come from HEAD."
    echo "  ! those two targets will NOT contain uncommitted changes."
    echo "  ! commit first if they should. Continuing in 5s."
    echo
    sleep 5
  fi
  work=$(mktemp -d)
  git archive HEAD | tar -x -C "$work"
  cat > "$work/build.sh" <<EOF
set -eu
apt-get update -qq
apt-get install -y -qq wget build-essential flex bison >/dev/null
cd /tmp
wget -q https://www.tcpdump.org/release/libpcap-${LIBPCAP}.tar.gz
tar xzf libpcap-${LIBPCAP}.tar.gz && cd libpcap-${LIBPCAP}
./configure --disable-dbus --disable-bluetooth --disable-usb \\
            --disable-rdma --disable-shared --without-libnl >/dev/null
make -j"\$(nproc)" >/dev/null && make install >/dev/null
cd /src
# **GOTOOLCHAIN=auto, because the golang image sets it to local.**
#
# This heredoc is unquoted, so the outer shell expands it: no backticks in
# here, or the comment explaining the fix runs as a command and takes the
# build down with it. With local, the toolchain line in go.mod is ignored
# and the build silently
# uses whatever Go the image happens to carry. That is how these two binaries,
# one of which is the Raspberry Pi build, came to be compiled against a standard
# library with five reachable advisories in it while the other ten were clean:
# the floor that exists to prevent exactly that does not reach inside here
# unless it is switched back on.
export GOTOOLCHAIN=auto
CGO_ENABLED=1 CGO_LDFLAGS=/usr/local/lib/libpcap.a go build -tags patrol \\
  -trimpath -ldflags "$LD" -o /out/\$TARGET ./cmd/lan-sheriff
EOF
  # A stale cached image is a stale toolchain, and the whole point of the floor
  # is that nobody has to remember. Quiet, and not fatal: an offline build with
  # a recent image is still worth having, and the version assertion below is
  # what actually decides whether the result may ship.
  docker pull -q golang:1.25-bookworm >/dev/null 2>&1 || true

  for pair in amd64:X86-64 arm64:AArch64; do
    arch=${pair%%:*}; elf=${pair##*:}
    note "linux/$arch capture, in docker$([ "$arch" = arm64 ] && echo ', emulated, slow')"
    if docker run --rm --platform "linux/$arch" \
        -e TARGET="lan-sheriff_linux_${arch}" \
        -v "$work:/src" -v "$OUT:/out" -v "$work/build.sh:/build.sh:ro" \
        golang:1.25-bookworm bash /build.sh >/dev/null 2>&1 \
      && docker run --rm --platform "linux/$arch" -v "$OUT:/out" -v "$ROOT/scripts:/s:ro" \
        golang:1.25-bookworm bash /s/verify-linux-binary.sh "/out/lan-sheriff_linux_${arch}" "$elf" >/dev/null 2>&1
    then
      ok "linux/$arch" capture
    else
      bad "linux/$arch" capture "docker build or verification"
    fi
  done
  rm -rf "$work"
else
  note "docker unavailable, skipping the linux capture builds"
fi

echo
printf '  %-16s %-10s %s\n' TARGET BUILD RESULT
sort "$results" | while IFS='|' read -r t b r; do printf '  %-16s %-10s %s\n' "$t" "$b" "$r"; done
echo
n=$(grep -c 'ok$' "$results" || true)
f=$(grep -c 'FAIL$' "$results" || true)
note "$n built, $f failed, in $OUT"
[ "$f" -eq 0 ]
