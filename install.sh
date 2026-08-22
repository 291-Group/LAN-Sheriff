#!/bin/sh
# LAN Sheriff installer.
#
#   curl -fsSL https://raw.githubusercontent.com/291-Group/LAN-Sheriff/main/install.sh | sh
#
# Or, better, read it first and then run it. This is a tool for watching what
# your network sends out; piping an unread script from the internet into a shell
# to install it is a slightly odd way to begin, and the whole file is ninety
# lines precisely so that reading it is realistic.
#
# What it does, in order:
#
#   1. works out your platform and refuses politely if it is not one we build
#   2. asks GitHub for the latest release tag
#   3. downloads the archive and the published checksums
#   4. **verifies the checksum and stops if it does not match**
#   5. unpacks it and puts the binary somewhere on your PATH
#
# Step 4 is not optional and there is no flag to skip it. A monitoring tool that
# would install an unverified binary has no business telling you which of your
# devices to trust.
#
# POSIX sh on purpose: this has to run on a Pi with dash as /bin/sh.

set -eu

REPO="291-Group/LAN-Sheriff"
BIN="lan-sheriff"

say()  { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "this needs $1, which is not installed"
}

need curl
need tar

# ---------------------------------------------------------------- platform ---

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)  os=linux  ;;
    Darwin) os=darwin ;;
    *)
        fail "no build for $os. Windows users: download the zip from
       https://github.com/$REPO/releases and run the exe."
        ;;
esac

case "$arch" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv7)  arch=arm   ;;
    *) fail "no build for $arch" ;;
esac

# The Linux capture build links glibc, deliberately: a fully static glibc binary
# breaks name resolution, and this program resolves names. On musl it would not
# start at all, so say so here rather than let it fail confusingly later.
if [ "$os" = linux ] && [ -f /etc/os-release ]; then
    if ! ldd /bin/sh 2>/dev/null | grep -qi 'gnu\|glibc'; then
        if grep -qi 'alpine\|openwrt' /etc/os-release 2>/dev/null; then
            fail "this system uses musl, and the release links glibc.
       Build from source instead: https://github.com/$REPO#build-from-source"
        fi
    fi
fi

# 32-bit ARM has no capture build, only the portable one. Say which you are
# getting rather than letting somebody discover it from the dashboard.
suffix=""
if [ "$arch" = arm ]; then
    suffix="_portable"
    say "note: 32-bit ARM gets the portable build, which has no packet capture."
    say "      Deputy Mode works fully. 64-bit Pi OS gets the full build."
fi

# ----------------------------------------------------------------- version ---

version=${LAN_SHERIFF_VERSION:-}
if [ -z "$version" ]; then
    # 2>/dev/null because curl prints its own transfer errors even with -s,
    # and the message below is the useful one.
    version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
              sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
fi
[ -n "$version" ] || fail "could not determine the latest release"
num=${version#v}

archive="${BIN}_${num}_${os}_${arch}${suffix}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

say "LAN Sheriff $version for $os/$arch"

# ---------------------------------------------------------------- download ---

tmp=$(mktemp -d)
# Clean up whatever happens, including on a failed checksum.
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive"
curl -fsSL -o "$tmp/$archive" "$base/$archive" ||
    fail "could not download $archive
       Check https://github.com/$REPO/releases for what this release contains."

say "downloading checksums"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" ||
    fail "could not download checksums.txt, so the archive cannot be verified.
       Refusing to install something unverified."

# ------------------------------------------------------------------ verify ---
#
# Fails closed in every direction: no checksum tool, no line for this archive,
# or a mismatch all stop the install. The only path that continues is the one
# where the file is exactly what the release says it is.

want=$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}' | head -1)
[ -n "$want" ] || fail "checksums.txt has no entry for $archive"

if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
else
    fail "no sha256sum or shasum available, so the download cannot be verified"
fi

if [ "$want" != "$got" ]; then
    fail "checksum mismatch for $archive
       expected $want
       got      $got
       Not installing. This means the download was corrupted or tampered with."
fi
say "checksum ok"

# ----------------------------------------------------------------- install ---

tar -xzf "$tmp/$archive" -C "$tmp" || fail "could not unpack $archive"
[ -f "$tmp/$BIN" ] || fail "$archive did not contain $BIN"

# Prefer a directory already on PATH that we can write to, so the common case
# needs no privilege at all. Only reach for sudo if there is no such place.
dest=""
for d in "$HOME/.local/bin" /usr/local/bin; do
    if [ -d "$d" ] && [ -w "$d" ]; then dest=$d; break; fi
done

if [ -z "$dest" ]; then
    if [ -w /usr/local ]; then
        mkdir -p /usr/local/bin && dest=/usr/local/bin
    else
        dest=/usr/local/bin
        say "installing to $dest needs sudo"
        sudo mkdir -p "$dest"
        sudo install -m 0755 "$tmp/$BIN" "$dest/$BIN" || fail "install failed"
        say ""
        say "installed $dest/$BIN"
        say "run it:  $BIN"
        exit 0
    fi
fi

install -m 0755 "$tmp/$BIN" "$dest/$BIN" || fail "install failed"

say ""
say "installed $dest/$BIN"
case ":$PATH:" in
    *":$dest:"*) say "run it:  $BIN" ;;
    *)           say "note: $dest is not on your PATH. Run it with $dest/$BIN" ;;
esac
say ""
say "Deputy Mode needs no privileges and works immediately."
say "Patrol Mode needs permission to capture; the dashboard tells you the"
say "exact command for your system if it is unavailable."
