#!/usr/bin/env bash
# Copies the staged test builds onto the microSD card, and refuses to copy
# anything built with a Go toolchain that has known advisories.
#
# The check is the reason this exists rather than being a cp. The beta builds
# handed out on 5 August were compiled with go1.25.5, which carries twelve
# reachable standard-library advisories, two of them in crypto/tls, which is
# what The Dispatch uses for every peer connection. Nothing caught it, because
# the binaries were correct in every other way: right architecture, right
# capture support, right stamp. A security tool handing testers known
# vulnerabilities is a credibility problem before it is a technical one.
#
# go.mod now carries a `toolchain` floor so this cannot recur by accident, and
# this asserts the result rather than trusting it.
#
#   scripts/build-all.sh dist/build      build them
#   scripts/refresh-card.sh              stage and copy to the card
#
# The card must be mounted. It is /Volumes/BOOT on macOS; pass a different path
# as the first argument if yours differs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARD="${1:-/Volumes/BOOT}"
STAGE="$ROOT/dist/card"
WANT_GO=go1.25.14

say() { printf '  %s\n' "$*"; }

# ── Staging, from the flat build output onto the names the card uses ─────────
#
# build-all.sh writes lan-sheriff_linux_arm64; the card says raspberry-pi/
# lan-sheriff-CAPTURE, because the person holding the card knows what machine
# they have and not what GOARCH it is. Something has to map one to the other,
# and until now that something was a person doing it by hand after every build.
#
# That is how the card goes stale, and it has: the readme said build 154 while
# the binaries beside it were older still, because restaging is the step with
# nothing to fail when it is skipped. The mapping lives here now, so the copy
# and the names it copies under cannot drift apart.
#
# Pass a build directory as the second argument to restage. Without one this
# copies whatever is already staged, which is the old behaviour.
BUILD_DIR="${2:-}"
if [ -n "$BUILD_DIR" ]; then
  [ -d "$BUILD_DIR" ] || { echo "no build directory at $BUILD_DIR" >&2; exit 1; }
  BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
  rm -rf "$STAGE"
  while IFS='|' read -r src dst; do
    [ -n "$src" ] || continue
    if [ ! -f "$BUILD_DIR/$src" ]; then
      echo "missing from the build: $src" >&2; exit 1
    fi
    mkdir -p "$STAGE/$(dirname "$dst")"
    cp -f "$BUILD_DIR/$src" "$STAGE/$dst"
  done <<'MAP'
lan-sheriff_darwin_arm64|mac/lan-sheriff-CAPTURE-apple-silicon
lan-sheriff_darwin_amd64|mac/lan-sheriff-CAPTURE-intel
lan-sheriff_linux_arm64|raspberry-pi/lan-sheriff-CAPTURE
lan-sheriff_linux_arm64_portable|raspberry-pi/lan-sheriff-portable
lan-sheriff_linux_arm_portable|raspberry-pi/lan-sheriff-portable-32bit
lan-sheriff_linux_amd64|linux-pc/lan-sheriff-CAPTURE
lan-sheriff_linux_amd64_portable|linux-pc/lan-sheriff-portable
lan-sheriff_windows_amd64.exe|windows/lan-sheriff-CAPTURE.exe
lan-sheriff_windows_amd64_portable.exe|windows/lan-sheriff-portable.exe
lan-sheriff_windows_arm64_portable.exe|windows/lan-sheriff-portable-arm64.exe
lan-sheriff_freebsd_amd64_portable|freebsd/lan-sheriff-portable-amd64
lan-sheriff_freebsd_arm64_portable|freebsd/lan-sheriff-portable-arm64
MAP
  say "staged $(find "$STAGE" -type f | wc -l | tr -d ' ') binaries from $BUILD_DIR"
fi

[ -d "$STAGE" ] || { echo "nothing staged in $STAGE; run scripts/build-all.sh first" >&2; exit 1; }
[ -d "$CARD" ] || { echo "no card mounted at $CARD" >&2; exit 1; }

# The toolchain floor, asserted per binary rather than assumed from go.mod.
# `go version -m` reads it out of the binary itself, which is the only thing
# that actually ships.
bad=0
while IFS= read -r bin; do
  v=$(go version -m "$bin" 2>/dev/null | head -1 | awk '{print $2}')
  if [ -z "$v" ]; then
    say "FAIL $(basename "$bin"): no Go build info, is this a Go binary?"
    bad=1
  elif [ "$v" != "$WANT_GO" ]; then
    # A newer toolchain is fine and expected over time; an older one is not.
    older=$(printf '%s\n%s\n' "$WANT_GO" "$v" | sort -V | head -1)
    if [ "$older" = "$v" ] && [ "$v" != "$WANT_GO" ]; then
      say "FAIL $(basename "$bin"): built with $v, older than $WANT_GO"
      bad=1
    else
      say "ok   $(basename "$bin"): $v"
    fi
  else
    say "ok   $(basename "$bin"): $v"
  fi
done < <(find "$STAGE" -type f)

if [ "$bad" -ne 0 ]; then
  echo
  echo "refusing to copy: rebuild with scripts/build-all.sh on a patched toolchain" >&2
  exit 1
fi

echo
mkdir -p "$CARD/lan-sheriff"
# The readme is written and maintained on the card itself, so it is deliberately
# left alone here. Only binaries are replaced.
for d in mac raspberry-pi windows linux-pc freebsd; do
  [ -d "$STAGE/$d" ] || continue
  mkdir -p "$CARD/lan-sheriff/$d"
  cp -f "$STAGE/$d"/* "$CARD/lan-sheriff/$d/"
  say "copied $d"
done

command -v dot_clean >/dev/null && dot_clean "$CARD/lan-sheriff" 2>/dev/null || true
sync
say "done. $(find "$CARD/lan-sheriff" -type f ! -name '*.txt' ! -path '*/old/*' | wc -l | tr -d ' ') binaries on the card"
say "the readme on the card was not touched"
