#!/usr/bin/env bash
# Turns the per-platform binaries into the archives and checksums a release
# publishes.
#
# # Why this exists rather than `goreleaser release`
#
# Capture builds need a real toolchain for their target, so each operating
# system is built on a runner of that operating system. Assembling those into
# one release then needs something that can package binaries it did not build,
# and GoReleaser's open-source edition cannot: `release` has no `--id` filter,
# `--skip=build` is not among its skips, and `builder: prebuilt` is a Pro
# feature. Running `goreleaser release` on the assembling runner therefore
# rebuilds every target from scratch, on a machine that cannot build most of
# them, and `--clean` deletes the downloaded artifacts before it starts. The
# fifth release rehearsal failed exactly that way.
#
# So the archiving, the checksums and the packages are done here. It is less
# clever and it is entirely under our control, which for the one process that
# has to work on 23 August is the better trade.
#
# # The naming is a contract
#
# install.sh downloads `lan-sheriff_<version>_<os>_<arch>[_portable].tar.gz` and
# verifies it against `checksums.txt`. Those names are not cosmetic: change them
# here and every existing install command breaks silently.
#
#   scripts/release/assemble.sh <version-without-v> <dist-dir> <output-dir>

set -euo pipefail

VERSION="${1:?version, without the leading v}"
DIST="${2:?directory holding the built binaries}"
OUT="${3:?directory to write archives into}"

BIN=lan-sheriff
mkdir -p "$OUT"

# Files that ride along inside each archive, matching what the archives config
# used to declare. Capture builds carry the security policy as well, because
# those are the ones that ask for privilege.
COMMON="README.md LICENSE"
CAPTURE_EXTRA="SECURITY.md"

say() { printf '  %s\n' "$*"; }

# GoReleaser writes each target to dist/<id>_<goos>_<goarch>[_variant]/<binary>.
# The id tells us whether this is a capture build or the portable one, and the
# directory name carries the platform, so nothing has to be passed in.
found=0
while IFS= read -r bin; do
  dir=$(basename "$(dirname "$bin")")
  id=${dir%%_*}
  rest=${dir#*_}
  goos=${rest%%_*}
  goarch=${rest#*_}
  # Strip the variant suffix goreleaser appends (amd64_v1, arm64_v8.0, arm_7).
  goarch=${goarch%%_*}

  suffix=""
  extra=""
  case "$id" in
    portable) suffix="_portable" ;;
    *) extra="$CAPTURE_EXTRA" ;;
  esac

  name="${BIN}_${VERSION}_${goos}_${goarch}${suffix}"
  stage="$OUT/.stage/$name"
  rm -rf "$stage"
  mkdir -p "$stage"

  # The binary keeps its plain name inside the archive: install.sh copies
  # whatever it finds to lan-sheriff, and a Windows build needs its .exe.
  cp "$bin" "$stage/$(basename "$bin")"
  for f in $COMMON $extra; do
    [ -f "$f" ] && cp "$f" "$stage/"
  done

  tar -czf "$OUT/${name}.tar.gz" -C "$stage" .
  say "packed ${name}.tar.gz"
  found=$((found + 1))
done < <(find "$DIST" -type f \( -name "$BIN" -o -name "$BIN.exe" \) | sort)

if [ "$found" -eq 0 ]; then
  echo "::error::no binaries found under $DIST; nothing to release" >&2
  exit 1
fi
rm -rf "$OUT/.stage"

# The Linux packages, from the same binaries the archives were made from.
#
# nfpm rather than goreleaser for the reason at the top of this file, and once
# per architecture because a package declares the architecture it is for. Only
# the capture builds are packaged: somebody installing a .deb expects the thing
# the systemd unit is written for, which is the build that can capture.
if command -v nfpm >/dev/null 2>&1; then
  for pair in "amd64 patrol-linux_linux_amd64_v1" "arm64 patrol-linux_linux_arm64_v8.0"; do
    set -- $pair
    arch=$1
    bindir=$2
    bin="$DIST/$bindir/$BIN"
    [ -f "$bin" ] || { say "no $arch capture binary, skipping its packages"; continue; }

    # The config is rendered rather than handed to nfpm with the variables
    # still in it. nfpm expands environment variables in some fields and not in
    # contents[].src, which fails as "Glob failed: ${PKG_BINARY}: no matching
    # files" and would be easy to read as a missing binary rather than an
    # unexpanded variable.
    rendered="$OUT/.nfpm-$arch.yaml"
    sed -e "s|\${PKG_ARCH}|$arch|g" \
        -e "s|\${PKG_VERSION}|$VERSION|g" \
        -e "s|\${PKG_BINARY}|$bin|g" \
        packaging/nfpm.yaml > "$rendered"
    for fmt in deb rpm apk; do
      nfpm package --config "$rendered" --packager "$fmt" --target "$OUT" >/dev/null
    done
    rm -f "$rendered"
    say "packaged $arch as deb, rpm and apk"
  done
else
  say "nfpm not installed, skipping the Linux packages"
fi

# One checksums file covering everything, which is what gets signed. Written
# with bare filenames rather than paths, because install.sh matches on the
# archive name at the end of the line.
(
  cd "$OUT"
  : > checksums.txt
  for f in *.tar.gz *.deb *.rpm *.apk; do
    [ -e "$f" ] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$f" >> checksums.txt
    else
      shasum -a 256 "$f" >> checksums.txt
    fi
  done
)
say "checksums.txt covers $(wc -l < "$OUT/checksums.txt" | tr -d ' ') files"

# A release that quietly contained only half its platforms would be worse than
# one that failed, so the expected set is asserted rather than hoped for.
#
# Every archive a release is expected to carry, not a sample of them. The list
# used to name seven while a release produced twelve, so the five it did not
# mention could have gone missing without failing anything: FreeBSD, 32-bit ARM
# and Windows on ARM are exactly the targets nobody here can test by hand, and
# the README now promises each of them by name.
missing=0
for expect in \
  "${BIN}_${VERSION}_linux_amd64.tar.gz" \
  "${BIN}_${VERSION}_linux_arm64.tar.gz" \
  "${BIN}_${VERSION}_darwin_amd64.tar.gz" \
  "${BIN}_${VERSION}_darwin_arm64.tar.gz" \
  "${BIN}_${VERSION}_windows_amd64.tar.gz" \
  "${BIN}_${VERSION}_linux_amd64_portable.tar.gz" \
  "${BIN}_${VERSION}_linux_arm64_portable.tar.gz" \
  "${BIN}_${VERSION}_linux_arm_portable.tar.gz" \
  "${BIN}_${VERSION}_windows_amd64_portable.tar.gz" \
  "${BIN}_${VERSION}_windows_arm64_portable.tar.gz" \
  "${BIN}_${VERSION}_freebsd_amd64_portable.tar.gz" \
  "${BIN}_${VERSION}_freebsd_arm64_portable.tar.gz"
do
  if [ ! -f "$OUT/$expect" ]; then
    echo "::error::missing expected artifact $expect" >&2
    missing=$((missing + 1))
  fi
done
[ "$missing" -eq 0 ] || exit 1
say "every expected platform is present"
