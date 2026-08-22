#!/bin/sh
# Vendor the DB-IP Lite country and ASN databases into internal/enrich/data,
# so that a release binary paints the map offline on first run.
#
# The databases are deliberately not committed: they are republished every month
# and git is the wrong place for a binary blob that changes on a schedule. A
# fresh checkout carries only the README in that directory, which is enough for
# the `go:embed` pattern to match and for the build to succeed without them.
#
# A build without them still works. LAN Sheriff falls back to fetching at
# runtime, which costs a few seconds of "locating..." on first launch. This
# script exists so that a *release* build does not make its users wait.
#
# The city database is never vendored: 125 MB written to disk, and the user opts
# into it at runtime or not at all.
#
# Usage:  make datasets
set -eu

dest="internal/enrich/data"
base="https://download.db-ip.com/free"

[ -d "$dest" ] || { echo "run this from the repository root" >&2; exit 1; }

# DB-IP publishes on the first of the month, so the current month's file does
# not exist for part of each month. Walk backwards until one is there, which is
# the same resolution order internal/enrich/datasets.go uses at runtime.
fetch() {
    kind="$1"       # country | asn
    out="$dest/dbip-$kind-lite.mmdb"
    i=0
    while [ "$i" -lt 3 ]; do
        # macOS date and GNU date disagree about arithmetic, so the month is
        # stepped in the shell rather than with a -d/-v flag that only one has.
        #
        # The leading zero is stripped with parameter expansion rather than with
        # `10#$m`. That base prefix is a bashism: it works in macOS /bin/sh and
        # fails in dash, which is /bin/sh on Debian and Ubuntu, so the script
        # would pass locally and break on the release runner. Without stripping
        # it, `08` is read as octal and is an error in every shell.
        y=$(date -u +%Y)
        m=$(date -u +%m)
        m=${m#0}
        n=$((m - i))
        while [ "$n" -le 0 ]; do n=$((n + 12)); y=$((y - 1)); done
        stamp=$(printf '%04d-%02d' "$y" "$n")

        url="$base/dbip-$kind-lite-$stamp.mmdb.gz"
        printf '  %s ... ' "$stamp"
        if curl -fsSL "$url" -o "$out.gz" 2>/dev/null; then
            gunzip -f "$out.gz"
            echo "ok ($(du -h "$out" | cut -f1))"
            return 0
        fi
        echo "not published"
        i=$((i + 1))
    done
    echo "could not fetch a $kind database from the last three months" >&2
    return 1
}

echo "DB-IP Lite, CC BY 4.0, attributed in the dashboard and the README:"
fetch country
fetch asn

echo
echo "vendored into $dest:"
ls -la "$dest"/*.mmdb 2>/dev/null || true
echo
echo "these are gitignored on purpose; they are rebuilt by this script"
