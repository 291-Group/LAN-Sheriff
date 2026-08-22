#!/usr/bin/env bash
# Tests the rule that decides whether a tag may publish to public channels.
#
# The rule lives in release.yml as three lines of shell, which is exactly the
# kind of thing that gets edited without anyone re-reading what it protects. A
# mistake here does not fail a build, it pushes a development version to a
# Homebrew tap where somebody's `brew upgrade` finds it, and that cannot be
# withdrawn. So the rule is asserted rather than trusted.
#
#   scripts/release/gate_test.sh

set -euo pipefail

# The rule, copied verbatim from the workflow. Kept in one line so the two are
# trivially comparable by eye.
gate() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo true || echo false; }

fail=0
check() {
  got=$(gate "$1")
  if [ "$got" != "$2" ]; then
    echo "  FAIL  $1 -> $got, expected $2"
    fail=1
  else
    echo "  ok    $1 -> $got"
  fi
}

echo "must NOT reach the public:"
check "v0.0.1-rehearsal.1"   false
check "v0.0.1-rehearsal.8"   false
check "v1.0.0-rc1"           false
check "v1.0.0-rc.1"          false
check "v1.0.0-beta"          false
check "v2.0.0-alpha.3"       false
check "v1.0.0-SNAPSHOT"      false

# The spellings a hyphen rule misses. v0.9.8b is not hypothetical: it was
# proposed as the version for the pre-launch test builds, and under the old rule
# it would have been published to a public tap.
check "v0.9.8b"             false
check "v1.0.0b"             false
check "v1.0.0rc1"           false
check "v1.0"                false
check "v1.0.0.1"            false
check "1.0.0"               false
check "v1.0.0 "             false
check "latest"              false
check "vX.Y.Z"              false

echo
echo "may reach the public:"
check "v1.0.0"               true
check "v1.2.3"               true
check "v10.20.30"            true

echo
if [ "$fail" -ne 0 ]; then
  echo "the publish gate is wrong; fix it before any tag is pushed" >&2
  exit 1
fi
echo "the gate holds: every prerelease spelling is refused"
