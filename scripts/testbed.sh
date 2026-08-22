#!/usr/bin/env bash
# Stands up one instance per distinguishable state, side by side, so they can be
# compared rather than remembered.
#
# # Why this exists
#
# Almost none of what makes two LAN Sheriff installs look different is the
# processor. It is which build was compiled, whether capture is permitted, where
# it is bound, whether a password is demanded, whether a record is being read
# rather than written, and whether there is any data yet. Testing "all versions"
# by collecting binaries for six architectures tests the least interesting axis
# of the lot, and every one of these states can be reached on one machine in
# under a minute.
#
# Each instance gets its own data directory, so nothing here can disturb a real
# install, and every one binds to loopback. Nothing is exposed to the network
# unless you ask for it by name, which is the one subcommand that prints what it
# is about to do first.
#
#   scripts/testbed.sh start     bring up the loopback states
#   scripts/testbed.sh status    what is running, and on which port
#   scripts/testbed.sh network   the network-bound state, opt in, see below
#   scripts/testbed.sh stop      shut everything down, keep the data
#   scripts/testbed.sh clean     shut down and delete the test data

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${TESTBED_DIR:-${TMPDIR:-/tmp}/lan-sheriff-testbed}"
BIN="$BASE/lan-sheriff"

say() { printf '  %s\n' "$*"; }

# Port, directory suffix, description, extra flags. The port is the identity: it
# is what you type into a browser, so it is what everything here is keyed on.
states() {
  cat <<'SPEC'
2931|populated|Deputy Mode, ordinary use. The baseline everything else is read against.|
2932|empty|A fresh install with nothing in it. Every empty state lives here.|--offline
2933|record|Reading a populated record. Nothing is captured; the screen must agree.|--offline
2934|locked|Loopback, but a password is demanded anyway.|--require-password
2935|dispatch|Peer sharing switched on and nothing paired yet.|--dispatch
SPEC
}

build() {
  mkdir -p "$BASE"
  # Stamped as though it were downloaded. An unstamped build tells the reader to
  # run `make patrol`, which is developer advice, and testing the developer's
  # copy of the interface is not testing what ships.
  local commit
  commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo testbed)
  local cli=github.com/291-Group/LAN-Sheriff/internal/cli
  say "building, stamped $commit so it behaves as a release binary"
  (cd "$ROOT" && go build \
    -ldflags "-X $cli.Version=0.0.0-testbed -X $cli.Commit=$commit" \
    -o "$BIN" ./cmd/lan-sheriff)
}

# "Did it bind", not "will it show me data". An instance started with
# --require-password answers 401 on the API until somebody logs in, and treating
# that as a failure reported the one state here that behaves correctly as broken.
up() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:$1/" 2>/dev/null)
  [ -n "$code" ] && [ "$code" != 000 ]
}

wait_up() {
  local n
  for n in $(seq 1 60); do
    up "$1" && return 0
    sleep 0.25
  done
  return 1
}

start() {
  build
  while IFS='|' read -r port dir _desc flags; do
    [ -n "$port" ] || continue
    local d="$BASE/$dir"
    mkdir -p "$d"
    if up "$port"; then
      say "$port already up ($dir)"
      continue
    fi
    # --open=false everywhere: five browser tabs opening at once is not a test
    # setup, it is a prank.
    # shellcheck disable=SC2086
    "$BIN" --listen "127.0.0.1:$port" --data-dir "$d" --open=false $flags \
      >"$d/log" 2>&1 &
    echo $! > "$d/pid"
    if wait_up "$port"; then say "$port up   $dir"; else say "$port FAILED, see $d/log"; fi
  done < <(states)

  # Both --offline instances above start against an empty directory, which is
  # right for `empty` and useless for `record`: a record with nothing in it
  # exercises the empty states a second time rather than the reading-a-record
  # ones. So `record` is seeded from whatever `populated` has collected.
  #
  # An earlier version instead let `empty` observe for two seconds and then
  # restarted it offline. Two seconds was enough to collect a hundred flows, so
  # the instance whose entire purpose was to be empty was the only one with data
  # in it, and the one meant to hold a record had none.
  seed_record

  echo
  status
}

# Copy the populated database over to the record instance and restart it, so
# --offline has something to serve. The write-ahead log is copied with the
# database because without it the copy is missing whatever has not been
# checkpointed, which on a young instance is most of it.
seed_record() {
  local src="$BASE/populated" dst="$BASE/record" n
  for n in $(seq 1 40); do
    n=$(curl -s --max-time 2 "http://127.0.0.1:2931/api/summary" 2>/dev/null \
        | sed -n 's/.*"flows":\([0-9]*\).*/\1/p')
    [ -n "${n:-}" ] && [ "$n" -gt 20 ] 2>/dev/null && break
    sleep 1
  done

  [ -f "$src/sheriff.db" ] || { say "populated has no database yet, record left empty"; return; }
  [ -f "$dst/pid" ] && kill "$(cat "$dst/pid")" 2>/dev/null || true
  sleep 1
  cp "$src"/sheriff.db* "$dst"/ 2>/dev/null || cp "$src/sheriff.db" "$dst/"
  "$BIN" --listen 127.0.0.1:2933 --data-dir "$dst" --open=false --offline \
    >>"$dst/log" 2>&1 &
  echo $! > "$dst/pid"
  wait_up 2933 && say "2933 seeded from populated, $(curl -s --max-time 2 \
    http://127.0.0.1:2933/api/summary | sed -n 's/.*"flows":\([0-9]*\).*/\1/p') flows to read"
}

status() {
  printf '  %-6s %-10s %s\n' PORT STATE URL
  while IFS='|' read -r port dir _desc flags; do
    [ -n "$port" ] || continue
    if up "$port"; then
      printf '  %-6s %-10s http://127.0.0.1:%s\n' "$port" "$dir" "$port"
    else
      printf '  %-6s %-10s (down)\n' "$port" "$dir"
    fi
  done < <(states)
  echo
}

# The one state that cannot be reached on loopback, because the password is
# demanded precisely when the bind address is not loopback. It is opt-in and it
# says what it will do, because putting a service on the network is a decision
# rather than a side effect of running a script.
network() {
  local addr
  addr=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
  [ -n "$addr" ] || { echo "could not determine a LAN address" >&2; exit 1; }
  cat <<EOF

  This starts an instance on ${addr}:2936, reachable by anything on your
  network. That is the point: binding off loopback is what makes LAN Sheriff
  demand a password, and the first visitor is the one who sets it.

  So visit it yourself, immediately, and set one. Until you do, the install is
  unclaimed and anyone on the network who reaches it first becomes its owner.

  Ctrl+C now if you would rather not.

EOF
  read -r -p "  Type yes to start it: " ans
  [ "$ans" = yes ] || { say "not started"; exit 0; }
  build
  mkdir -p "$BASE/network"
  "$BIN" --listen "$addr:2936" --data-dir "$BASE/network" --open=false \
    >"$BASE/network/log" 2>&1 &
  echo $! > "$BASE/network/pid"
  sleep 2
  say "up at http://${addr}:2936  (set the password now)"
}

stop() {
  local n=0 p
  for p in "$BASE"/*/pid; do
    [ -f "$p" ] || continue
    if kill "$(cat "$p")" 2>/dev/null; then n=$((n + 1)); fi
    rm -f "$p"
  done
  say "stopped $n"
}

clean() { stop; rm -rf "$BASE"; say "removed $BASE"; }

case "${1:-start}" in
  start)   start ;;
  status)  status ;;
  network) network ;;
  stop)    stop ;;
  clean)   clean ;;
  *) echo "usage: $0 {start|status|network|stop|clean}" >&2; exit 2 ;;
esac
