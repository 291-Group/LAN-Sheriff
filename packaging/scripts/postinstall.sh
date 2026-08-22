#!/bin/sh
# Runs after the package installs. Creates the service account and its data
# directory, and grants capture capability where the init system cannot.
set -e

USER=lan-sheriff
DATA=/var/lib/lan-sheriff

if ! id "$USER" >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --home-dir "$DATA" "$USER" 2>/dev/null || true
    elif command -v adduser >/dev/null 2>&1; then
        # busybox adduser, on Alpine
        adduser -S -H -D -h "$DATA" -s /sbin/nologin "$USER" 2>/dev/null || true
    fi
fi

mkdir -p "$DATA"
chown "$USER":"$USER" "$DATA" 2>/dev/null || chown "$USER" "$DATA" 2>/dev/null || true
chmod 0700 "$DATA"

# systemd grants capture through AmbientCapabilities in the unit, so the binary
# needs no capabilities of its own. OpenRC has no equivalent, so there the file
# has to carry them. Detecting which init is in charge decides it: setting file
# capabilities unconditionally would be harmless on systemd but is worth not
# doing, because a binary carrying capabilities behaves differently when it is
# copied somewhere those capabilities cannot be granted.
if [ ! -d /run/systemd/system ] && command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/lan-sheriff || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "LAN Sheriff installed. Start it with:"
    echo "  sudo systemctl enable --now lan-sheriff"
    echo "Then open http://localhost:2911"
else
    echo "LAN Sheriff installed. Start it with:"
    echo "  sudo rc-service lan-sheriff start"
fi
echo
echo "It listens on localhost only. To reach it from another machine, edit the"
echo "service file; the dashboard will then require a password before it shows"
echo "anything."
