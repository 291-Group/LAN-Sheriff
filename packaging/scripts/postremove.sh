#!/bin/sh
set -e
[ -d /run/systemd/system ] && { systemctl daemon-reload >/dev/null 2>&1 || true; }
if [ -d /var/lib/lan-sheriff ]; then
    echo "The database is still at /var/lib/lan-sheriff"
    echo "It is a record of your own network and nothing else has a copy."
    echo "Remove it yourself when you are ready:  sudo rm -rf /var/lib/lan-sheriff"
fi
