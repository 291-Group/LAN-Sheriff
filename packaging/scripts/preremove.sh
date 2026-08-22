#!/bin/sh
# Stops the service before the files go. The data directory is deliberately
# left alone: it is a record of somebody's own network and removing a package
# is not a request to destroy it. postremove says where it is.
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop lan-sheriff >/dev/null 2>&1 || true
    systemctl disable lan-sheriff >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-service lan-sheriff stop >/dev/null 2>&1 || true
fi
