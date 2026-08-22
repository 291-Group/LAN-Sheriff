#!/bin/sh
# Removes LAN Sheriff.
#
#   curl -fsSL https://raw.githubusercontent.com/291-Group/LAN-Sheriff/main/uninstall.sh | sh
#
# The binary goes without asking. **Your data does not**, unless you say so:
# the database is a record of your own network, and a script that quietly
# deleted it because you wanted the program gone would be making a decision
# that is not its to make. It tells you where it is and what removes it.

set -eu

BIN="lan-sheriff"
say() { printf '%s\n' "$*"; }

removed=0
for d in "$HOME/.local/bin" /usr/local/bin /usr/bin /opt/homebrew/bin; do
    [ -f "$d/$BIN" ] || continue
    if [ -w "$d" ]; then
        rm -f "$d/$BIN" && say "removed $d/$BIN" && removed=1
    else
        say "removing $d/$BIN needs sudo"
        sudo rm -f "$d/$BIN" && say "removed $d/$BIN" && removed=1
    fi
done

[ "$removed" = 1 ] || say "no $BIN binary found on the usual paths"

# Where the data lives, per platform. Printed, never deleted.
case "$(uname -s)" in
    Darwin) data="$HOME/Library/Application Support/lan-sheriff" ;;
    *)      data="${XDG_DATA_HOME:-$HOME/.local/share}/lan-sheriff" ;;
esac

say ""
if [ -d "$data" ]; then
    size=$(du -sh "$data" 2>/dev/null | awk '{print $1}')
    say "Your data is still here, ${size:-unknown} in:"
    say "  $data"
    say ""
    say "It is a record of your own network and nothing else has a copy."
    say "Delete it yourself when you are ready:"
    say "  rm -rf \"$data\""
else
    say "No data directory found, so there is nothing else to remove."
fi
