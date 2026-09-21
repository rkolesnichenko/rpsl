#!/bin/sh
# Download RIPE Database split dumps for the opt-in real-data regression:
#
#   scripts/fetch-ripe-dumps.sh [dir] [class ...]
#   RPSL_REALDATA=.data/ripe go test -run TestRealData ./examples/bulk-ripe/bulk
#
# Defaults to .data/ripe (gitignored) and the classes the expansion check needs.
# Files are only re-downloaded when the server copy is newer.
set -eu
dir=${1:-.data/ripe}
[ $# -gt 0 ] && shift
classes=${*:-as-set route-set route route6 aut-num}
base=https://ftp.ripe.net/ripe/dbase/split
mkdir -p "$dir"
for c in $classes; do
	f="ripe.db.$c.gz"
	echo "fetching $f"
	if [ -f "$dir/$f" ]; then
		curl -fsSL -z "$dir/$f" -o "$dir/$f" "$base/$f"
	else
		curl -fsSL -o "$dir/$f" "$base/$f"
	fi
done
