#!/bin/sh
# Download RIPE Database split dumps for the opt-in real-data regression:
#
#   scripts/fetch-ripe-dumps.sh [dir] [class ...]
#   RPSL_REALDATA=$PWD/.data/ripe go test -run TestRealData ./examples/bulk-ripe/bulk
#
# Defaults to .data/ripe (gitignored), the classes the expansion check needs,
# and the small filter-set and peering-set dumps, which exercise the policy
# parser's filter and peering grammar on real data.
# Files are only re-downloaded when the server copy is newer.
set -eu
dir=${1:-.data/ripe}
[ $# -gt 0 ] && shift
classes=${*:-as-set route-set route route6 aut-num filter-set peering-set}
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
