#!/bin/sh
# Download the public IRR dumps for the opt-in real-data regression:
#
#   scripts/fetch-irr-dumps.sh [registry ...]      # default: all of them
#   RPSL_REALDATA=$PWD/.data go test -run TestRealData ./examples/bulk-ripe/bulk
#
# Registries: ripe apnic (every split class), arin afrinic lacnic (one file
# each), radb (one file, over FTP). Each goes to .data/<registry>/ (DIR
# overrides .data, which is gitignored); about 470 MB compressed in all. A file
# is only re-downloaded when the server's copy is newer. RADB's FTP server
# often times out, so every download is tried three times; a registry that
# still fails is reported and the others are fetched anyway.
set -u
cd "$(dirname "$0")/.."
base=${DIR:-.data}
registries=${*:-ripe apnic arin afrinic lacnic radb}
failed=""

ripe_classes="as-block as-set aut-num domain filter-set inet-rtr inet6num inetnum irt key-cert mntner
	organisation peering-set person poem poetic-form role route-set route route6 rtr-set"
apnic_classes="as-block as-set aut-num domain filter-set inet-rtr inet6num inetnum irt key-cert limerick
	mntner organisation peering-set role route-set route route6 rtr-set"

# fetch downloads the URL $2 to the file $1, three tries, only when newer.
fetch() {
	for try in 1 2 3; do
		if [ -f "$1" ]; then
			curl -fsSL --connect-timeout 60 -z "$1" -o "$1.part" "$2" && { [ ! -s "$1.part" ] || mv "$1.part" "$1"; } && rm -f "$1.part" && return 0
		else
			curl -fsSL --connect-timeout 60 -o "$1.part" "$2" && mv "$1.part" "$1" && return 0
		fi
		rm -f "$1.part"
		[ "$try" = 3 ] || { echo "  retrying $2" >&2; sleep 10; }
	done
	return 1
}

for r in $registries; do
	dir=$base/$r
	mkdir -p "$dir"
	echo "== $r"
	case $r in
	ripe)
		urls=""
		for c in $ripe_classes; do urls="$urls ripe.db.$c.gz=https://ftp.ripe.net/ripe/dbase/split/ripe.db.$c.gz"; done ;;
	apnic)
		urls=""
		for c in $apnic_classes; do urls="$urls apnic.db.$c.gz=https://ftp.apnic.net/apnic/whois/apnic.db.$c.gz"; done ;;
	arin) urls="arin.db.gz=https://ftp.arin.net/pub/rr/arin.db.gz" ;;
	afrinic) urls="afrinic.db.gz=https://ftp.afrinic.net/pub/dbase/afrinic.db.gz" ;;
	lacnic) urls="lacnic.db.gz=https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz" ;;
	radb) urls="radb.db.gz=ftp://ftp.radb.net/radb/dbase/radb.db.gz" ;;
	*)
		echo "unknown registry $r (known: ripe apnic arin afrinic lacnic radb)" >&2
		failed="$failed $r"
		continue ;;
	esac
	for u in $urls; do
		file=${u%%=*}
		echo "  $file"
		fetch "$dir/$file" "${u#*=}" || { echo "  FAILED: $file" >&2; failed="$failed $r/$file"; }
	done
done

if [ -n "$failed" ]; then
	echo "not fetched:$failed" >&2
	exit 1
fi
