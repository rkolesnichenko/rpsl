#!/usr/bin/env bash
# run.sh up plain|rpki — start IRRd 4.5.3 on the fixture; run.sh down — stop it.
# Used by resolve/internal/irrdoracle's TestRecord (RPSL_IRRD_DOCKER=1).
set -euo pipefail
cd "$(dirname "$0")"
P=(docker compose -p rpsl-irrdoracle -f compose.yaml)
case "${1:-}" in
up)
	mode=${2:?usage: run.sh up plain|rpki}
	export IRRD_CONFIG=irrd.yaml
	[ "$mode" = rpki ] && export IRRD_CONFIG=irrd-rpki.yaml
	"${P[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	"${P[@]}" build -q irrd
	"${P[@]}" up -d --wait postgres redis
	"${P[@]}" run --rm irrd irrd_database_upgrade --config /etc/irrd/irrd.yaml
	if [ "$mode" = plain ]; then
		"${P[@]}" run --rm irrd irrd_load_database --config /etc/irrd/irrd.yaml --source RIPE /data/ripe.db
	fi
	"${P[@]}" run --rm irrd irrd_load_database --config /etc/irrd/irrd.yaml --source RADB /data/radb.db
	"${P[@]}" up -d irrd
	for i in $(seq 1 120); do
		if printf '!v\n' | nc -w 2 127.0.0.1 "${IRRD_PORT:-18043}" 2>/dev/null | grep -q version; then
			# RPKI mode imports the ROAs and RIPE's file a moment after start.
			[ "$mode" = rpki ] && sleep 5
			echo SUCCESS
			exit 0
		fi
		sleep 1
	done
	echo TIMEOUT
	exit 1
	;;
down)
	"${P[@]}" down -v --remove-orphans
	;;
*)
	echo "usage: run.sh up plain|rpki | down" >&2
	exit 2
	;;
esac
