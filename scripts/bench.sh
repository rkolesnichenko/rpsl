#!/bin/sh
# Compares the benchmarks of the working tree with those of a git ref, on this
# machine:
#
#   scripts/bench.sh [base-ref]      # base-ref defaults to the latest release tag
#
#   COUNT=10 scripts/bench.sh        # runs per benchmark (default 6)
#   BENCH=Stream scripts/bench.sh    # only benchmarks matching a regexp
#   RPSL_REALDATA=$PWD/.data/ripe scripts/bench.sh   # the real-data ones too
#
# The base ref runs in a temporary git worktree, so nothing in this checkout
# changes. The results are written to base.txt and head.txt in a directory the
# script prints, and compared with benchstat when it is installed
# (go install golang.org/x/perf/cmd/benchstat@latest). Timings only compare
# fairly on one machine with little else running, which is why nothing here
# runs in CI. Even then a few percent is noise — comparing a tree against
# itself shows how much — so reproduce a change before believing it.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
base=${1:-$(git describe --tags --abbrev=0 --match 'v*')}
count=${COUNT:-6}
bench=${BENCH:-.}
modules=". lexer ast types resolve examples/bulk-ripe"
out=$(mktemp -d "${TMPDIR:-/tmp}/rpsl-bench.XXXXXX")
tree=$out/base-tree
cleanup() { git -C "$repo" worktree remove --force "$tree" 2>/dev/null || true; }
trap cleanup EXIT

# run runs the benchmarks of every module of the tree at $1 into the file $2;
# $3 names the tree in a warning.
run() {
	: >"$2"
	for m in $modules; do
		[ -d "$1/$m" ] || continue # a module the base ref does not have yet
		(cd "$1/$m" && go test -run '^$' -bench "$bench" -benchmem -count "$count" ./... >>"$2")
	done
	if ! grep -q '^Benchmark' "$2"; then
		echo "warning: $3 has no benchmarks matching '$bench'" >&2
	fi
}

echo "== base: $base"
git worktree add --quiet --detach "$tree" "$base"
run "$tree" "$out/base.txt" "$base"
echo "== head: the working tree"
run "$repo" "$out/head.txt" "the working tree"

echo "== results in $out"
bin=$(go env GOPATH)/bin
cmd=$(command -v benchstat || true)
[ -n "$cmd" ] || { [ -x "$bin/benchstat" ] && cmd="$bin/benchstat"; }
if [ -n "$cmd" ]; then
	(cd "$out" && "$cmd" base=base.txt head=head.txt)
else
	echo "benchstat is not installed; to compare:"
	echo "  go install golang.org/x/perf/cmd/benchstat@latest"
	echo "  cd $out && benchstat base=base.txt head=head.txt"
fi
