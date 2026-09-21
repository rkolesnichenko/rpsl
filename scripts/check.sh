#!/bin/sh
# Full verification for every module — what CI runs, and what to run before a
# commit:
#
#   scripts/check.sh                 # build, vet, race tests, gofmt, invariants
#   FUZZTIME=15s scripts/check.sh    # ... plus every fuzz target for 15s each
#
# staticcheck and govulncheck run when installed (CI installs them).
set -u
cd "$(dirname "$0")/.."
modules=". lexer ast types resolve examples/bulk-ripe"
fail=0
step() { printf '\n== %s\n' "$*"; }
bad() { echo "FAIL: $*"; fail=1; }

step gofmt
unformatted=$(gofmt -l .)
[ -z "$unformatted" ] || bad "not gofmt-clean: $unformatted"

for m in $modules; do
	step "module $m: build, vet, test -race"
	(cd "$m" && go build ./... && go vet ./... && go test -race -count=1 ./...) || bad "module $m"
done

step "leaf isolation: types and lexer depend on no sibling module"
for leaf in types lexer; do
	others=$(cd "$leaf" && go list -deps ./... | grep rkolesnichenko | grep -v "rpsl/$leaf\$")
	[ -z "$others" ] || bad "$leaf depends on $others"
done

step "engine purity: the core resolve package does not import net"
if (cd resolve && go list -deps .) | grep -qx net; then bad "resolve imports net"; fi

bin=$(go env GOPATH)/bin
for tool in staticcheck govulncheck; do
	cmd=$(command -v "$tool" || true)
	[ -n "$cmd" ] || { [ -x "$bin/$tool" ] && cmd="$bin/$tool"; }
	if [ -z "$cmd" ]; then
		step "$tool: not installed, skipped"
		continue
	fi
	for m in $modules; do
		step "$tool $m"
		(cd "$m" && "$cmd" ./...) || bad "$tool $m"
	done
done

if [ -n "${FUZZTIME:-}" ]; then
	# module-dir package fuzz-target
	for t in "lexer . FuzzTokenize" "ast . FuzzAttributeList" \
		"types . FuzzParseSetName" "types . FuzzParseRangeOperator" \
		". . FuzzParseStream" ". ./policy FuzzParseImport" ". ./policy FuzzParseASPathRegexp" \
		". ./policy FuzzParseFilter" ". ./policy FuzzParsePeering"; do
		set -- $t
		step "fuzz $3 ($FUZZTIME)"
		(cd "$1" && go test -run='^$' -fuzz="^$3\$" -fuzztime="$FUZZTIME" "$2") || bad "fuzz $3"
	done
fi

echo
if [ "$fail" -ne 0 ]; then echo "check: FAILED"; exit 1; fi
echo "check: ok"
