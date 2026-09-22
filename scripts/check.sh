#!/bin/sh
# Full verification for every module — what CI runs, and what to run before a
# commit:
#
#   scripts/check.sh                 # build, vet, race tests, gofmt, invariants
#   FUZZTIME=15s scripts/check.sh    # ... plus every fuzz target for 15s each
#
# staticcheck and govulncheck run when installed (CI installs them), and the
# bgpq4 differential in resolve when bgpq4 is (CI installs it too).
set -u
cd "$(dirname "$0")/.."
modules=". lexer ast types resolve examples/bulk-ripe"
fail=0
step() { printf '\n== %s\n' "$*"; }
bad() { echo "FAIL: $*"; fail=1; }

# gofiles lists the Go files the next commit would hold — tracked or new, not
# ignored — so tool state such as .claude/ and .data/ is never scanned.
gofiles() {
	git ls-files -z --cached --others --exclude-standard '*.go' |
		xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\0" "$f"; done' _
}

step gofmt
unformatted=$(gofiles | xargs -0 gofmt -l)
[ -z "$unformatted" ] || bad "not gofmt-clean: $unformatted"

for m in $modules; do
	step "module $m: build, vet, test -race"
	(cd "$m" && go build ./... && go vet ./... && go test -race -count=1 ./...) || bad "module $m"
done

# Coverage is reported, not enforced. It runs without -race: with it, coverage
# counters are atomic and slow the hot loops of the tests about fourfold.
step "coverage"
for m in $modules; do
	(cd "$m" && go test -count=1 -cover ./... 2>&1 | grep -o 'rkolesnichenko/[^ 	]*.*coverage: [0-9.]*%') || bad "coverage $m"
done

step "leaf isolation: types and lexer depend on no sibling module, ast only on lexer"
for spec in "types:" "lexer:" "ast:lexer"; do
	leaf=${spec%%:*}
	allowed="rpsl/$leaf\$"
	[ -z "${spec#*:}" ] || allowed="$allowed|rpsl/${spec#*:}\$"
	others=$(cd "$leaf" && go list -deps ./... | grep rkolesnichenko | grep -Ev "$allowed")
	[ -z "$others" ] || bad "$leaf depends on $others"
done

step "tools: scripts/mkproxy builds and vets"
(cd scripts/mkproxy && GOWORK=off go build -o /dev/null . && GOWORK=off go vet .) || bad "scripts/mkproxy"

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

# fuzz runs one fuzz target. The Go fuzzing harness sometimes ends a run that
# found nothing with "context deadline exceeded" when a worker is slow to stop
# at -fuzztime; a real crash always prints "Failing input written to". So a run
# that fails that way without a failing input is retried once.
fuzz() {
	out=$(cd "$1" && go test -run='^$' -fuzz="^$3\$" -fuzztime="$FUZZTIME" "$2" 2>&1)
	rc=$?
	printf '%s\n' "$out"
	if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "context deadline exceeded" &&
		! printf '%s' "$out" | grep -q "Failing input written"; then
		step "fuzz $3: harness deadline without a failing input; retrying once"
		(cd "$1" && go test -run='^$' -fuzz="^$3\$" -fuzztime="$FUZZTIME" "$2")
		rc=$?
	fi
	return "$rc"
}

if [ -n "${FUZZTIME:-}" ]; then
	# module-dir package fuzz-target
	for t in "lexer . FuzzTokenize" "ast . FuzzAttributeList" "ast . FuzzEdit" "ast . FuzzFormat" \
		"types . FuzzParseSetName" "types . FuzzParseRangeOperator" "types . FuzzParsePrefixRange" \
		"types . FuzzParseRouterID" \
		". . FuzzParseStream" ". . FuzzDecode" ". ./policy FuzzParseImport" ". ./policy FuzzParseASPathRegexp" \
		". ./policy FuzzParseFilter" ". ./policy FuzzParsePeering" ". ./policy FuzzFilterString" \
		". ./policy FuzzParseInject" ". ./policy FuzzParseComponents" ". ./policy FuzzParseAggrMtd" \
		". ./policy FuzzParseIfaddr" ". ./policy FuzzParseInterface" ". ./policy FuzzParsePeer" \
		". ./policy FuzzParseRPAttribute" ". ./policy FuzzParseTypedef" ". ./policy FuzzParseProtocol"; do
		set -- $t
		step "fuzz $3 ($FUZZTIME)"
		fuzz "$1" "$2" "$3" || bad "fuzz $3"
	done
fi

echo
if [ "$fail" -ne 0 ]; then echo "check: FAILED"; exit 1; fi
echo "check: ok"
