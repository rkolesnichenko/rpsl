#!/bin/sh
# Full verification for every module — what CI runs, and what to run before a
# commit:
#
#   scripts/check.sh                 # build, vet, race tests, gofmt, invariants,
#                                    # every benchmark once
#   FUZZTIME=15s scripts/check.sh    # ... plus every fuzz target for 15s each
#                                    # (scripts/fuzz.sh, which CI runs as its own job)
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
# It writes the NUL-separated list to stdout and returns 1 when git fails, which
# a pipeline's status (no pipefail in sh) would hide.
gofiles() {
	gofiles_list=$(mktemp) || return 1
	if git ls-files -z --cached --others --exclude-standard '*.go' > "$gofiles_list"; then
		xargs -0 sh -c 'for f; do if [ -f "$f" ]; then printf "%s\0" "$f"; fi; done' _ < "$gofiles_list"
		gofiles_rc=$?
	else
		gofiles_rc=1
	fi
	rm -f "$gofiles_list"
	return $gofiles_rc
}

step gofmt
# xargs exits non-zero when gofmt does (a file that does not parse), so the
# capture's status is tested, not only its output.
gofmt_files=$(mktemp) || bad "could not list Go files"
if gofiles > "$gofmt_files"; then
	unformatted=$(xargs -0 gofmt -l < "$gofmt_files") || bad "gofmt failed (a file does not parse?)"
else
	bad "could not list Go files"
	unformatted=
fi
rm -f "$gofmt_files"
[ -z "$unformatted" ] || bad "not gofmt-clean: $unformatted"

for m in $modules; do
	step "module $m: build, vet, test -race"
	(cd "$m" && go build ./... && go vet ./... && go test -race -count=1 ./...) || bad "module $m"
done

# Coverage is reported, not enforced. It runs without -race: with it, coverage
# counters are atomic and slow the hot loops of the tests about fourfold.
step "coverage"
for m in $modules; do
	# The output is captured first: grep's status in a pipeline would hide a
	# failing run whose output still reports coverage.
	out=$(cd "$m" && go test -count=1 -cover ./... 2>&1) || { printf '%s\n' "$out"; bad "coverage $m"; continue; }
	printf '%s\n' "$out" | grep -o 'rkolesnichenko/[^ 	]*.*coverage: [0-9.]*%'
done

# Every benchmark runs once, so none can break unnoticed. Timing them is
# scripts/bench.sh's job: one run on a shared machine measures nothing.
step "benchmarks: each runs once"
for m in $modules; do
	(cd "$m" && go test -run '^$' -bench . -benchtime 1x ./... >/dev/null) || bad "benchmarks $m"
done

step "leaf isolation: types and lexer depend on no sibling module, ast only on lexer"
for spec in "types:" "lexer:" "ast:lexer"; do
	leaf=${spec%%:*}
	allowed="rpsl/$leaf\$"
	[ -z "${spec#*:}" ] || allowed="$allowed|rpsl/${spec#*:}\$"
	# go list's status is tested on its own: through a pipe, a failing go list
	# would leave an empty list and pass.
	deps=$(cd "$leaf" && go list -deps ./...) || { bad "go list $leaf"; continue; }
	others=$(printf '%s\n' "$deps" | grep rkolesnichenko | grep -Ev "$allowed")
	[ -z "$others" ] || bad "$leaf depends on $others"
done

step "tools: scripts/mkproxy builds and vets"
(cd scripts/mkproxy && GOWORK=off go build -o /dev/null . && GOWORK=off go vet .) || bad "scripts/mkproxy"

step "engine purity: resolve, resolve/peval, resolve/rtconfig, resolve/consist, resolve/irrdq and resolve/rpki do not import net"
if deps=$(cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki); then
	if printf '%s\n' "$deps" | grep -qx net; then bad "resolve, resolve/peval, resolve/rtconfig, resolve/consist, resolve/irrdq or resolve/rpki imports net"; fi
else
	bad "go list resolve"
fi

step "any names: only types spells AS-ANY and its kin (types.SetName.IsAny)"
# A quoted AS-ANY, RS-ANY, RTRS-ANY, PRNG-ANY or FLTR-ANY outside types is a
# copy of SetName.IsAny. grep exits 1 when nothing matches, the good case, so
# only a status above 1 fails the step. IsAny's own names must be among the
# hits, or the listing or the pattern is broken and the step would pass on
# any tree.
any_files=$(mktemp) || bad "could not list Go files"
if gofiles > "$any_files"; then
	any_hits=$(xargs -0 sh -c 'grep -H -n -i -E "\"(AS|RS|RTRS|PRNG|FLTR)-ANY\"" "$@"; [ $? -le 1 ]' _ < "$any_files") ||
		bad "any names: grep failed"
	case "$any_hits" in
	*types/setname.go:*) ;;
	*) bad "any names: types/setname.go's names were not found (is the step broken?)" ;;
	esac
	any_hits=$(printf '%s\n' "$any_hits" |
		grep -v -E '^([^:]*_test\.go|types/setname\.go|resolve/internal/irrdoracle/cases\.go):') ||
		[ $? -eq 1 ] || bad "any names: filtering the hits failed"
else
	bad "could not list Go files"
	any_hits=
fi
rm -f "$any_files"
[ -z "$any_hits" ] || bad "a copy of types.SetName.IsAny: $any_hits"

step "api surface: api/ matches the public API, and the API conventions hold"
go run ./internal/apisurface -check ||
	bad "api surface (RPSL_API_UPDATE=1 go run ./internal/apisurface -check rewrites api/; review the diff)"

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
	scripts/fuzz.sh || bad "fuzz"
fi

echo
if [ "$fail" -ne 0 ]; then echo "check: FAILED"; exit 1; fi
echo "check: ok"
