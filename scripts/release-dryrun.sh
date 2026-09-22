#!/bin/sh
# Rehearses a release (RELEASING.md) end to end without publishing anything:
#
#   scripts/release-dryrun.sh vX.Y.Z     # the version about to be released
#
# In a temporary git repository holding the tree as it would be committed, it
# follows RELEASING.md step by step — bump each module's requires in dependency
# order, `GOWORK=off go mod tidy`, build, vet and test the module on its own,
# commit exactly the files RELEASING.md adds, publish the module — against a
# file-system proxy that serves each module's zip the way the Go proxy would
# (scripts/mkproxy). Then a fresh consumer module fetches each module, must end
# up with only that module and the ones it requires, and runs the published
# module's own tests from its zip. Nothing touches the real repository, its
# remote, the public proxy, or your module cache.
set -eu
V=${1:?usage: scripts/release-dryrun.sh vX.Y.Z (the version about to be released)}
M=github.com/rkolesnichenko/rpsl
repo=$(cd "$(dirname "$0")/.." && pwd)
# A released version is already in every go.mod and go.sum; rehearsing it again
# has nothing to bump and would clash with the published checksums.
if [ -n "$(git -C "$repo" tag -l "$V" "*/$V")" ]; then
	echo "release-dryrun: $V is already released; rehearse the next version" >&2
	exit 2
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rpsl-dryrun.XXXXXX")
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
work=$tmp/repo
proxy=$tmp/proxy

# Resolve siblings from the rehearsal proxy only, never record them in the
# public checksum database, and keep the rehearsal out of the real module cache.
export GOWORK=off GOFLAGS=-mod=mod GOTOOLCHAIN=local
export GOPROXY="file://$proxy" GONOSUMDB="$M" GOMODCACHE="$tmp/modcache"

step() { printf '\n== %s\n' "$*"; }
git_() { git -c user.name=release-dryrun -c user.email=dryrun@localhost "$@"; }

step "snapshot the tree as it would be committed"
mkdir -p "$work" "$proxy"
(cd "$repo" && git ls-files -z --cached --others --exclude-standard |
	xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\0" "$f"; done' _ |
	tar --null -T - -cf -) | (cd "$work" && tar -xf -)
cd "$work"
git_ init -q && git_ add -A && git_ commit -qm snapshot && git_ tag snapshot
(cd scripts/mkproxy && go build -o "$tmp/mkproxy" .)

publish() { "$tmp/mkproxy" -repo "$work" -out "$proxy" -version "$V" "$@"; }

# check builds, vets and tests one module outside the workspace.
check() {
	step "$1: build, vet, test with GOWORK=off"
	(cd "$1" && go build ./... && go vet ./... && go test -count=1 ./...)
}

# commit commits exactly the files RELEASING.md adds, and fails if tidying
# left anything else behind (such as a new go.sum that `git commit -am` skips).
commit() {
	msg=$1
	shift
	git_ add "$@"
	git_ commit -qm "$msg"
	left=$(git status --porcelain)
	if [ -n "$left" ]; then
		echo "FAIL: left uncommitted after \"$msg\":"
		echo "$left"
		exit 1
	fi
	echo "committed: $*"
}

step "1. lexer and types (no sibling requirements)"
check lexer
check types
publish lexer types

step "2. ast (requires lexer)"
(cd ast && go mod edit -require=$M/lexer@$V && go mod tidy)
check ast
commit "ast: require lexer $V" ast/go.mod ast/go.sum
publish ast

step "3. the root module (requires ast, lexer, types)"
go mod edit -require=$M/ast@$V -require=$M/lexer@$V -require=$M/types@$V
go mod tidy
check .
commit "rpsl: require the leaves at $V" go.mod go.sum
publish .

step "4. resolve (requires the root module and the leaves)"
(cd resolve && go mod edit -require=$M@$V -require=$M/ast@$V -require=$M/lexer@$V -require=$M/types@$V && go mod tidy)
check resolve
commit "resolve: require $V" resolve/go.mod resolve/go.sum
publish resolve

step "5. examples/bulk-ripe (not tagged; builds outside the workspace)"
(cd examples/bulk-ripe && for m in "" /ast /lexer /resolve /types; do go mod edit -require=$M$m@$V; done && go mod tidy)
check examples/bulk-ripe
commit "examples: require $V" examples/bulk-ripe/go.mod examples/bulk-ripe/go.sum

step "6. a consumer of each module gets only what it requires, and the published tests pass"
for spec in "types:$M/types" "lexer:$M/lexer" "ast:$M/ast $M/lexer" \
	"rpsl:$M $M/ast $M/lexer $M/types" "resolve:$M/resolve $M $M/ast $M/lexer $M/types"; do
	name=${spec%%:*}
	want=$(printf '%s\n' ${spec#*:} | sort)
	mod=$(printf '%s\n' ${spec#*:} | head -1)
	c=$tmp/consumer-$name
	mkdir -p "$c"
	(
		cd "$c"
		go mod init example.com/consumer >/dev/null 2>&1
		go get "$mod@$V" >/dev/null 2>&1
		got=$(go list -m all | sed 1d | cut -d' ' -f1 | sort)
		if [ "$got" != "$want" ]; then
			echo "FAIL: a consumer of $mod needs:"
			echo "$got"
			echo "want:"
			echo "$want"
			exit 1
		fi
		pkgs=$(go list -f '{{if eq .Module.Path "'"$mod"'"}}{{.ImportPath}}{{end}}' "$mod/..." | grep .)
		go test -count=1 $pkgs >/dev/null
		echo "$mod@$V: modules $(echo $got), its tests pass from the zip"
	)
done

step "release dry run: ok"
echo "The release commits RELEASING.md makes, in order:"
git log --reverse --format='%s:' --name-only snapshot..HEAD | sed '/^$/d; /:$/!s/^/    /'
