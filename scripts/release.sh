#!/bin/sh
# Releases every module at one version, as RELEASING.md describes it, in order:
#
#   scripts/release.sh vX.Y.Z [--no-gh-release]
#
# It refuses to start unless the tree is clean, on main and pushed, CHANGELOG.md
# has the version dated and linked, and CI passed on HEAD. Then: tag lexer and
# types; bump, tidy, build, vet, test, commit, tag and push ast, the root module
# and resolve in turn; bump examples/bulk-ripe (untagged). After each push it
# waits until the Go proxy serves the tag — asking only for tags already
# pushed, from an empty module cache so the local one cannot answer for it, and
# by the tag's commit too, which makes a proxy that cached a miss fetch
# again — and it retries a `go mod tidy` the checksum database is not
# ready for. Last, from an empty module cache: every module's @latest is the
# version, a consumer of each gets only what it requires and its tests pass
# from the published zip, and rpslq and rpslconf install; then rpslq's and
# rpslconf's binaries, built from the published module for each platform, and
# the GitHub release, from the changelog section, with the binaries attached.
#
# Each step first checks whether it is done — its tag on the remote, its commit
# made — so after a failure the same command resumes where it stopped.
#
# The environment changes where it publishes, for scripts/release-dryrun.sh:
#   RELEASE_REMOTE   git remote to push to (origin)
#   RELEASE_PROXY    module proxy to wait on and verify with (https://proxy.golang.org)
#   RELEASE_POLL     seconds between proxy polls (30); RELEASE_WAIT the most to wait (2400)
#   RELEASE_SKIP_CI  1: do not ask GitHub whether CI passed
#   RELEASE_ON_PUSH  a command run with the module directories after each tag push
#   RELEASE_STOP_AFTER  stop after this step (1-5), as if it had failed there
#   RELEASE_DIST     directory to leave rpslq's and rpslconf's archives in (a temporary one)
set -eu

usage() {
	echo "usage: scripts/release.sh vX.Y.Z [--no-gh-release]" >&2
	exit 2
}
V=
GH_RELEASE=1
for a in "$@"; do
	case $a in
	--no-gh-release) GH_RELEASE= ;;
	v*.*.*) V=$a ;;
	*) usage ;;
	esac
done
[ -n "$V" ] || usage
X=${V#v} # the version as CHANGELOG.md writes it
M=github.com/rkolesnichenko/rpsl
REMOTE=${RELEASE_REMOTE:-origin}
PROXY=${RELEASE_PROXY:-https://proxy.golang.org}
POLL=${RELEASE_POLL:-30}
WAIT=${RELEASE_WAIT:-2400}
cd "$(dirname "$0")/.."
export GOWORK=off
PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64" # rpslq's and rpslconf's binaries

step() { printf '\n== %s\n' "$*"; }
refuse() {
	echo "release: $*" >&2
	echo "release: nothing was pushed" >&2
	exit 2
}
fail() {
	echo "release: $*" >&2
	echo "release: fix it and run the same command again: it resumes where it stopped" >&2
	exit 1
}
stop_after() {
	if [ "${RELEASE_STOP_AFTER:-}" = "$1" ]; then
		echo "release: stopping after step $1 (RELEASE_STOP_AFTER)" >&2
		exit 3
	fi
}

# remote_tag prints the commit a tag names on the remote, or nothing.
remote_tag() { git ls-remote --tags "$REMOTE" "refs/tags/$1" | cut -f1; }

# ask_proxy asks the proxy for the module query $1, from an empty module cache
# and outside any module, so the answer is the proxy's own. With the local cache
# the query passes, without asking, for a version a tidy has just resolved, and
# a miss the proxy has cached goes unseen until a consumer — or step 6 — hits it
# (v0.20.0: the root module was "served" while the proxy answered 404 for ~45 min).
ask_proxy() {
	d=$(mktemp -d "${TMPDIR:-/tmp}/rpsl-ask.XXXXXX")
	rc=0
	(cd "$d" && GOMODCACHE="$d/modcache" GOPATH="$d/gopath" GOPROXY=$PROXY GOFLAGS=-mod=mod \
		go list -m "$1" >/dev/null 2>&1) || rc=$?
	chmod -R u+w "$d" 2>/dev/null || true
	rm -rf "$d"
	return "$rc"
}

# served reports whether the proxy serves module $1 at $V.
served() { ask_proxy "$1@$V"; }

# wait_proxy waits until the proxy serves module $1 at $V, tagged $2. Asking by
# the tag's commit makes a proxy that cached a miss (from before the push)
# fetch the tag again.
wait_proxy() {
	commit=$(git rev-parse "$2^{commit}")
	waited=0
	until served "$1"; do
		[ "$waited" -gt 0 ] || echo "waiting for the proxy to serve $1@$V"
		if [ "$waited" -ge "$WAIT" ]; then
			fail "$1@$V: the proxy still does not serve it after ${WAIT}s"
		fi
		ask_proxy "$1@$commit" || true
		sleep "$POLL"
		waited=$((waited + POLL))
	done
	echo "proxy serves $1@$V"
}

# tidy runs `go mod tidy` in $1, retrying while the checksum database or the
# proxy has not caught up with a sibling just published.
tidy() {
	waited=0
	until out=$(cd "$1" && go mod tidy 2>&1); do
		case $out in
		*"404 Not Found"* | *"unknown revision"*) ;;
		*) echo "$out" >&2; fail "go mod tidy in $1" ;;
		esac
		if [ "$waited" -ge "$WAIT" ]; then
			echo "$out" >&2
			fail "go mod tidy in $1: a sibling is still not available after ${WAIT}s"
		fi
		sleep "$POLL"
		waited=$((waited + POLL))
	done
}

# check builds, vets and tests module directory $1 on its own.
check() {
	(cd "$1" && go build ./... && go vet ./... && go test -count=1 ./...) >/dev/null ||
		fail "$1 does not build, vet or test cleanly at $V (run it by hand to see why)"
}

pushed() {
	[ -n "${RELEASE_ON_PUSH:-}" ] && $RELEASE_ON_PUSH "$@"
	return 0
}

# release_tags prints the tags of $V that exist, locally or on the remote.
release_tags() {
	{
		git tag -l "$V" "*/$V"
		git ls-remote --tags "$REMOTE" "refs/tags/$V" "refs/tags/*/$V" | sed 's|.*refs/tags/||'
	} | sort -u
}

step "preconditions"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || refuse "not on main"
[ -z "$(git status --porcelain)" ] || refuse "the tree is not clean"
git fetch -q --tags "$REMOTE"
existing=$(release_tags)
if [ -z "$existing" ]; then
	[ "$(git rev-parse HEAD)" = "$(git rev-parse "$REMOTE/main")" ] ||
		refuse "HEAD is not $REMOTE/main: push first, and let CI run"
	grep -Eq "^## \[$X\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md ||
		refuse "CHANGELOG.md has no dated \"## [$X] - YYYY-MM-DD\" section"
	grep -q "^\[$X\]: " CHANGELOG.md || refuse "CHANGELOG.md does not link [$X]"
	if [ -z "${RELEASE_SKIP_CI:-}" ]; then
		runs=$(gh run list --commit "$(git rev-parse HEAD)" --json status,conclusion \
			--jq '.[] | .status + "/" + .conclusion')
		[ -n "$runs" ] || refuse "no CI run for HEAD"
		echo "$runs" | grep -vqx 'completed/success' && refuse "CI has not passed on HEAD: $(echo $runs)"
	fi
	echo "releasing $V from $(git log -1 --format='%h %s')"
else
	# Resuming: every tag already made must be in HEAD's history.
	for t in $existing; do
		c=$(remote_tag "$t")
		[ -n "$c" ] || c=$(git rev-parse "$t^{commit}")
		git merge-base --is-ancestor "$c" HEAD || refuse "tag $t ($c) is not in HEAD's history"
	done
	echo "resuming $V: already tagged: $(echo $existing)"
fi

step "1. lexer and types"
if [ -z "$(remote_tag "lexer/$V")" ] || [ -z "$(remote_tag "types/$V")" ]; then
	check lexer
	check types
	for d in lexer types; do
		git rev-parse -q --verify "refs/tags/$d/$V" >/dev/null || git tag "$d/$V"
	done
	git push -q "$REMOTE" "lexer/$V" "types/$V"
	pushed lexer types
fi
wait_proxy "$M/lexer" "lexer/$V"
wait_proxy "$M/types" "types/$V"
stop_after 1

# bump releases module directory $1 under tag $2 ("" for none): it requires
# the modules after $4 at $V, and commits as $3.
bump() {
	dir=$1 tag=$2 msg=$3
	shift 3
	if [ -n "$tag" ] && [ -n "$(remote_tag "$tag")" ]; then
		echo "$tag is on $REMOTE already"
	else
		if [ "$(git log -1 --format=%s)" != "$msg" ]; then
			for m in "$@"; do (cd "$dir" && go mod edit "-require=$m@$V"); done
			tidy "$dir"
			check "$dir"
			git add "$dir/go.mod" "$dir/go.sum"
			git commit -qm "$msg"
			[ -z "$(git status --porcelain)" ] || fail "\"$msg\" left files uncommitted: $(git status --porcelain)"
			echo "committed: $msg"
		fi
		if [ -n "$tag" ]; then
			git rev-parse -q --verify "refs/tags/$tag" >/dev/null || git tag "$tag"
			git push -q "$REMOTE" main "$tag"
			pushed "$dir"
		else
			git push -q "$REMOTE" main
		fi
	fi
}

step "2. ast (requires lexer)"
bump ast "ast/$V" "ast: require lexer $V" "$M/lexer"
wait_proxy "$M/ast" "ast/$V"
stop_after 2

step "3. the root module (requires ast, lexer, types)"
bump . "$V" "rpsl: require the leaves at $V" "$M/ast" "$M/lexer" "$M/types"
wait_proxy "$M" "$V"
stop_after 3

step "4. resolve (requires the root module and the leaves)"
bump resolve "resolve/$V" "resolve: require $V" "$M" "$M/ast" "$M/lexer" "$M/types"
wait_proxy "$M/resolve" "resolve/$V"
stop_after 4

step "5. examples/bulk-ripe (not tagged; builds outside the workspace)"
git fetch -q "$REMOTE"
if git log "$REMOTE/main" --format=%s | grep -qx "examples: require $V"; then
	echo "examples are bumped on $REMOTE already"
else
	bump examples/bulk-ripe "" "examples: require $V" "$M" "$M/ast" "$M/lexer" "$M/resolve" "$M/types"
fi
stop_after 5

step "6. from an empty module cache"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rpsl-release.XXXXXX")
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
export GOMODCACHE="$tmp/modcache" GOPATH="$tmp/gopath" GOPROXY="$PROXY" GOFLAGS=-mod=mod
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
		latest=$(go list -m "$mod@latest")
		[ "$latest" = "$mod $V" ] || fail "$mod@latest is $latest, not $V"
		go get "$mod@$V" >/dev/null 2>&1 || fail "go get $mod@$V"
		got=$(go list -m all | sed 1d | cut -d' ' -f1 | sort)
		[ "$got" = "$want" ] || fail "a consumer of $mod needs $(echo $got), not $(echo $want)"
		pkgs=$(go list -f '{{if eq .Module.Path "'"$mod"'"}}{{.ImportPath}}{{end}}' "$mod/..." | grep .)
		if ! out=$(go test -count=1 $pkgs 2>&1); then
			echo "$out" | grep -v '^ok' | tail -40 >&2
			fail "$mod@$V: its tests fail from the published zip"
		fi
		echo "$mod@$V: @latest, modules $(echo $got), its tests pass from the zip"
	)
done
GOBIN=$tmp/bin go install "$M/resolve/cmd/rpslq@$V" || fail "go install rpslq@$V"
got=$("$tmp/bin/rpslq" -v)
[ "$got" = "rpslq $V" ] || fail "rpslq -v says \"$got\", not \"rpslq $V\""
echo "$got installs"
GOBIN=$tmp/bin go install "$M/resolve/cmd/rpslconf@$V" || fail "go install rpslconf@$V"
got=$("$tmp/bin/rpslconf" -v)
[ "$got" = "rpslconf $V" ] || fail "rpslconf -v says \"$got\", not \"rpslconf $V\""
echo "$got installs"

step "7. rpslq and rpslconf binaries, built from the published module"
# The archives outlive the script: in RELEASE_DIST, made absolute, or beside
# the other temporary files of this user — not in $tmp, which the EXIT trap
# removes, as it would with --no-gh-release before anyone uploaded them.
dist=${RELEASE_DIST:-${TMPDIR:-/tmp}/rpsl-release-$V}
mkdir -p "$dist" "$tmp/build"
dist=$(cd "$dist" && pwd)
rm -f "$dist"/rpslq_"${V}"_* "$dist"/rpslconf_"${V}"_* "$dist/SHA256SUMS"
(
	cd "$tmp/build"
	go mod init example.com/rpslq-build >/dev/null 2>&1
	go get "$M/resolve@$V" >/dev/null 2>&1 || fail "go get $M/resolve@$V"
	license=$(go list -m -f '{{.Dir}}' "$M/resolve")/LICENSE
	for tool in rpslq rpslconf; do
		for p in $PLATFORMS; do
			os=${p%/*} arch=${p#*/}
			exe=$tool
			[ "$os" = windows ] && exe=$tool.exe
			stage=$tmp/stage-$tool-$os-$arch
			mkdir -p "$stage"
			GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$stage/$exe" "$M/resolve/cmd/$tool" ||
				fail "building $tool for $p"
			cp "$license" "$stage/LICENSE"
			case $tool in
			rpslq)
				cat >"$stage/README.txt" <<README
rpslq $V ($os/$arch): router filters from IRR data, as bgpq4 writes them,
on the rpsl engine. Its command line is bgpq4's; see
https://github.com/rkolesnichenko/rpsl/blob/main/docs/rpslq.md
README
				;;
			rpslconf)
				cat >"$stage/README.txt" <<README
rpslconf $V ($os/$arch): router configuration from the routing policy in
IRR data, as IRRToolSet's rtconfig writes it, on the rpsl engine. See
https://github.com/rkolesnichenko/rpsl/blob/main/docs/rpslconf.md
README
				;;
			esac
			name=${tool}_${V}_${os}_$arch
			if [ "$os" = windows ]; then
				(cd "$stage" && zip -q -X "$dist/$name.zip" "$exe" LICENSE README.txt)
			else
				tar -czf "$dist/$name.tar.gz" -C "$stage" "$exe" LICENSE README.txt
			fi
			echo "built $name"
		done
	done
)
if command -v sha256sum >/dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$dist" && $sum rpslq_"${V}"_* rpslconf_"${V}"_* >SHA256SUMS)

# Check what is about to be published: the checksums, each archive's contents,
# the platform and module version each binary was built for, and the native
# binary's own word.
(cd "$dist" && $sum -c --quiet SHA256SUMS) || fail "SHA256SUMS does not verify"
native=$(go env GOOS)/$(go env GOARCH)
for tool in rpslq rpslconf; do
	for p in $PLATFORMS; do
		os=${p%/*} arch=${p#*/}
		exe=$tool a=$dist/${tool}_${V}_${os}_$arch.tar.gz
		[ "$os" = windows ] && exe=$tool.exe a=$dist/${tool}_${V}_${os}_$arch.zip
		x=$tmp/check-$tool-$os-$arch
		mkdir -p "$x"
		if [ "$os" = windows ]; then (cd "$x" && unzip -q "$a"); else tar -xzf "$a" -C "$x"; fi
		[ "$(ls "$x" | tr '\n' ' ')" = "LICENSE README.txt $exe " ] || fail "$a holds $(ls "$x" | tr '\n' ' ')"
		info=$(go version -m "$x/$exe")
		{ echo "$info" | grep -q "GOOS=$os" && echo "$info" | grep -q "GOARCH=$arch"; } || fail "$a is not built for $p"
		echo "$info" | grep -Eq "(mod|dep)[[:space:]]+$M/resolve[[:space:]]+$V[[:space:]]+h1:" || fail "$a is not built from resolve $V"
		if [ "$p" = "$native" ] && [ "$("$x/$exe" -v)" != "$tool $V" ]; then
			fail "$a: $tool -v says $("$x/$exe" -v)"
		fi
		echo "checked $(basename "$a"): $p, from resolve $V"
	done
done
echo "archives and SHA256SUMS in $dist"

if [ -n "$GH_RELEASE" ]; then
	step "8. the GitHub release, with the binaries"
	assets=$(ls "$dist"/rpslq_"${V}"_* "$dist"/rpslconf_"${V}"_* "$dist/SHA256SUMS")
	if gh release view "$V" >/dev/null 2>&1; then
		echo "the GitHub release $V exists: attaching the binaries"
		gh release upload "$V" $assets --clobber
	else
		awk -v h="## [$X]" 'index($0, h) == 1 {f = 1; next} /^## \[/ {f = 0} f' CHANGELOG.md |
			sed -e '/./,$!d' >"$tmp/notes.md"
		[ -s "$tmp/notes.md" ] || fail "no notes for $V in CHANGELOG.md"
		gh release create "$V" --title "$V" --notes-file "$tmp/notes.md" --latest --verify-tag $assets
	fi
fi

step "released $V"
