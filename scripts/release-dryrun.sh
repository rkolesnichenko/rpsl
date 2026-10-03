#!/bin/sh
# Rehearses a release end to end without publishing anything:
#
#   scripts/release-dryrun.sh vX.Y.Z     # the version about to be released
#
# It runs the real scripts/release.sh on a copy of the tree as it would be
# committed — the version dated in its CHANGELOG.md — against a bare git
# repository standing in for GitHub and a file-system module proxy standing in
# for the Go proxy (scripts/mkproxy), which publishes each pushed tag a moment
# later, as the Go proxy does, so the script must wait for it. Before the
# release it checks the script's refusals (a dirty tree, HEAD not pushed, an
# undated version, a tag outside HEAD's history); during it, it stops the
# script after step 2 and runs it again, which must resume. release.sh's own
# last steps then check every module from an empty module cache — its
# @latest, that a consumer gets only what it requires, its tests from the
# zip — and every rpslq, rpslconf, rpslcheck and rpsld archive it builds, as a real
# release does.
# Nothing touches the real repository, its remote, the public proxy, the
# checksum database, GitHub, or your module cache.
set -eu
V=${1:?usage: scripts/release-dryrun.sh vX.Y.Z (the version about to be released)}
X=${V#v}
M=github.com/rkolesnichenko/rpsl
repo=$(cd "$(dirname "$0")/.." && pwd)
# A released version is already in every go.mod and go.sum; rehearsing it again
# has nothing to bump and would clash with the published checksums.
if [ -n "$(git -C "$repo" tag -l "$V" "*/$V")" ]; then
	echo "release-dryrun: $V is already released; rehearse the next version" >&2
	exit 2
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rpsl-dryrun.XXXXXX")
trap 'wait; chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
work=$tmp/repo
proxy=$tmp/proxy

export GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=mod
export GOPROXY="file://$proxy" GONOSUMDB="$M" GOMODCACHE="$tmp/modcache"
export RELEASE_REMOTE=rehearsal RELEASE_PROXY="file://$proxy" RELEASE_POLL=1 RELEASE_WAIT=120 RELEASE_SKIP_CI=1
export RELEASE_ON_PUSH="$tmp/publish" RELEASE_DIST="$tmp/dist"

step() { printf '\n== dryrun: %s\n' "$*"; }
git_() { git -c user.name=release-dryrun -c user.email=dryrun@localhost "$@"; }
die() {
	echo "release-dryrun: FAIL: $*" >&2
	exit 1
}

step "snapshot the tree as it would be committed, $V dated"
mkdir -p "$work" "$proxy"
(cd "$repo" && git ls-files -z --cached --others --exclude-standard |
	xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\0" "$f"; done' _ |
	tar --null -T - -cf -) | (cd "$work" && tar -xf -)
cd "$work"
git_ init -q -b main && git_ add -A && git_ commit -qm snapshot && git_ tag snapshot
if ! grep -q "^## \[$X\] - " CHANGELOG.md; then
	awk -v x="$X" -v d="$(date +%Y-%m-%d)" -v m="https://github.com/rkolesnichenko/rpsl" '
		/^## \[Unreleased\]$/ { print; print ""; print "## [" x "] - " d; next }
		/^\[Unreleased\]: / { print "[Unreleased]: " m "/compare/v" x "...HEAD"; print "[" x "]: " m "/releases/tag/v" x; next }
		{ print }' CHANGELOG.md >CHANGELOG.md.new && mv CHANGELOG.md.new CHANGELOG.md
	git_ commit -qam "changelog: date $V"
fi
git_ init -q --bare "$tmp/remote.git"
git_ remote add rehearsal "$tmp/remote.git"
git_ push -q rehearsal main
(cd scripts/mkproxy && go build -o "$tmp/mkproxy" .)
# The stand-in proxy publishes a pushed module two seconds later, as the Go
# proxy fetches a tag only after it is asked, so release.sh must wait for it.
cat >"$tmp/publish" <<EOF
#!/bin/sh
(sleep 2; "$tmp/mkproxy" -repo "$work" -out "$proxy" -version "$V" "\$@") &
EOF
chmod +x "$tmp/publish"

release() {
	sh scripts/release.sh "$@" --no-gh-release
}
remote_tags() { git ls-remote --tags rehearsal | sed 's|.*refs/tags/||' | sort | tr '\n' ' '; }

# refused runs release.sh expecting it to refuse (exit 2) with a message
# containing $1, and to leave the remote without release tags.
refused() {
	want=$1
	shift
	if out=$(release "$@" 2>&1); then
		die "release.sh did not refuse ($want)"
	fi
	echo "$out" | grep -q "$want" || die "release.sh refused, but not with \"$want\":
$out"
	[ -z "$(remote_tags | tr -d ' ')" ] || die "a refused run pushed tags: $(remote_tags)"
	echo "refused: $want"
}

step "release.sh refuses what it must"
touch stray-file
refused "the tree is not clean" "$V"
rm stray-file
git_ commit -q --allow-empty -m "not pushed"
refused "HEAD is not rehearsal/main" "$V"
git_ reset -q --hard HEAD~1
refused 'no dated "## \[99.0.0\]' v99.0.0
orphan=$(git_ commit-tree -m orphan "$(git write-tree)")
git_ push -q rehearsal "$orphan:refs/tags/lexer/$V"
if out=$(release "$V" 2>&1); then die "a tag outside HEAD's history was accepted"; fi
echo "$out" | grep -q "is not in HEAD's history" || die "a foreign tag was refused, but not as such:
$out"
echo "refused: a tag outside HEAD's history"
git_ push -q rehearsal ":refs/tags/lexer/$V"
git_ tag -d "lexer/$V" >/dev/null 2>&1 || true # release.sh fetched it

step "release.sh, stopped after step 2"
if (export RELEASE_STOP_AFTER=2; release "$V"); then die "RELEASE_STOP_AFTER=2 did not stop the release"; fi
[ "$(remote_tags)" = "ast/$V lexer/$V types/$V " ] || die "after step 2 the remote has: $(remote_tags)"

step "release.sh again: it resumes and finishes"
release "$V" || die "the resumed release failed"
[ "$(remote_tags)" = "ast/$V lexer/$V resolve/$V types/$V $V " ] || die "the remote has: $(remote_tags)"
[ "$(git rev-parse HEAD)" = "$(git rev-parse rehearsal/main)" ] || die "main is not pushed"


step "release dry run: ok"
echo "The release commits release.sh made, in order:"
git log --reverse --format='%s:' --name-only snapshot..HEAD | sed '/^$/d; /:$/!s/^/    /'
