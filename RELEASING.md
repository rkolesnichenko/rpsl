# Releasing

`rpsl` is six Go modules in one repository. Inside the repo they find each
other through `go.work`, which overrides every inter-module `require` with the
local directory; the `require`s themselves name the latest release. A consumer
has no workspace, so each module must be tagged and its siblings' `require`s
bumped to the new version, **in dependency order**: a module can only be tidied
once the versions it requires are on the proxy.

```
lexer, types  →  ast  →  root (rpsl: façade, object, policy)  →  resolve  →  examples/bulk-ripe
```

Nested modules are tagged with their directory as a prefix (`lexer/v0.1.0`); the
root module uses a plain tag (`v0.1.0`). `examples/bulk-ripe` is not tagged — it
is a harness, not a library — but its `require`s are bumped so it builds outside
the workspace. The root module's zip excludes the nested modules, and the Go
command adds the root `LICENSE` to each nested module's zip, so pkg.go.dev
detects the license everywhere.

**A published version is permanent.** Once the Go proxy has fetched a tag, that
version is cached forever and cannot be changed, only retracted. Rehearse first.

## Visibility

The proxy cannot fetch a private repository, so
`github.com/rkolesnichenko/rpsl` must stay public.

## Pre-flight

Every item must pass on the commit you are about to release.

1. `FUZZTIME=15s scripts/check.sh` — every module under `-race`, gofmt,
   staticcheck, govulncheck (CI installs them), the invariants, all fuzz targets.
2. `RPSL_REALDATA=$PWD/.data go test -run TestRealData ./examples/bulk-ripe/bulk`
   and, in `resolve`, `RPSL_REALDATA=$PWD/../.data go test -run TestBgpq4RealData .`
   (dumps via `scripts/fetch-irr-dumps.sh`).
3. `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve` and
   `RPSL_LIVE=1 go test -run TestRIPETemplatesAreCurrent ./object`.
4. **`scripts/release-dryrun.sh vX.Y.Z`**, with the version you are about to
   release (it refuses one that is already tagged), performs every step below in a
   temporary repository against a local proxy, builds and tests each module with
   `GOWORK=off`, checks that a consumer of each module gets only what it
   requires, runs each module's tests from its published zip, and lists the
   files each release commit must hold. It publishes nothing.
5. `CHANGELOG.md`: the release's section is dated (`## [X.Y.Z] - YYYY-MM-DD`)
   and linked at the bottom, and a new empty `## [Unreleased]` sits above it. Commit that, push `main`, and
   wait for CI to pass on it.

## Each release (example: v0.2.0)

Run every command from the repository root. Every `go mod tidy` runs with
`GOWORK=off`, so it resolves siblings from the proxy exactly as a consumer
would. Commit the `go.sum` files by name: they are new, and `git commit -am`
skips new files, which would publish a module that does not build. Never commit
`replace` directives.

```sh
V=v0.2.0   # the version you are releasing
M=github.com/rkolesnichenko/rpsl
export GOWORK=off

# 1. The leaves, which require no sibling.
git tag lexer/$V && git tag types/$V && git push origin lexer/$V types/$V
GOPROXY=https://proxy.golang.org go list -m $M/lexer@$V $M/types@$V   # the proxy fetches them

# 2. ast (requires lexer).
(cd ast && go mod edit -require=$M/lexer@$V && go mod tidy && go build ./... && go test ./...)
git add ast/go.mod ast/go.sum && git commit -m "ast: require lexer $V"
git tag ast/$V && git push origin main ast/$V
GOPROXY=https://proxy.golang.org go list -m $M/ast@$V

# 3. The root module (requires ast, lexer, types).
go mod edit -require=$M/ast@$V -require=$M/lexer@$V -require=$M/types@$V
go mod tidy && go build ./... && go test ./...
git add go.mod go.sum && git commit -m "rpsl: require the leaves at $V"
git tag $V && git push origin main $V
GOPROXY=https://proxy.golang.org go list -m $M@$V

# 4. resolve (requires the root module and the leaves).
(cd resolve && go mod edit -require=$M@$V -require=$M/ast@$V -require=$M/lexer@$V -require=$M/types@$V &&
    go mod tidy && go build ./... && go test ./...)
git add resolve/go.mod resolve/go.sum && git commit -m "resolve: require $V"
git tag resolve/$V && git push origin main resolve/$V
GOPROXY=https://proxy.golang.org go list -m $M/resolve@$V

# 5. The example module: not tagged, bumped so it builds outside the workspace.
(cd examples/bulk-ripe && for m in "" /ast /lexer /resolve /types; do go mod edit -require=$M$m@$V; done &&
    go mod tidy && go build ./... && go test ./...)
git add examples/bulk-ripe/go.mod examples/bulk-ripe/go.sum && git commit -m "examples: require $V"
git push origin main
```

`git status` must be clean after each commit. If a `go mod tidy` cannot find a
just-pushed tag, the proxy has not seen it yet: run the `go list -m` line for it
again.

## After

- pkg.go.dev picks the modules up from the proxy within minutes; request them at
  `https://pkg.go.dev/github.com/rkolesnichenko/rpsl@v0.1.0` (and `/lexer`,
  `/ast`, `/types`, `/resolve`) if they do not appear.
- A fresh consumer module that runs `go get github.com/rkolesnichenko/rpsl/types`
  must end up with only that module in its `go.mod` (leaf isolation); the dry run
  already checked this against the rehearsal proxy.
- Development continues through `go.work`, which overrides the released
  `require`s with the local modules.

## A broken release

A published version cannot be replaced. Add a `retract` directive for it to the
module's `go.mod`, fix the problem, and release the next patch version, which
carries the retraction.
