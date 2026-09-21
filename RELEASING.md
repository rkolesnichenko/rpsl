# Releasing

`rpsl` is six Go modules in one repository. Inside the repo they find each
other through `go.work`, with every inter-module `require` pinned at `v0.0.0`.
A consumer has no workspace, so each module must be tagged and its siblings'
`require`s bumped to real versions, **in dependency order**: a module can only be
tidied once the versions it requires are on the proxy.

```
lexer, types  →  ast  →  root (rpsl: façade, object, policy)  →  resolve  →  examples/bulk-ripe
```

Nested modules are tagged with their directory as a prefix (`lexer/v0.1.0`);
the root module uses a plain tag (`v0.1.0`). The root module's zip excludes the
nested modules, and Go copies the root `LICENSE` into each nested zip, so
pkg.go.dev detects the license everywhere.

## One-time setup

1. Create `github.com/rkolesnichenko/rpsl` on GitHub, add it as `origin`, and
   push `main`. CI (`.github/workflows/ci.yml`) starts running on that push.
2. Check the tree is clean and green: `FUZZTIME=15s scripts/check.sh`.

## Each release (example: v0.1.0)

Run every `go mod tidy` with `GOWORK=off`, so it resolves siblings from the
proxy exactly as a consumer would. Never commit `replace` directives.

```sh
V=v0.1.0

# 1. Leaves with no sibling dependencies.
git tag lexer/$V && git tag types/$V && git push origin lexer/$V types/$V

# 2. ast (requires lexer).
(cd ast && go mod edit -require=github.com/rkolesnichenko/rpsl/lexer@$V && GOWORK=off go mod tidy)
git commit -am "ast: require lexer $V" && git tag ast/$V && git push origin main ast/$V

# 3. Root module (requires ast, lexer, types).
go mod edit -require=github.com/rkolesnichenko/rpsl/ast@$V \
            -require=github.com/rkolesnichenko/rpsl/lexer@$V \
            -require=github.com/rkolesnichenko/rpsl/types@$V
GOWORK=off go mod tidy
git commit -am "rpsl: require leaves $V" && git tag $V && git push origin main $V

# 4. resolve (requires the root module and the leaves).
(cd resolve && go mod edit -require=github.com/rkolesnichenko/rpsl@$V \
    -require=github.com/rkolesnichenko/rpsl/ast@$V \
    -require=github.com/rkolesnichenko/rpsl/lexer@$V \
    -require=github.com/rkolesnichenko/rpsl/types@$V && GOWORK=off go mod tidy)
git commit -am "resolve: require $V" && git tag resolve/$V && git push origin main resolve/$V

# 5. The example module (optional tag; bump so it builds outside the workspace).
(cd examples/bulk-ripe && for m in rpsl rpsl/ast rpsl/lexer rpsl/resolve rpsl/types; do
    go mod edit -require=github.com/rkolesnichenko/$m@$V; done && GOWORK=off go mod tidy)
git commit -am "examples: require $V" && git push origin main
```

If `go mod tidy` cannot find a just-pushed tag, the proxy has not seen it yet:
request it once with `GOPROXY=https://proxy.golang.org go list -m <module>@$V`.

## Verify

```sh
for m in rpsl rpsl/lexer rpsl/ast rpsl/types rpsl/resolve; do
  GOPROXY=https://proxy.golang.org GOWORK=off go list -m github.com/rkolesnichenko/$m@$V
done
```

This also triggers pkg.go.dev indexing. A fresh consumer module that
`go get`s `github.com/rkolesnichenko/rpsl/types` should end up with only that
module in its `go.mod` (leaf isolation).

## Changelog

Move the `[Unreleased]` entries in `CHANGELOG.md` under `## [0.1.0] - <date>`
before tagging, and start a new empty `[Unreleased]` section.
