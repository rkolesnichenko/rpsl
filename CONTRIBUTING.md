# Contributing

Thanks for your interest in `rpsl`. This document covers what a contributor needs
to know to run the test suite, respect the library's non-negotiable invariants,
and submit changes.

## Prerequisites

- Go **1.23+** — the streaming parser returns an `iter.Seq2`, which is a 1.23
  language feature.
- A POSIX shell (`scripts/check.sh` runs the per-module loop; `go test ./...`
  alone covers only the root module).

## Repository layout

The repo is a Go workspace of six modules:

| Module | What's in it |
| --- | --- |
| ROOT (`.`) | `rpsl` façade, `object`, `policy` |
| `lexer/` | scanner + tokens |
| `ast/` | generic object/attribute model + `Diagnostic`/`Severity` |
| `types/` | leaf value types (`ASN`, `SetName`, `PrefixRange`, `RangeOperator`, `AddrFamily`, `NICHandle`; prefixes are `netip.Prefix`) |
| `resolve/` | pure expansion engine + `Source` interface; `irrd`/`whois`/`rdap` backends; `internal/netconn` (socket deadlines, backends only) |
| `examples/bulk-ripe/` | GB-scale integration harness and the opt-in real-data regression |

Inter-module `require`s are pinned at `v0.0.0` and resolve via the root
`go.work` (`use`). `go work sync` **fails** by design: it tries to fetch the
sibling modules from GitHub. Ignore it; the workspace is the source of truth
locally.

## Running tests

`go test ./...` only covers the ROOT module. Run everything — every module
under `-race`, gofmt, staticcheck/govulncheck when installed, and the
structural invariants — with:

```sh
scripts/check.sh
FUZZTIME=15s scripts/check.sh   # also runs all nine fuzz targets (as CI does)
```

Per-target subsets you'll reach for often:

- **Lossless round-trip guard** (ROOT module): `go test -run 'TestRoundTrip|TestStreamRoundTrip' .`
- **A single fuzz target** (must never panic): e.g.
  `go test -run='^$' -fuzz='^FuzzParseImport$' -fuzztime=30s ./policy`
- **Golden expansions**: hand-checked expectations for a synthetic snapshot
  under `resolve/testdata/`, run on every `go test`. The optional live `bgpq4`
  diff is gated on `RPSL_BGPQ4_SERVER` / `RPSL_BGPQ4_SET`.
- **Real-data regression** (opt-in): `scripts/fetch-ripe-dumps.sh`, then
  `RPSL_REALDATA=.data/ripe go test -run TestRealData ./examples/bulk-ripe/bulk`.
- **Live backends** (opt-in, read-only): `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve`.
- **GB-scale integration harness:** `go run ./examples/bulk-ripe --json <dump>.gz`

## Non-negotiables

These are the invariants that make the library trustworthy. Don't relax them to
make a change pass:

1. **Lossless round-trip.** `rpsl.ParseObject(text).String() == text` must hold
   byte-for-byte for everything in `testdata/corpus/`. The corpus is the guard;
   adding a fixture that demonstrates a new case is welcome, removing one is
   not.
2. **Parsing is resilient.** Bad input produces a `Diagnostic`, not a panic.
   Fuzz targets enforce this.
3. **The engine is pure.** `cd resolve && go list -deps .` must not include
   `net`. All sockets live in `resolve/irrd`, `resolve/whois`, and
   `resolve/rdap`. Any new I/O belongs in a backend subpackage.
4. **Dict ↔ decoder agreement.** If `object/profiles.go` lists an attribute on a
   class, the matching `decodeXxx` must surface it on the typed struct.
   Otherwise data is silently dropped on `Decode`.
   `TestDecoderSurfacesEveryProfiledAttribute` enforces this.
5. **Imports run strictly downward.**
   `resolve → object → policy → types → ast → lexer`. Go forbids import cycles,
   but `object` and `policy` share the root module, so keep the direction by
   convention.

## Style

- Hand-written lexer / recursive-descent parser. No parser generators
  (goyacc, participle); the grammar is small and error recovery matters more
  than generation.
- `net/netip` for every IP type. No `net.IP` or `net.IPNet` in new code.
- Order is significant in RPSL (e.g. `import:` precedence). Store attributes as
  a slice, never a map; preserve document order in any accessor.
- Comparable value types (`ASN`, `SetName`, `PrefixRange`, `RangeOperator`,
  `netip.Prefix`) so they work as map keys and in tests.
- Treat the policy AST as sealed interfaces (`isExpr()`, `isFilter()` etc.). Use
  exhaustive type switches; document any new variant on the sealed interface
  itself.

## Commit and PR conventions

- Branch from `main`. Keep the branch focused; small PRs review faster.
- `scripts/check.sh` must pass before merge.
- Updating `CLAUDE.md` or `docs/rpsl-go-design.md` is part of the change when
  the externally-observable behavior shifts. The design doc is the source of
  truth.

## Reporting bugs

Open an issue with the smallest reproducing input you can. For correctness
bugs in the engine, a snippet of the offending IRR object plus the expected
expansion is ideal; `bgpq4` output for the same set is good prior art for
"what matches what".
