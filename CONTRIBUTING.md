# Contributing

Thanks for your interest in `rpsl`. This document covers what a contributor needs
to know to run the test suite, respect the library's non-negotiable invariants,
and submit changes. Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

- Go **1.23+** — the streaming parser returns an `iter.Seq2`, which is a 1.23
  language feature.
- A POSIX shell (`scripts/check.sh` runs the per-module loop; `go test ./...`
  alone covers only the root module).

## Repository layout

The repo is a Go workspace of six modules:

| Module | What's in it |
| --- | --- |
| ROOT (`.`) | `rpsl` façade, `object`, `policy`, `auth` |
| `lexer/` | scanner + tokens |
| `ast/` | generic object/attribute model + `Diagnostic`/`Severity` |
| `types/` | leaf value types (`ASN`, `SetName`, `PrefixRange`, `RangeOperator`, `AddrFamily`, `NICHandle`; prefixes are `netip.Prefix`) |
| `resolve/` | pure expansion engine + `Source` interface; `irrd`/`whois`/`rdap` backends; `internal/netconn` (socket deadlines, backends only) |
| `examples/bulk-ripe/` | GB-scale integration harness and the opt-in real-data regression |

Inter-module `require`s name the latest release, and the root
`go.work` (`use`) overrides them with the local directories, so a change in one
module is seen by the others at once, without a release. Leave the `require`s
alone: they are bumped only when releasing ([RELEASING.md](RELEASING.md)).

## Running tests

`go test ./...` only covers the ROOT module. Run everything — every module
under `-race`, gofmt, staticcheck/govulncheck when installed, and the
structural invariants — with:

```sh
scripts/check.sh
FUZZTIME=15s scripts/check.sh   # also runs every fuzz target (as CI does)
```

Per-target subsets you'll reach for often:

- **Lossless round-trip guard** (ROOT module): `go test -run 'TestRoundTrip|TestStreamRoundTrip' .`
- **A single fuzz target** (must never panic): e.g.
  `go test -run='^$' -fuzz='^FuzzParseImport$' -fuzztime=30s ./policy`
- **Expansion against a model and against bgpq4**: `go test -run 'TestModel|TestBgpq4|TestGolden' ./resolve`.
  The model oracle and backend equivalence always run; the bgpq4 differential
  and the check that the goldens under `resolve/testdata/golden` are bgpq4's
  output run when `bgpq4` is installed (`brew install bgpq4`, `apt install
  bgpq4`). After editing the snapshot, regenerate the goldens with
  `go test -run TestGoldensAreBgpq4Output -update ./resolve` and review the
  diff. Known differences from bgpq4 are pinned in
  `resolve/testdata/bgpq4/divergences.md`. With `RPSL_REALDATA` set,
  `TestBgpq4RealData` compares real RIPE sets too. CI installs Ubuntu's bgpq4
  (1.12) and Homebrew ships a newer one (1.16); the tests pass with both, so a
  failure that appears with only one version is a change in bgpq4. Pin it in
  `divergences.md` rather than editing the goldens to match.
- **A fuzz failure:** Go saves the failing input under the package's
  `testdata/fuzz/<Target>/`. Commit it with the fix: every `go test` replays it
  from then on.
- **Real-data regression** (opt-in): `scripts/fetch-irr-dumps.sh` downloads the
  public dumps of RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB and the ten IRRs RADB
  mirrors (about 480 MB) into `.data/`, then
  `RPSL_REALDATA=$PWD/.data go test -run TestRealData ./examples/bulk-ripe/bulk`
  checks them all. A registry's dump artefacts, the problems in its data too
  frequent for the error limit (names where a NIC handle belongs, in RADB and
  its mirrors), and any family whose limit it raises (TC's misused policies) are
  listed in the test with their reasons; anything else fails it.
- **Live backends** (opt-in, read-only): `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve`,
  and `RPSL_LIVE=1 go test -run TestRIPETemplatesAreCurrent ./object` for the
  RIPE templates the RIPE profile is built from (`object/testdata/ripe-templates`).
- **GB-scale integration harness:** `go run ./examples/bulk-ripe --json <dump>.gz`

## Performance

Every module has benchmarks (`bench_test.go`) for its hot paths: the lexer, the
stream, decoding and validation, the policy parser, and the expansion engine.
Their inputs are generated in code, so they need no data; the two in
`examples/bulk-ripe/bulk` measure the RIPE dumps and run only with
`RPSL_REALDATA` set. `scripts/check.sh` runs each once, so none can break
unnoticed, but it does not time them.

To see what a change costs, compare it with the last release, or any ref, on
your own machine:

```sh
scripts/bench.sh                  # the working tree against the latest release tag
scripts/bench.sh main             # ... or against any ref
BENCH=Stream COUNT=10 scripts/bench.sh
```

It runs the base ref in a temporary git worktree and compares the two with
[`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) when that is
installed. Timings are noisy: identical code can differ by several percent, so
reproduce a change before believing it. A change to a hot path should say what
`bench.sh` showed.

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
   `TestEveryAttributeLandsInItsOwnField` enforces this, and
   `TestAttributeTypesAgreeAcrossClasses` requires an attribute to decode to
   the same type in every class that has it.
5. **Imports run strictly downward.**
   `resolve → object → policy → types → ast → lexer`. Go forbids import cycles,
   but `object` and `policy` share the root module, so keep the direction by
   convention.
6. **Diagnostic rules are a contract.** A `Diagnostic.Rule` ID is stable API that
   callers filter on. Add a new rule to [`docs/diagnostics.md`](docs/diagnostics.md)
   with its severity: an Error means the value was dropped, a Warning that it
   was used anyway. `TestDiagnosticRulesAreDocumented` fails on a rule that is
   emitted but not listed, or listed but never emitted.

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
- Add a line to `CHANGELOG.md` under `## [Unreleased]` for any change a user of
  the library can see: API, behavior, a new or changed diagnostic rule.
- Updating `CLAUDE.md` or `docs/rpsl-go-design.md` is part of the change when
  the externally-observable behavior shifts. The design doc is the source of
  truth.

## Reporting bugs

Open an issue with the smallest reproducing input you can. For correctness
bugs in the engine, a snippet of the offending IRR object plus the expected
expansion is ideal; `bgpq4` output for the same set is good prior art for
"what matches what".
