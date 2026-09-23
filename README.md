# rpsl

[![Go Reference](https://pkg.go.dev/badge/github.com/rkolesnichenko/rpsl.svg)](https://pkg.go.dev/github.com/rkolesnichenko/rpsl)
[![ci](https://github.com/rkolesnichenko/rpsl/actions/workflows/ci.yml/badge.svg)](https://github.com/rkolesnichenko/rpsl/actions/workflows/ci.yml)

A complete RPSL parser, type system, policy AST, and set-expansion engine for Go.

`rpsl` takes raw RPSL — the text of RIPE / ARIN / RADB IRR database objects — and
produces **typed, validated objects**, parses the `import:` / `export:` /
`default:` routing-policy grammar into a real **AST**, and expands set references
(`as-set`, `route-set`, …) into concrete **ASNs and prefixes**.

The existing Go option, [`frederic-arr/rpsl-go`](https://github.com/frederic-arr/rpsl-go),
deliberately stops at raw `key: value` extraction. Everything past the lexer —
value validation, the policy AST, and the expansion engine — is what this library
adds. It aims to do in Go what `bgpq4` plus a real RPSL object model do together,
but as an importable, testable package rather than a CLI.

Three RFCs define the surface area: **RFC 2622** (core RPSL), **RFC 2650** (using
RPSL in practice), and **RFC 4012** (RPSLng: `mp-*`, `route6`, the `afi`
dictionary, `except`/`refine`). Real RIPE/IRRd data deviates from the spec, so the
parser targets IRRd/RIPE reality with the RFCs as the skeleton.

## Status

Every layer ships. Until v1.0.0, a minor version may change the API; the
[changelog](CHANGELOG.md) says how, and v0.2.0 has a migration table.

| Layer | What it does | State |
| --- | --- | --- |
| `lexer` + `ast` | Tokenize, model and build objects; lossless byte-for-byte round-trip | shipped |
| `types` + `object` | Leaf value types and typed decoding for all 22 classes | shipped |
| `policy` | RFC 2622 §6 routing-policy parser → sealed-interface AST, and the §8.1/§9 attribute sub-grammars | shipped |
| `resolve` | Pure expansion engine for as-set, route-set, rtr-set, peering-set and filter-set, + in-memory, dump and caching `Source`s | shipped |
| `resolve/{irrd,whois,rdap}` | Live IRRd / WHOIS / RDAP backends | shipped |
| `auth` | RFC 2725 authorisation and RIPE's `mnt-irt:` consent, with cryptography injected | shipped |

RFC 4012 (RPSLng) is supported: `mp-import`/`mp-export`/`mp-default`, the `afi`
dictionary and `afi`-scoped policies (`Import`/`Export`/`Default`/`Except`/
`Refine` expose `AppliesTo`), `except`/`refine` — which `policy.Flatten`
resolves into the terms a policy denotes — `route6`, `mp-members`, and the
`interface:` and `mp-peer:` forms. RIPE's `import-via:` and `export-via:`
(draft-ietf-grow-rpsl-via) parse into the same AST, with the peering routes pass
through on each clause's `Via`. The expansion engine applies an
address-family constraint via `Expander.AFI`. A SAFI has no meaning in set
expansion — no set member carries one — so it applies only where RFC 4012 puts
it, in `Import`/`Export`/`Default.AppliesTo`.

Deliberately out of scope: evaluating AS-path regexps against live BGP paths
(they parse into their own AST and stop there), cryptographic verification of
`auth:` credentials (the `auth` package injects a `Verifier` instead), and the
RFC 2725 §7 update-transaction protocol.

## Install

Each leaf is its own module, so a minimal consumer pulls in only what it needs:

```sh
go get github.com/rkolesnichenko/rpsl          # façade + object + policy
go get github.com/rkolesnichenko/rpsl/types    # just the value types
go get github.com/rkolesnichenko/rpsl/resolve  # the expansion engine
```

Go 1.23+ is required (the streaming parser returns an `iter.Seq2`).

## Module map

Imports run strictly downward — `resolve → object → policy → types → ast → lexer`
— so a `types`-only consumer never transitively pulls in the resolver.

| Package | Import path | Role | Depends on |
| --- | --- | --- | --- |
| `rpsl` | `github.com/rkolesnichenko/rpsl` | Façade: `ParseObject`, `Parse` (streaming), `Decode`, `Validate` | `object`, `ast`, `lexer` |
| `object` | `…/rpsl/object` | Typed classes (`AutNum`, `Route`, `AsSet`, …) + `Decode` | `policy`, `types`, `ast` |
| `policy` | `…/rpsl/policy` | Routing-policy AST + `ParseImport`/`ParseExport`/`ParseDefault` (and `ParseMP*`, `ParseImportVia`/`ParseExportVia`) | `types`, `ast`, `lexer` |
| `types` | `…/rpsl/types` | Leaf value types: `ASN`, `SetName`, `PrefixRange`, `AddrFamily`, `NICHandle` | — |
| `ast` | `…/rpsl/ast` | Generic lossless `Object`/`Attribute` model; `Diagnostic`/`Severity` | `lexer` |
| `lexer` | `…/rpsl/lexer` | Hand-written scanner; total-partition `Tokenize` | — |
| `resolve` | `…/rpsl/resolve` | Pure expansion `Expander` + `Source` interface + `MemSource` | `object`, `types` |
| `resolve/irrd` | `…/rpsl/resolve/irrd` | `Source` over an IRRd query port (RADB/NTT/…) | `resolve`, `object` |
| `resolve/whois` | `…/rpsl/resolve/whois` | `Source` over plain WHOIS (RIPE-DB) | `resolve`, `object` |
| `resolve/rdap` | `…/rpsl/resolve/rdap` | RDAP registration client (not a `Source`) | `types` |

Per-module guides: [`lexer`](lexer/README.md) · [`ast`](ast/README.md) ·
[`types`](types/README.md) · [`resolve`](resolve/README.md).

## Quickstart

Parse one object, confirm the lossless round-trip, then decode it to a typed value:

```go
src := "aut-num: AS65001\n" +
	"as-name: EXAMPLE-AS\n" +
	"import:  from AS65002 accept ANY\n" +
	"mnt-by:  EXAMPLE-MNT\n" +
	"source:  RIPE\n"

obj, _ := rpsl.ParseObject(src)
fmt.Println(obj.String() == src) // true — byte-for-byte

decoded, _ := object.Decode(obj)
an := decoded.(object.AutNum)
fmt.Println(an.AS, an.MntBy) // AS65001 [EXAMPLE-MNT]
```

## Worked examples

The snippets below come from runnable `Example` tests
([`example_test.go`](example_test.go), [`policy/example_test.go`](policy/example_test.go),
[`resolve/example_test.go`](resolve/example_test.go)), so `go test` keeps them
honest. The live-source one needs the network; its counterpart,
[`resolve/irrd/example_test.go`](resolve/irrd/example_test.go), is compiled but
not run.

### Lossless round-trip

`ParseObject` is resilient: a malformed line produces a `Diagnostic` instead of
failing the whole object, and `String()` always reproduces the input exactly.

```go
obj, diags := rpsl.ParseObject(src)

fmt.Println("class:", obj.Class())
fmt.Println("key:", obj.Key())
fmt.Println("roundtrip:", obj.String() == src)
fmt.Println("diagnostics:", len(diags))
```

### Streaming a dump

`Parse` yields one object at a time over an `io.Reader`, holding only the current
object in memory — multi-gigabyte IRR dumps stream rather than load wholesale.

```go
for obj, diags := range rpsl.Parse(reader) {
	if len(diags) > 0 {
		// report and continue; partial results are the norm
	}
	fmt.Printf("%s %s\n", obj.Class(), obj.Key())
}
```

### Typed decode

`object.Decode` upgrades a generic object to its class type via a registry;
unknown classes degrade to `object.Generic` rather than erroring.

```go
decoded, diags := object.Decode(obj)
an := decoded.(object.AutNum)
fmt.Println(an.AS)       // AS65001
fmt.Println(an.Imports)  // []policy.Import — parsed, not raw strings
fmt.Println(an.MntBy)    // [EXAMPLE-MNT]
```

### Policy AST

`import:`/`export:` values are a small language. They parse into a sealed
interface hierarchy (`Expr`, `Filter`, `Peering`, `ASExpr`) — Go's stand-in for
sum types — which you walk with exhaustive type switches.

```go
imp, _ := policy.ParseImport("from AS65002 accept AS65002")
factor := imp.Expr.(policy.Factor)

if p, ok := factor.Peers[0].Peering.(policy.PeeringAS); ok {
	if as, ok := p.AS.(policy.ASNum); ok {
		fmt.Println("peer:", as.AS) // peer: AS65002
	}
}
if f, ok := factor.Filter.(policy.FilterASExpr); ok {
	if as, ok := f.AS.(policy.ASNum); ok {
		fmt.Println("accept:", as.AS) // accept: AS65002
	}
}
```

> AS-path regexps (`<...>`) are parsed into their own AST (`policy.ASPathRE`) but
> **not** evaluated against live BGP paths — that is a separate `bgp` consumer's
> job. Keeping them structured still lets you translate them to a router config.

### Set expansion (in memory)

The `resolve.Expander` is pure: no globals, no implicit network, all limits
explicit. All I/O goes through the injected `Source`, so the same engine runs
against an in-memory corpus in tests and a live backend in production.

```go
src := resolve.NewMemSource([]object.Object{
	decodeObject("as-set: AS-CONE\nmembers: AS1\nmembers: AS2\nsource: TEST\n"),
	decodeObject("route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"),
	decodeObject("route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n"),
})

e := &resolve.Expander{Src: src, AFI: types.AFIv4} // MaxDepth 32, MaxPrefixes 1<<20 by default

name, _ := types.ParseSetName("AS-CONE")
asns, _ := e.ExpandAS(context.Background(), name)        // [AS1 AS2]
prefixes, _ := e.ExpandPrefixes(context.Background(), name) // 10.0.0.0/8, 192.0.2.0/24
```

`ExpandPrefixes` enforces `MaxPrefixes` *during* enumeration and returns a typed
`*resolve.SetTooLargeError` rather than OOM-ing — real customer-cone as-sets expand
to hundreds of thousands of prefixes.

### Live source

To resolve against a real registry, swap the `Source` — the engine code is
identical:

```go
import "github.com/rkolesnichenko/rpsl/resolve/irrd"

irr := &irrd.Source{
	Addr:      "whois.radb.net:43",
	Sources:   []string{"RADB", "RIPE"}, // IRR precedence
	Timeout:   10 * time.Second,
	KeepAlive: true,         // pool persistent connections
}
defer irr.Close()

e := &resolve.Expander{Src: irr, AFI: types.AFIv4}
asns, err := e.ExpandAS(ctx, name)
```

See [`resolve/README.md`](resolve/README.md) for the WHOIS and RDAP backends and
their trade-offs.

## Design principles

1. **Lossless round-trip** at the syntactic layer — `Parse(text)` then
   `obj.String()` reproduces the input byte-for-byte. This is what makes the
   library usable for *editing* objects, not just reading them.
2. **Errors are values; parsing is resilient** — a malformed `import:` line never
   prevents reading `mnt-by:` on the same object. You get partial results plus
   `[]Diagnostic` with line/column spans, and the parser never panics on hostile
   input.
3. **The `Source` is injected, never hardcoded I/O** — the expansion engine is
   pure and context-cancellable, so the same code runs offline and live.
4. **Layered, independently shippable** — leaves are separate modules; minimal
   consumers stay dependency-light.

Full rationale: [`docs/rpsl-go-design.md`](docs/rpsl-go-design.md).

## Testing

The correctness bar is "matches the tools operators already trust," so testing is
differential and corpus-driven. The modules are separate, so `go test ./...`
covers only the root; run everything with:

```sh
scripts/check.sh               # every module: build, vet, test -race; gofmt; invariants
FUZZTIME=15s scripts/check.sh  # ... plus every fuzz target (what CI runs)
```

- **Lossless round-trip** — `go test -run TestRoundTrip .` for single objects,
  `TestStreamRoundTrip` and `FuzzParseStream` for streams.
- **Fuzz** (never panic, never drop input, and hold each parser's properties —
  see design §11): `FuzzTokenize` (lexer); `FuzzAttributeList`, `FuzzEdit`,
  `FuzzFormat` (ast); `FuzzParseSetName`, `FuzzParseRangeOperator`,
  `FuzzParsePrefixRange`, `FuzzParseRouterID` (types); `FuzzParseStream`,
  `FuzzDecode` (root); `FuzzParseImport`, `FuzzParseASPathRegexp`,
  `FuzzParseFilter`, `FuzzParsePeering`, `FuzzParseInject`,
  `FuzzParseComponents`, `FuzzParseAggrMtd`, `FuzzParseIfaddr`,
  `FuzzParseInterface`, `FuzzParsePeer`, `FuzzParseRPAttribute`,
  `FuzzParseTypedef`, `FuzzParseProtocol`, `FuzzFilterString` (policy).
- **Real data (opt-in)** — `scripts/fetch-ripe-dumps.sh` downloads RIPE split
  dumps; `RPSL_REALDATA=$PWD/.data/ripe go test -run TestRealData ./examples/bulk-ripe/bulk`
  checks lossless streaming, error rates, and order-independent expansion of the
  largest real sets.
- **Live backends (opt-in)** — `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve`
  queries RADB, RIPE and RDAP read-only;
  `RPSL_LIVE=1 go test -run TestRIPETemplatesAreCurrent ./object` checks that the
  RIPE profile's template fixtures still match whois.ripe.net.
- **Benchmarks** — every module benchmarks its hot paths on generated input;
  `scripts/bench.sh [ref]` compares the working tree with a ref (the latest
  release by default) on your machine, with `benchstat` when installed. With
  `RPSL_REALDATA` set, two more measure the RIPE dumps.
- **Expansion correctness** — every `go test` holds the engine and all three
  Sources to a brute-force model of RFC 2622 on thousands of random IRRs. With
  `bgpq4` installed, bgpq4 itself expands the same IRRs and the snapshot whose
  goldens are its output; the few known differences are pinned in
  `resolve/testdata/bgpq4/divergences.md`; on the RIPE dumps, 304 of 305 sampled
  sets expand exactly as bgpq4 expands them (the other hits bgpq4's `^n` bug).

## Releasing

The repo is a set of independent modules wired together for development by the
root `go.work` (`use`). Inter-module `require`s name the latest release, and the
workspace overrides them with the local directories, so:

- `go test ./...` only covers the root module; use `scripts/check.sh`.
- A change in one module is seen by the others at once; the `require`s are
  bumped only when releasing.

Publishing tags each module and bumps its siblings' `require`s in dependency
order (`lexer`, `types` → `ast` → root → `resolve`); the exact procedure is in
[`RELEASING.md`](RELEASING.md), and `scripts/release-dryrun.sh` rehearses it
end to end against a local proxy without publishing anything.

## Further reading

- GoDoc: [pkg.go.dev/github.com/rkolesnichenko/rpsl](https://pkg.go.dev/github.com/rkolesnichenko/rpsl)
- Design doc: [`docs/rpsl-go-design.md`](docs/rpsl-go-design.md)
- Diagnostic rules and severities: [`docs/diagnostics.md`](docs/diagnostics.md)
- RFCs: [2622](https://www.rfc-editor.org/rfc/rfc2622),
  [2650](https://www.rfc-editor.org/rfc/rfc2650),
  [4012](https://www.rfc-editor.org/rfc/rfc4012)

## License

[MIT](LICENSE) © 2026 R. Kolesnichenko.
