# rpsl — RPSL parser, type system, and set-expansion engine for Go

Full design and rationale: @docs/rpsl-go-design.md
Read it before making architectural decisions. It is the source of truth; this file is the operating contract.

## What we're building

A Go library that parses raw RPSL (RIPE/ARIN/RADB IRR objects) into typed, validated objects,
parses the `import`/`export`/`default` policy grammar into a real AST, and expands set references
(`as-set`, `route-set`, …) into concrete ASNs and prefixes. The differentiators are the policy AST
(design §7) and the expansion engine (design §8) — not the lexer.

## Non-negotiable principles (design §1)

1. **Lossless round-trip at the syntactic layer.** `Parse(text)` then `obj.String()` must reproduce
   the input byte-for-byte (only opt-in normalization may change it). There is a golden-corpus test
   that enforces this; never weaken it to make a change pass.
2. **Errors are values; parsing is resilient.** A malformed `import:` line must NOT prevent reading
   `mnt-by:` on the same object. Return partial results plus `[]Diagnostic` with line/col spans.
   The parser must never panic on hostile input — diagnose instead.
3. **The resolver is an injected interface, never hardcoded I/O.** The expansion engine
   (`resolve`) is pure: no globals, no implicit network, context-cancellable, all limits explicit.
   All I/O goes through the `Source` interface so the same engine runs against an in-memory corpus
   in tests and live IRR/RDAP in production.
4. **Layered, independently shippable.** Leaf packages must not depend on heavier ones. A consumer
   of `rpsl/types` must not transitively pull in `rpsl/resolve`.

## Module layout (design §2)

```
rpsl/
  lexer/    ast/    types/    object/    policy/    resolve/    rpsl.go
```
Publish leaves as independently `go get`-able modules. Keep import direction strictly downward:
resolve → object → policy → types → ast → lexer (never the reverse).

**As-built module reality (diverges from the flat tree above):**
- Separate go-get modules: `lexer`, `ast`, `types`, `resolve`. `object`, `policy`, and the
  top-level `rpsl` façade live in the ROOT module. Wired for dev by a root `go.work` (`use`).
- Inter-module requires use `v0.0.0`; `go work sync` FAILS (tries to fetch them from GitHub) —
  ignore it, the `go.work` `use` set resolves locally and the per-module loop is the source of truth.
- `Diagnostic`/`Severity` live in the `ast` module (so `object` can emit them); `rpsl` re-exports via aliases.
- Net-using Source backends are isolated in `resolve/` sub-packages (irrd/whois/rdap) to keep core `resolve` socket-free.
- Tests use in-process fake servers over a localhost listener + a `Dial` hook (no real network);
  the bgpq4 differential is a checked-in golden snapshot, with an opt-in live diff gated on env vars.

## Build order — work strictly in this sequence (design §12)

1. **lexer + ast + lossless round-trip + golden-corpus harness.** ← START HERE. Shippable alone.
2. types + object typed decoding for non-policy classes (mntner, person, role, route, route6,
   raw set members).
3. policy parser for import/export/default (RFC 2622 §6) — recursive descent, good error recovery.
4. RFC 4012: mp-*, afi dictionary, except/refine, route6.
5. resolve engine + in-memory Source + differential tests vs bgpq4.
6. Live/IRRd/RDAP Source backends.

Do not start a milestone before the previous one's tests are green. Stop-and-ship after 1, 2, 5.

## Go conventions

- Target Go 1.23+. Use `iter.Seq2` for streaming object parsing (IRR dumps are multi-GB; parse lazily).
- All IP/prefix types build on `net/netip` (interop with `bart`/`netipx`). No `net.IP`/`net.IPNet`
  in new code.
- Hand-written lexer and recursive-descent policy parser. NO parser generators (goyacc/participle):
  the grammar is small and error recovery matters more than generation.
- Model the policy AST as sealed interfaces (`isExpr()`, `isFilter()` unexported marker methods) —
  Go's stand-in for sum types. Exhaustive type switches over them.
- Ordering is significant: store attributes as a slice, never a map. `GetAll` preserves document order.
- Comparable value types where possible (ASN, Prefix) so they work as map keys and in tests.

## Testing (design §11) — treat as part of "done"

- **Golden round-trip corpus**: real objects in `testdata/corpus/`; assert `Parse → String` is byte-identical.
- **Policy-AST table tests** straight from the RFC 2622/4012 examples.
- **Differential expansion vs bgpq4**: fixed offline IRR snapshot; diff our prefix/ASN sets against
  `bgpq4 -j`. Divergence = a bug to root-cause (possibly in bgpq4).
- **Fuzz** (`go test -fuzz`) the lexer and policy parser. Must never panic.
- **Property tests** for the engine: synthetic cyclic/deep set graphs verify cycle handling and limits.

## Engine correctness traps — get these right (design §8, §10)

- **Dual membership**: union direct `members:`/`mp-members:` WITH indirect `member-of:` claims, but
  honor `mbrs-by-ref:` + the mntner check. Skipping the mntner check is a silent, hijack-relevant bug.
- **Cycle detection**: as-sets reference each other cyclically. DFS with a visited set keyed by
  canonical set name; revisit = skip, not error (matches bgpq4).
- **Fan-out guard**: real customer-cone as-sets expand to >100k prefixes. Enforce `MaxPrefixes`
  *during* enumeration; return typed `ErrSetTooLarge`, never OOM.
- **AFI constraint**: v4 expansion drops route6/IPv6 mp-members and vice versa; `any` means both.
- **Prefix-range operators** `^+ ^- ^n ^n-m`: first-class type with a capped `Materialize`.

## Scope guardrails

- Do NOT evaluate AS-path regexps (`<...>`) against live BGP paths — parse them to an AST and stop.
  That's a separate `bgp` consumer's job. Conflating them is how RPSL tools rot.
- Class/attribute dictionary is data-driven: ship a RIPE profile and an RFC-strict profile.
  Real data deviates from the RFC; target IRRd/RIPE reality, validate against the chosen profile.

## Commands

- **`go test ./...` only covers the ROOT module** (rpsl, object, policy). Each leaf
  is a separate module, so run the full suite with a per-module loop:
  `for m in . lexer ast types resolve; do (cd "$m" && go build ./... && go vet ./... && go test ./...); done`
- `go test -run TestRoundTrip ./...` — the lossless guard (root module).
- Fuzz (must never panic): `go test -run=xxx -fuzz=FuzzTokenize ./lexer`,
  `-fuzz=FuzzParseImport ./policy`, `-fuzz=FuzzParseASPathRegexp ./policy`.
- Leaf isolation: `cd types && go list -deps ./... | grep rkolesnichenko` must show only itself.
- Engine purity: `cd resolve && go list -deps .` must NOT include `net` (sockets live only
  in resolve/irrd, resolve/whois, resolve/rdap).
