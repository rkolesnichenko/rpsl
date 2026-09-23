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
  lexer/  ast/  types/  object/  policy/  resolve/  auth/  rpsl.go
```
Publish leaves as independently `go get`-able modules. Keep import direction strictly downward:
resolve → object → policy → types → ast → lexer (never the reverse).

**As-built module reality (diverges from the flat tree above):**
- Separate go-get modules: `lexer`, `ast`, `types`, `resolve`. `object`, `policy`, `auth` and
  the top-level `rpsl` façade live in the ROOT module. Wired for dev by a root `go.work` (`use`).
- Inter-module requires name the latest release (v0.1.0); the `go.work` `use` set overrides them
  with the local directories, so edits are seen across modules at once. Bump them only when releasing.
- `Diagnostic`/`Severity` live in the `ast` module (so `object` can emit them); `rpsl` re-exports via aliases.
- Net-using Source backends are isolated in `resolve/` sub-packages (irrd/whois/rdap) to keep core `resolve` socket-free.
- Tests use in-process fake servers over a localhost listener + a `Dial` hook (no real network);
  the bgpq4 differential runs bgpq4 against an in-process IRRd (`resolve/internal/irrtest`) when bgpq4
  is installed; the snapshot goldens are its checked-in output; a live diff is opt-in via env vars.

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
  A claim must also come from the set's own `source:` (maintainer names are per-registry; IRRd agrees).
- **Cycle detection**: as-sets reference each other cyclically. DFS with a visited set keyed by
  canonical set name; revisit = skip, not error (matches bgpq4).
- **Fan-out guards**: enforce `MaxPrefixes` *during* enumeration by streaming ranges through
  `PrefixRange.All()` into a deduplicating set (duplicates are free; no `remaining+1` arithmetic).
  `MaxVisited` caps distinct sets fetched; `MaxDepth` caps the *shortest* nesting distance
  (breadth-first discovery, so results never depend on member order). All three return
  `SetTooLargeError{Limit}`; none truncates silently.
- **Range operators on members** (`RS-FOO^+`, `AS1^24`) compose along each path via
  `RangeOperator.Apply`. Evaluation states are (set, operator stack) with stacks compared by effect
  (`resolve/opstack.go`), so cycles through operators reach the RFC fixpoint; there is no cyclic-operator error.
- **AFI constraint**: v4 expansion drops route6/IPv6 mp-members and vice versa; `any` means both.
  A *SAFI* cannot constrain set expansion (no set member carries one, and there is no multicast
  route class), so `Expander.AFI` stays an `AFI`; SAFI applies only in `policy.*.AppliesTo`.
- **Every set class expands**: as-set and route-set to ASNs/prefixes, rtr-set to routers,
  peering-set to peerings, filter-set through `EvalFilter`. `Source.GetSet` returns
  `object.NamedSet`; `nestedNames` + `nestable` decide what each class may nest.
- **Filters are only partly enumerable**: `EvalFilter` handles ANY, prefix lists, set and AS
  references, OR and AND (range intersection) and returns `*NotEnumerableError` for NOT,
  PeerAS, community tests and AS-path regexps. Never answer one of those with an empty set.
- **`Expander.Concurrency` must not change a result.** Discovery fetches a whole breadth-first
  level at once and merges in the level's own order; `TestConcurrencyDoesNotChangeResults`
  compares serial and parallel over 200 random graphs.
- **Prefix-range operators** `^+ ^- ^n ^n-m`: first-class type with a capped `Materialize`.
- **Dict ↔ decoder agreement**: if `object/profiles.go` lists an attribute on a class, the
  matching `decodeXxx` in `object/classes.go` must read it. Drift silently drops data
  (as-set `mp-members` was exactly this).

## Scope guardrails

- Do NOT evaluate AS-path regexps (`<...>`) against live BGP paths — parse them to an AST and stop.
  That's a separate `bgp` consumer's job. Conflating them is how RPSL tools rot.
- Class/attribute dictionary is data-driven: ship a RIPE profile and an RFC-strict profile.
  Real data deviates from the RFC; target IRRd/RIPE reality, validate against the chosen profile.

## Commands

- **`go test ./...` only covers the ROOT module** (rpsl, object, policy, auth). Run everything
  (all six modules incl. examples/bulk-ripe under -race, gofmt, invariants) with
  `scripts/check.sh`; `FUZZTIME=15s scripts/check.sh` also runs every fuzz target.
- `go test -run 'TestRoundTrip|TestStreamRoundTrip' .` — the lossless guard (root module).
- Fuzz (24 targets, must never panic): FuzzTokenize (lexer); FuzzAttributeList, FuzzEdit,
  FuzzFormat (ast); FuzzParseSetName, FuzzParseRangeOperator, FuzzParsePrefixRange,
  FuzzParseRouterID (types); FuzzParseStream, FuzzDecode (root); FuzzParseImport,
  FuzzParseASPathRegexp, FuzzParseFilter, FuzzParsePeering, FuzzParseInject,
  FuzzParseComponents, FuzzParseAggrMtd, FuzzParseIfaddr, FuzzParseInterface, FuzzParsePeer,
  FuzzParseRPAttribute, FuzzParseTypedef, FuzzParseProtocol, FuzzFilterString (policy).
- Opt-in: `RPSL_REALDATA=$PWD/.data go test -run TestRealData ./examples/bulk-ripe/bulk`
  (RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB dumps via scripts/fetch-irr-dumps.sh);
  `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve`;
  `RPSL_LIVE=1 go test -run TestRIPETemplatesAreCurrent ./object` (RIPE profile vs whois -t).
- Releasing: RELEASING.md (tag order lexer/types → ast → root → resolve); rehearse first with
  `scripts/release-dryrun.sh` (local proxy, publishes nothing).
- Performance: `scripts/bench.sh [ref]` compares benchmarks with a ref (default: latest tag).
- Leaf isolation: `cd types && go list -deps ./... | grep rkolesnichenko` must show only itself.
- Engine purity: `cd resolve && go list -deps .` must NOT include `net` (sockets live only
  in resolve/irrd, resolve/whois, resolve/rdap).
- IRRd wire framing: `A<len>\n<payload>C\n` where `<len>` *includes* the payload's trailing
  newline (see `resolve/irrd/readframe_test.go`). After ReadFull(payload), the next ReadString
  consumes the `C\n` status line directly — there is no separator newline to skip.
