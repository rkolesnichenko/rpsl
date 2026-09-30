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
- Net-using Source backends are isolated in `resolve/` sub-packages (irrd/whois/rdap/nrtm4) to keep core `resolve` socket-free.
- `resolve/peval` (policy evaluation for one BGP session) and `resolve/rtconfig` (router
  configuration from an evaluated policy: Cisco IOS/IOS-XE, Junos, Cisco IOS-XR, BIRD 2) sit
  beside `resolve`, pure like it — no `net` either. `resolve/internal/backend` (shared
  server/dump opening for rpslq and rpslconf), `resolve/internal/routemodel` (test-only
  AS-path-regexp-vs-path oracle), `resolve/internal/cfgsim` (test-only: reads router
  configuration and decides routes against it, the semantic oracle for `rtconfig`),
  `resolve/internal/buildinfo` (the version `-v` prints, for rpslq and rpslconf) and
  `resolve/internal/rpslconf` (the `rpslconf` command's logic, both modes; `resolve/cmd/rpslconf`
  is the shim) are internal packages alongside it.
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
- **Real data before "done"**: fixtures hold what the RFC says and registries write something else.
  Before calling a task done, run the opt-in real-data or live test that covers the changed code
  (Commands, below), and check one count and its denominator by hand against the dump.

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
- **Every set class expands**, from memory and over both live backends: as-set and route-set
  to ASNs/prefixes, rtr-set to routers, peering-set to peerings, filter-set through `EvalFilter`.
  `Source.GetSet` returns `object.NamedSet`; `nestedNames` + `nestable` decide what each class
  may nest. `checkSet` refuses a set of another name and treats one whose class is not its
  name's (`route-set: AS-EVIL`) as missing; never expand an object under its name's rules alone.
- **Filters are only partly enumerable**: `EvalFilter` handles ANY, prefix lists, set and AS
  references, OR and AND (range intersection) and returns `*NotEnumerableError` for NOT,
  PeerAS, community tests and AS-path regexps. Never answer one of those with an empty set.
- **`Expander.Exclude`** (bgpq4's EXCEPT): an excluded set is skipped in discovery (never
  fetched or Missing), an excluded AS is never fetched for routes; the named top set is always
  expanded. Checked against the model oracle over every backend. Exclusion never widens a
  normalized filter: `NormalizeFilter` applies it to positive prefix literals only. Negated
  literals and every PathMatch's Sets (either polarity — `<[^AS-A]>` rejects with AS-A) are
  evaluated with Exclude cleared, so an excluded AS or set cannot drop out of a deny side and
  become accepted. `peval` never applies it to peering or router matching (an excluded set on
  the right of an EXCEPT would widen the peering), only to clause filters.
- **`Expander.Concurrency` must not change a result.** Discovery fetches a whole breadth-first
  level at once and merges in the level's own order; `TestConcurrencyDoesNotChangeResults`
  compares serial and parallel over 200 random graphs.
- **RPKI (`resolve/rpki`) is IRRd 4's RPKI-aware mode**, validated against IRRd's own code
  and tests: RFC 6811 with AS0 covering but never matching; `Filter` suppresses route
  *objects* (OriginatedRoutes, route claimants), never a route-set's listed prefixes;
  `WriteRPSL` is IRRd's pseudo-object text byte for byte (fixture captured from RADB).
  irrtest's `WithRPKI` is an independent port — keep it independent of package rpki.
  Only RADB's and NTT's dumps are RPKI-filtered; the other mirrors on RADB's FTP are not.
- **NRTMv4 (`resolve/nrtm4`) verifies before it uses.** ES256 on the notification file (key
  rotation: current, then announced next, never the old again), SHA-256 on each file, headers
  against session/version, the delta chain contiguous from the version held — a delta applies
  whole or not at all, nothing after a refused one. Each version is published as a new immutable
  MemSource (one expansion = one version). `internal/nrtmtest` is an independent spec-following
  server; when a test fails, first check the fake server obeys the draft (it has twice broken §4.3).
- **`resolve.Corpus` is how loaders hold objects**: sets and `member-of:` claimants whole, other
  routes as (prefix, origin, source), the rest dropped — 460 MB for RIPE, not 3.7 GB. `Corpus.Source`
  and `NewMemSource` share `buildMemSource`; `TestCorpusMatchesMemSource` holds every answer equal.
  Don't retain decoded objects in a loader again.
- **Prefix-range operators** `^+ ^- ^n ^n-m`: first-class type with a capped `Materialize`.
- **Dict ↔ decoder agreement**: if `object/profiles.go` lists an attribute on a class, the
  matching `decodeXxx` in `object/classes.go` must read it. Drift silently drops data
  (as-set `mp-members` was exactly this).
- **Registry-scoped members** (draft-ietf-grow-rpsl-registry-scoped-members): `object.DirectMembers`
  is the one place the draft's member selection lives; the engine keys its graph by `types.SetRef`,
  so `RIPE::AS-X` and `AS-X` are two nodes. The scope never cascades (a node's nested refs come from
  its own object) and a scoped miss never falls back to precedence. `checkSet` refuses a scoped
  answer from another registry. `Corpus.SourceOf` restricts unscoped lookups and routes only.
- **`PolicySource`**: `Corpus.KeepPolicy` holds aut-nums and inet-rtrs as text (95 MB for RIPE),
  decoded per call — never decoded in memory (707 MB).
- **Policy evaluation (`resolve/peval`) never guesses.**
  - A term whose peering names a router the session does not give, a peering regexp, or a
    non-BGP4 protocol goes to `Undecided`.
  - An AS mismatch is no match, whatever the routers.
  - `NormalizeFilter` keeps regexps and community tests symbolic.
  - Negations stay inside a conjunct (`NotPrefixes`, `Negated`).
  - A filter-set holding a regexp is inlined once per polarity (memoized), or refused with an
    operator or on a cycle; a test repeated in a conjunct is kept once; every step is charged
    against MaxVisited, and MaxConjuncts caps both a disjunction's conjuncts and a conjunct's tests.
  - `EvalFilter` success ⇒ at most one pure conjunct.
  - Only test code matches a regexp against a path: `resolve/internal/routemodel` and the filter
    model's own Go translation (`goRE` in resolve/filter_model_test.go).
  - The filter model runs over MemSource only, with no set reaching AS-ANY; the policy model
    covers import:, export:, import-via: and default:, each with its mp- form (MemSource,
    KeepPolicy Corpus, irrd, whois). export-via: has table tests only.
- **Router configuration (`resolve/rtconfig`) never approximates.**
  - `ErrUnsupported` (an `*UnsupportedError` naming the vendor, a `Cause*` and the term) is
    refused before anything is written; `Write*` is all-or-nothing — the whole configuration, or
    none of it and the error.
  - Negations stay inside a clause's own list (a deny entry in its prefix/path/community list),
    never a separate deny rule at the policy level, so a route a negation rejects simply fails
    that clause's match and falls through to the next one.
  - Junos route-filters are checked by longest match, not first match, so `junosGroups` splits a
    clause's ranges into disjoint groups (no range nests another) and writes one term per group.
  - Every printer ends its policy with an explicit reject (IOS's numbered `deny`, Junos's
    catch-rest term, IOS-XR's bare `drop`, BIRD's trailing `reject;`), since the vendors' own
    default behavior when nothing matches differs.
  - BIRD needs parentheses around every test (`&&`/`||`/`=`/`~` share one precedence) and cannot
    merge two configuration blocks for one `protocol bgp`, so `WriteImport`/`WriteExport` only
    record a neighbour's filter names and `WriteSessions` writes one `protocol bgp` per neighbour,
    once, after every other call.
  - `resolve/internal/cfgsim` is the semantic oracle: it reads what `rtconfig` writes — and what
    IRRToolSet's `rtconfig` writes, for the differential — and decides synthetic routes against
    it, matching AS-path regexps against paths (test-only, like routemodel), so it must model
    each vendor's documented semantics, including rtconfig's own Junos policy-chain OR (D12).

## Scope guardrails

- Do NOT evaluate AS-path regexps (`<...>`) against live BGP paths — parse them to an AST and stop.
  That's a separate `bgp` consumer's job. Conflating them is how RPSL tools rot.
- Class/attribute dictionary is data-driven: ship a RIPE profile (RIPE's templates), an IRRd
  profile (IRRd 4's class tables, what RADB and its mirrors run), an ARIN profile (IRRd's
  tables for ARIN's five classes plus its generated created:, derived in code) and an
  RFC-strict profile.
  Real data deviates from the RFC; target IRRd/RIPE reality, validate against the chosen profile.

## Commands

- **`go test ./...` only covers the ROOT module** (rpsl, object, policy, auth). Run everything
  (all six modules incl. examples/bulk-ripe under -race, gofmt, invariants) with
  `scripts/check.sh`; `FUZZTIME=15s scripts/check.sh` also runs every fuzz target.
- `go test -run 'TestRoundTrip|TestStreamRoundTrip' .` — the lossless guard (root module).
- Fuzz (40 targets, must never panic): FuzzTokenize (lexer); FuzzAttributeList, FuzzEdit,
  FuzzFormat (ast); FuzzParseSetName, FuzzParseRangeOperator, FuzzParsePrefixRange,
  FuzzParseRouterID, FuzzParseSetRef (types); FuzzParseStream, FuzzDecode (root);
  FuzzParseSrcMember (object); FuzzParseImport,
  FuzzParseASPathRegexp, FuzzParseFilter, FuzzParsePeering, FuzzParseInject,
  FuzzParseComponents, FuzzParseAggrMtd, FuzzParseIfaddr, FuzzParseInterface, FuzzParsePeer,
  FuzzParseRPAttribute, FuzzParseTypedef, FuzzParseProtocol, FuzzFilterString,
  FuzzParseMPFilter (policy);
  FuzzReadFrame, FuzzParseMembers, FuzzParseRegistries (resolve/irrd); FuzzScanResponse (resolve/whois);
  FuzzAggregate (resolve/internal/filtergen); FuzzReadJSON, FuzzApplySLURM (resolve/rpki);
  FuzzParseNotification, FuzzReadDelta (resolve/nrtm4); FuzzCorpusDelete, FuzzNormalizeFilter (resolve);
  FuzzTranslateRegexp (resolve/rtconfig); FuzzParseTemplate (resolve/internal/rpslconf).
- Never slice a string at an offset found in a transformed copy of it (`strings.ToUpper` can
  lengthen UTF-8): v0.19.0 panicked on "ɐ" (2 bytes) → "Ɐ" (3). Match case-insensitively in place.
- Opt-in: `RPSL_REALDATA=$PWD/.data go test -run TestRealData ./examples/bulk-ripe/bulk`
  (RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB and RADB's ten mirrors, via scripts/fetch-irr-dumps.sh);
  `RPSL_LIVE=1 go test -run TestLiveSmoke ./resolve`;
  `RPSL_LIVE=1 go test -run 'TestRIPETemplatesAreCurrent|TestIRRdSourceIsCurrent' ./object`
  (RIPE profile vs whois -t; IRRd profile's fixture vs IRRd's latest release);
  `RPSL_REALDATA=$PWD/.data go test -run TestRealDataRPKI ./resolve/rpki` (every registry's
  routes vs NTT's VRPs; RADB's and NTT's filtered exports ≤1% invalid) and, with `RPSL_LIVE=1`
  too, `-run TestLive ./resolve/rpki` (Validate vs what RADB hides; pseudo-object rendering);
  `RPSL_LIVE=1 go test -run TestLiveRIPE ./resolve/nrtm4` (RIPE's NRTMv4 signature and newest delta),
  `RPSL_LIVE_NRTM=1 … -run TestLiveRIPEMirror` (a full RIPE mirror, ~400 MB);
  `RPSL_REALDATA=$PWD/.data go test -run TestRealDataPeval ./resolve` (a sample of RIPE's
  aut-nums, import/export evaluated toward every named peer in both families).
- `rpslq` (resolve/cmd/rpslq; logic in resolve/internal/rpslq, formats in resolve/internal/filtergen)
  is bgpq4 on this engine: bgpq4's getopt command line, every vendor/kind/shape, and -A as a
  node-for-node port of bgpq4's radix tree (filtergen/tree.go) — don't "improve" its
  aggregation or printers, they must stay bgpq4's. `TestRpslqMatchesBgpq4`,
  `TestRpslqVendorsMatchBgpq4`, `TestRpslqExceptMatchesBgpq4` and `TestTreeMatchesBgpq4` hold it to
  the bgpq4 binary byte for byte (and its refusals to bgpq4's); deliberate differences are
  pinned in resolve/testdata/bgpq4/divergences.md. rpslq-only options are long options
  (`-P` and `-c` are rpslq's two short exceptions, kept for compatibility): `-P` writes each
  entry as RPSL notation, `-c` sets concurrent queries in flight.
  Its IRRd queries use `irrd.Source.Pipeline` (one connection, many queries in flight).
- `rpslconf` (resolve/cmd/rpslconf; logic in resolve/internal/rpslconf) is IRRToolSet's
  `RtConfig`/`peval` on this engine, with both modes: template mode (default; reads an
  `@RtConfig` template from stdin, `-config` chooses cisco/junos/ciscoxr/bird) and peval mode
  (`-e`, `NormalFilter.String()` output). See docs/rpslconf.md.
  `TestPevalMatchesIRRToolSet` (resolve/peval_irrtoolset_test.go) and the rtconfig differential
  (`TestRtconfigMatches`, `TestRtconfigGoldens`, resolve/rtconfig_irrtoolset_test.go) run when
  `peval`/`rtconfig` are on PATH — `scripts/build-irrtoolset.sh` builds IRRToolSet 5.1.3 from
  source (CI does; natively on Linux, in Docker elsewhere) and installs them there, or
  `brew install irrtoolset` also gives both binaries, but its `rtconfig`'s arm64 build ignores
  its command line and always writes Cisco — the differential probes each vendor by its output
  and compares only the ones a given build actually produces. `RPSL_RTCONFIG_UPDATE=1` rewrites the rtconfig goldens
  (resolve/testdata/rtconfig/golden) from a live `rtconfig`; divergences D1–D17 are pinned in
  resolve/testdata/rtconfig/divergences.md. `bird -p` (resolve/internal/cfgsim.BIRDSyntax) checks
  a BIRD writer's output against the real parser when `bird` is installed; it is skipped otherwise.
- Releasing: `scripts/release.sh vX.Y.Z` does RELEASING.md's steps (tag order lexer/types → ast →
  root → resolve), waits for the proxy, verifies from an empty module cache, and resumes after a
  failure; it also builds rpslq's and rpslconf's binaries (5 platforms each, from the published
  module) and attaches them to the GitHub release. `docs/rpslq.md` is rpslq's page for bgpq4
  users. Rehearse first with
  `scripts/release-dryrun.sh` (runs release.sh against a bare repo and
  a local proxy; publishes nothing) — alone, not beside check.sh. Never query the proxy for an
  unpushed tag: it caches the miss for ~30 minutes.
- Performance: `scripts/bench.sh [ref]` compares benchmarks with a ref (default: latest tag).
- Leaf isolation: `cd types && go list -deps ./... | grep rkolesnichenko` must show only itself.
- Engine purity: `cd resolve && go list -deps . ./peval ./rtconfig` must NOT include `net`
  (sockets live only in resolve/irrd, resolve/whois, resolve/rdap).
- A `resolve`-module test that reads a file outside `resolve/` (a docs/*.md contract, such as
  `TestRpslconfDocs`) skips when `../../go.work` is absent: `resolve` publishes on its own, and
  release.sh step 6 tests that published zip from an empty module cache, where nothing outside
  the module exists to read.
- IRRd wire framing: `A<len>\n<payload>C\n` where `<len>` *includes* the payload's trailing
  newline (see `resolve/irrd/readframe_test.go`). After ReadFull(payload), the next ReadString
  consumes the `C\n` status line directly — there is no separator newline to skip.
