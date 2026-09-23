# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the modules follow [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API. The modules are released together, with the
same version (see [RELEASING.md](RELEASING.md)).

## [Unreleased]

## [0.2.0] - 2026-09-23

Closes the gaps between what v0.1.0 shipped and what the RFCs and this project's
own design document describe. The headline is that the policy AST and the
resolver now meet: `filter-set`, `peering-set` and `rtr-set` expand, and a
policy filter can be evaluated into the prefixes it denotes.

**This release changes types that shipped in v0.1.0.** See *Migrating from
v0.1.0* below; every change is a compile error, never a silent behaviour change.

### Added

- **`policy`** — the attribute sub-grammars that were raw text:
  - `ParseInject`, `ParseComponents`, `ParseAggrMtd`, `ParseASExpression` for
    the RFC 2622 §8.1 aggregation attributes, with a sealed `InjectCond` tree.
  - `ParseIfaddr`, `ParseInterface`, `ParsePeer` for the RFC 2622 §9 and
    RFC 4012 §4 `inet-rtr` attributes.
  - `ParseMntRoutes` for the RFC 2725 `mnt-routes:` scope.
  - `Dictionary`, `ParseRPAttribute`, `ParseTypedef`, `ParseProtocol` and the
    built-in `RFCDictionary` for the RFC 2622 §9 RP-attribute dictionary, plus
    `ParseImportWith`/`ParseExportWith`/`ParseDefaultWith` to check a policy's
    actions and protocol names against one. The plain `Parse*` are unchanged.
  - `String()` on the whole AST, rendering canonical RPSL. Every policy example
    in RFC 2622, 2650 and 4012 re-parses from its own rendering to the same AST.
  - `Flatten` resolves `EXCEPT` and `REFINE` into the plain (peering, actions,
    filter) terms a policy denotes (RFC 2622 §6.5-6.6); `Except` and `Refine`
    gained `Unscoped`/`AppliesTo`.
- **`object`** — typed decoding for `key-cert`, `dictionary`, `poem` and
  `poetic-form`, which used to fall back to `Generic`; `Auth`, `Timestamp`,
  `Changed`, `RtrSetMember` and their parsers; and the `NamedSet`,
  `RouterSet`, `PeeringGroup` and `FilterGroup` interfaces over the set classes.
- **`ast`** — `Builder` composes an object attribute by attribute, and
  `Object.Format` normalizes attribute alignment and name case. Formatting is
  the one sanctioned departure from losslessness and changes no parsed value.
- **`types`** — `RouterID` (an rtr-set member: an address or an inet-rtr name),
  and `PrefixRange.Contains`/`Intersect`.
- **`resolve`** — `ExpandRouters`, `ExpandPeerings`, `ExpandFilterSet` and
  `EvalFilter`, with `NotEnumerableError` for the filter terms that have no
  finite answer in prefixes (`NOT`, `PeerAS`, community tests, AS-path
  regexps); `Cache`, a concurrency-safe caching `Source` with single-flight and
  negative caching; `DumpLoader`/`LoadDump`/`LoadDumps` to expand against an IRR
  bulk dump with no network; and `Expander.Concurrency`, which fetches a whole
  breadth-first level at once without changing any result.
- **`auth`** — a new package for RFC 2725: the `Verifier` interface that
  cryptography plugs into, `CheckMntner`/`CheckMntners`, `ReferralChain`, and
  `RouteCreation`/`RouteAuthority`, which apply the §4 rule that creating a
  route needs permission from the object's own maintainers, the origin AS *and*
  the address space — the rule that stops a prefix hijack in an IRR.

### Changed

- Address-family scoping in the engine stays on `Expander.AFI`. On review, a
  SAFI cannot constrain set expansion — no RPSL set member carries one, and
  there is no multicast route class — so `policy.Import.AppliesTo` remains the
  only place a SAFI has meaning. The engine's documentation now says so.

### Migrating from v0.1.0

Attributes whose values are small languages now decode into those languages
rather than into strings:

| Class | Field | v0.1.0 | v0.2.0 |
| --- | --- | --- | --- |
| `Route`, `Route6` | `Pingable` | `[]string` | `[]netip.Addr` |
| | `Inject` | `[]string` | `[]policy.Inject` |
| | `Components` | `string` | `policy.Components` |
| | `AggrBndry` | `string` | `policy.ASExpr` |
| | `AggrMtd` | `string` | `policy.AggrMtd` |
| | `ExportComps` | `string` | `policy.Filter` |
| `InetRtr` | `Ifaddr` | `[]string` | `[]policy.Ifaddr` |
| | `Interface` | `[]string` | `[]policy.Interface` |
| | `Peers`, `MpPeers` | `[]string` | `[]policy.Peer` |
| `Mntner`, `Irt` | `Auth` | `[]string` | `[]object.Auth` |
| `RtrSet` | `Members`, `MpMembers` | `[]string` | `[]object.RtrSetMember` |
| `Common` | `Changed` | `[]string` | `[]object.Changed` |
| `Registry` | `Created`, `LastModified` | `string` | `object.Timestamp` |
| | `MntRoutes` | `[]string` | `[]policy.MntRoutes` |

Each new type keeps a `Raw` field (or `String()`) holding the value exactly as
written, so code that only wanted the text reads `.Raw` and is otherwise
unchanged.

`resolve.Source` now returns `object.NamedSet` rather than `object.Set`, so the
engine can fetch every set class. A Source that only serves as-sets and
route-sets needs no other change; a caller that used the returned value as an
`object.Set` adds a type assertion. `object.Set` itself is unchanged and still
carries `SetMembers`.

## [0.1.0] - 2026-09-22

The first release. There is no earlier version to migrate from.

### Added

- **`lexer`** — a hand-written, line-oriented scanner:
  - **Lossless.** Every byte of the input belongs to exactly one token, so
    joining the tokens reproduces the source.
  - **Folding.** Continuation lines are folded into the logical value, and
    segments map every byte of that value back to its source line and column.
  - **Shared line rules.** `IsBlankLine`, `StartsAttribute` and `CanonicalName`
    are the rules the streaming parser uses too.
- **`ast`** — the generic, lossless object model:
  - Ordered attributes; `String()` is byte-for-byte the source.
  - `GetFirst`, `GetAll`, `Has`, and comma-separated `List` items with offsets.
  - `Append` and `Set` edit an object without touching other bytes.
  - `Diagnostic` and `Severity`, with stable rule IDs.
- **`types`** — comparable value types built on `net/netip`, all with text and
  JSON forms:
  - `ASN`, in asplain and asdot.
  - `SetName`: hierarchical, validated and canonical, so it is safe in a query.
  - `PrefixRange`: `^+ ^- ^n ^n-m`, canonical, with a lazy `All` and a capped
    `Materialize`.
  - `RangeOperator`, whose `Apply` composes operators by RFC 2622 §2.
  - `AddrFamily` (the RFC 4012 `afi` dictionary) and `NICHandle`.
- **`object`** — typed decoding of `aut-num`, `mntner`, `person`, `role`,
  `route`, `route6`, `as-set`, `route-set`, `peering-set`, `filter-set`,
  `rtr-set`, `inet-rtr`, `inetnum`, `inet6num`, `as-block`, `irt`, `domain` and
  `organisation`:
  - **Every attribute is typed.** The RFC 2622 common attributes are embedded as
    `Common`, RIPE's cross-class ones as `Registry`, and every attribute a
    profile lists has its own field.
  - **Decoding is per attribute.** A value that cannot be read is an Error
    diagnostic and is left out, and a suspect value is a Warning; the rules are
    listed in `docs/diagnostics.md`. Other classes decode to `Generic`.
  - **Validation profiles.** `RIPE` is RIPE's own templates, checked against
    whois.ripe.net by an opt-in test. `RFCStrict` follows RFC 2622, 2725, 2726
    and 4012. `NewProfile` builds custom profiles.
- **`policy`** — `import`, `export`, `default` and their `mp-` forms (RFC 2622
  §5–6, RFC 4012):
  - **A sealed AST:** factors, `{…}` lists, `except` and `refine`,
    peerings with AS and router expressions, filters (prefix lists, sets,
    templates, `PeerAS`, community tests, boolean operators), actions, and
    AS-path regexps parsed into their own tree.
  - **`afi` scoping,** exposed through `AppliesTo`.
  - **Diagnosed, never dropped.** Every value is fully consumed or diagnosed at
    the offending token.
  - **Bounded.** Tokens, diagnostics and nesting depth are capped.
  - **The RFCs' own examples.** All 124 policy examples in RFC 2622, 2650 and
    4012 parse, except RFC 2622's `NOT` in a peering: its own grammar lacks it,
    and the parser points to `EXCEPT` instead.
- **`rpsl`** — the façade:
  - `ParseObject`.
  - `Parse`/`ParseWith`: a lazy, lossless, resumable `iter.Seq2` stream for
    multi-GB dumps. Memory is capped (`MaxObjectBytes`, `MaxObjectLines`), and
    positions are relative to the stream.
  - `Decode` and `Validate`.
- **`resolve`** — a pure expansion engine: `ExpandAS`, `ExpandPrefixRanges` and
  `ExpandPrefixes` over an injected `Source`.
  - **Membership.** Direct members are joined with indirect ones. `mbrs-by-ref`
    is honored with the maintainer check and only for claims from the set's own
    source (`ClaimAllowed`).
  - **RFC semantics.** Class rules decide which nestings are followed. Range
    operators compose along every path, and cycles through them reach the RFC's
    fixpoint. The address-family constraint applies throughout.
  - **Limits.** `MaxDepth`, `MaxPrefixes` and `MaxVisited` each return
    `SetTooLargeError`, and none truncates a result.
  - **Missing sets.** Missing nested sets are reported by `Missing()`.
  - **Sources.** `MemSource` holds an in-memory IRR, with source precedence.
- **`resolve/irrd`, `resolve/whois`** — `Source`s over an IRRd query port and
  over whois (RIPE and IRRd servers):
  - source priority;
  - per-query timeouts;
  - response caps;
  - a connection pool (irrd);
  - a missing set is `ErrNotFound` and a server error is an error, never an
    empty result.
- **`resolve/rdap`** — RDAP registration lookups for AS numbers and IP
  networks, with a dial-time guard against internal addresses, timeouts and
  rate-limit errors.
- **Tests and tools:**
  - **Correctness checks.** A brute-force model oracle holds the engine and all
    three `Source`s to RFC 2622. A differential against bgpq4 runs when bgpq4 is
    installed, and the snapshot's golden expansions are bgpq4's output.
  - **Fuzzing.** Twelve fuzz targets check properties, not only panics.
  - **Opt-in runs.** Real-data regression over the RIPE dumps
    (`RPSL_REALDATA`) and live checks (`RPSL_LIVE`).
  - **Scripts.** `scripts/check.sh` runs all of the above; `examples/bulk-ripe`
    is a GB-scale harness; `scripts/release-dryrun.sh` rehearses a release.

### Known limitations

- **AS-path regexps are parsed, not evaluated.** Matching them against BGP
  paths is a BGP consumer's job.
- **bgpq4 disagrees in a few places,** listed in
  `resolve/testdata/bgpq4/divergences.md`:
  - bgpq4 drops the single-length `^n` form (a bgpq4 bug);
  - IRRd and bgpq4 do not apply range operators on set and AS members;
  - bgpq4 follows route-sets listed in as-sets;
  - the engine refuses `AS-ANY`.
- **Some sets exceed the default `MaxPrefixes`** (2^20). Bogon and martian lists
  such as `0.0.0.0/0^+` denote more prefixes than that, so `ExpandPrefixes`
  returns `SetTooLargeError` for them; `ExpandPrefixRanges` returns their ranges.
- **Router labels warn.** A single-label router name such as `PEERING` is a
  Warning, since it cannot name a router.
- **Some values stay raw strings.** `import-via`, `export-via` and most action
  values do; a few common RP-attributes have typed helpers.
- **`rdap` is not a `Source`.** RDAP serves registration data, not IRR sets.

[Unreleased]: https://github.com/rkolesnichenko/rpsl/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rkolesnichenko/rpsl/releases/tag/v0.1.0
