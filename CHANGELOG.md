# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the modules follow [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API. The modules are released together, with the
same version (see [RELEASING.md](RELEASING.md)).

## [Unreleased]

## [0.9.0] - 2026-09-24

### Fixed

- **The live backends expand every set class.** `irrd.Source` built a
  route-set from `!i` for any class but as-set, so `ExpandRouters` and
  `ExpandPeerings` of an existing rtr-set or peering-set returned nothing with
  no error, and a filter-set failed with `ErrSetClass`; `whois.Source` asked
  only for as-sets and route-sets and reported the others not found, and never
  saw inet-rtr claims. irrd now fetches those sets with `!m`, and whois asks
  for the set's own class and for the claimant classes that may join it.
- **The engine checks the set a `Source` returns.** A set whose class is not
  its name's (`route-set: AS-EVIL`) was expanded under its name's rules, so an
  as-set could pull in prefixes no route object backs, and route claims. Such
  a set is now missing; a set of another name than the one asked for is an
  error.
- **A filter-set named twice in one evaluation denoted nothing the second
  time** (`FLTR-A AND FLTR-A` was empty). Filter-set values are memoized per
  call, and a cycle of filter-sets is solved to the least fixpoint.
- **`policy.Flatten` honours the afi clause of `except` and `refine`**
  (RFC 4012 §2.5). An IPv6-scoped exception used to exclude routes from the
  IPv4 terms too.
- **A `Cache` waiter is not failed by another caller's cancellation**: one
  cancelled expansion failed every concurrent one sharing the lookup.

### Security

- **`EvalFilter` is bounded.** `AND` compared every pair of ranges and never
  checked its context (28 s past a 100 ms deadline, then an empty answer with
  no error); it now tests each range only against its prefix's ancestors and
  descendants, checking the context. Every set reference ran its own
  expansion with a fresh `MaxVisited`, about MaxVisited² fetches in all; one
  budget now covers the call, and each set is expanded once.
- **`policy.Flatten` is bounded.** Each level of an `except` chain doubles the
  filters: a 613-byte value rendered to 151 MB. Past `MaxFlattenNodes` it
  returns `ErrFlattenTooLarge`.
- **Backend responses cost less.** `MaxResponse` defaults to 32 MiB in `irrd`
  and `whois` (was 256 MiB), over twenty times the largest real answer; whois
  blanks `%` lines in place instead of allocating 28 times the response.
- **`ast.Object.Set` is linear.** Removing many duplicates with comments
  between them was quadratic: minutes for an object within the stream's cap.
- **Warnings for over-long lines outside objects are bounded**: two per run,
  not one per line, so a small `MaxObjectBytes` keeps memory bounded.
- **The `Cache` LRU is O(1)**: a lookup scanned the whole recency list under
  the cache's lock (4.2 s through a cache against 42 ms without, for a
  50,000-member set).

### Changed

- **`policy.Flatten(e, af) ([]Term, error)`** flattens for one address family
  and can fail; it was `Flatten(e) []Term`. `Import.Terms(af)` and
  `Export.Terms(af)` flatten a policy and give no terms where it does not
  apply.
- **A cycle of filter-sets denotes the least fixpoint**, as one of route-sets
  does, where a back-edge used to contribute nothing.
- `Except.AppliesTo` and `Refine.AppliesTo` are documented as what they report:
  whether the node's own afi clause admits a family.

### Added

- `policy.ErrFlattenTooLarge`, `policy.MaxFlattenNodes`, `Import.Terms`,
  `Export.Terms`.
- `irrd.ErrIndirectUnsupported`, returned by `irrd.Source.MembersByRef` for an
  rtr-set with `mbrs-by-ref:`, whose inet-rtr claims IRRd's query protocol
  cannot list.

## [0.8.1] - 2026-09-24

### Fixed

- **Route-set members written without a prefix length are read as IRRd
  reads them.** A member that is a whole address — `206.197.238.0`,
  `2001:db8::32^+` — is the host prefix, /32 or /128: IRRd stores it so and
  answers `!i` with the length, and bgpq4 reads it so too. This library
  rejected it, so five members of three ARIN and RADB route-sets were dropped
  from expansions. `object.ParseSetMember` now accepts it, with a Warning. A
  short address (`10.1`) is still an error, and so is an address without a
  length anywhere else, a policy prefix list included.

### Added

- **New Warning `object/<class>-members-no-length`** (and `-mp-members-no-length`).

## [0.8.0] - 2026-09-24

### Fixed

- **Abbreviated IPv4 prefixes are read as IRRd reads them.** A prefix written
  with fewer than four octets — `191.243.44/22`, `10/8` — has the missing
  octets zero: IRRd parses route-set members and route keys with Python's
  IPy, which reads them so, and bgpq4 gets them from IRRd. This library
  rejected them, so six RADB route-set members were dropped from expansions.
  `types.ParsePrefix` now accepts them, with a Warning wherever a registry
  value holds one. A short address without a length is still an error.

### Added

- **`types.AbbreviatedIPv4`**, which reports the spelling, as `PaddedIPv4`
  does for zero-padded octets.
- **New Warnings `object/<class>-abbreviated-prefix` and
  `policy/abbreviated-prefix`.**

## [0.7.0] - 2026-09-24

### Fixed

- **A line break separates list items, as in IRRd.** IRRd joins the lines of
  a value with commas, so a set whose members are listed one per line without
  commas has all of them; this library read such a value as one invalid member
  and dropped it, so the set expanded to less than IRRd and bgpq4 return. RADB
  holds 293 such values (209 as-sets, 83 route-set `members:`/`mp-members:`,
  one `notify:`), at least 600 members. They are now read as separate items,
  with one Warning per attribute.
- **`assignment-size:` is in the RIPE profile.** RIPE prints it in its
  templates as `assignment-size:[optional]`, with no space before the `[`, and
  the pattern that reads templates required one, so the attribute was missing
  from the profile and the typed objects: 74,575 RIPE inetnum and inet6num
  objects were reported as having an unknown attribute. The template check
  now reads such lines.

### Added

- **`object.AuthBcrypt`, `AuthMailFrom` and `AuthIRRdInternal`**: the
  `BCRYPT-PW` password hash IRRd uses, RFC 2622's `MAIL-FROM`, and IRRd's
  `IRRD-INTERNAL-AUTH`, which were unknown schemes with a Warning (31,488
  `auth:` lines in seven registries).
- **`auth.Credential.From`**, the update's sender address, so a `Verifier` can
  check a `MAIL-FROM` line (a forgeable check; see the package documentation).
- **`object.Inetnum.AssignmentSize`** and **`object.Inet6num.AssignmentSize`**.
- **New Warning `object/list-line-break`**, for list items separated by a line
  break without a comma.

### Changed

- **`ast.Attribute.List` splits items at line breaks as well as at commas.**
  An empty item next to a line break between lines of the value (a comma
  ending a line, a `+` blank line) is not an item, as in IRRd; one between
  commas on a line, or at either end of the value, still is.

## [0.6.2] - 2026-09-23

### Fixed

- **Unicode spaces separate policy tokens.** A no-break space (U+00A0) or any
  other Unicode space (`unicode.IsSpace`) between the tokens of an `import:`,
  `export:`, `default:`, their `mp-` and via forms, `filter:`, `peering:` or
  the `inet-rtr` and aggregation sub-grammars is read as an ASCII space, as
  IRRd reads it; before, the value was dropped with an Error. Three objects in
  the NTTCOM, RADB and TC mirrors held one. The same goes for a vertical tab
  and a form feed, which were read as part of a word. Zero-width characters
  (U+200B) are not spaces and are still an Error.

### Changed

- **New Warning `policy/unicode-space`**, once per value, at the first such
  space: RPSL separates tokens with ASCII spaces, tabs and newlines.
- **Clearer policy messages.** A message about a missing token at the end of a
  value says "end of value" (or "end of regexp") instead of quoting an empty
  token (`""`), and an AS-path regexp is quoted with its `<` and `>`.
- **A hint after `EXCEPT`.** A filter term where `EXCEPT` expects a policy
  (`from AS1 accept ANY EXCEPT FLTR-BOGONS`) is still a `policy/expect-peering`
  Error, now saying that `EXCEPT` joins two policies and suggesting
  `AND NOT FLTR-BOGONS`. The TC mirror holds 142 such policies (and 4 more
  with a stray comma first, `accept ANY, except BOGONS`, reported at the comma).

## [0.6.1] - 2026-09-23

### Fixed

- **NIC handles follow RFC 2622 and registry practice.** `types.ParseNICHandle`
  accepts underscores (RFC 2622's object-name syntax, used in RADB), a leading
  digit (ARIN's own handles, such as `1NO-ARIN`) and up to 64 characters (was
  30). It was stricter than the RFC and rejected them: 116 ARIN and 473 RADB
  handles in `admin-c:`, `tech-c:` and `nic-hdl:` were dropped with an Error.
  A person's name where a handle belongs (`admin-c: Eric Cluett`, in about
  15,000 RADB objects) is still rejected: it is not a handle, and a
  `NICHandle` stays one word, safe to put in a query.

## [0.6.0] - 2026-09-23

### Added

- **`types.ParseAddr`, `types.ParsePrefix` and `types.PaddedIPv4`**: `netip`'s
  address grammar, except that zero-padded IPv4 octets (`064.006.160.000`) are
  read as decimal, as RPSL writes addresses and IRRd reads them.

### Changed

- **Zero-padded IPv4 octets are accepted as decimal** everywhere an RPSL value
  holds an address: route and route6 prefixes, inetnum ranges, `holes:`,
  `pingable:`, route-set members, prefix lists, router addresses, `ifaddr:`,
  `peer:` and prefix ranges. They were an Error and the value was dropped; they
  are now a Warning (`object/<class>-leading-zeros`, `policy/leading-zeros`) and
  the value is used. ARIN's IRR holds 88 routes written this way, which every
  expansion built from its dump had been missing.

## [0.5.0] - 2026-09-23

### Added

- **`mnt-irt:` authorisation** (`auth`), the RIPE Database's rule that
  pointing an inetnum or inet6num at an incident response team needs that
  team's consent. `MntIrtChange` decides an update: only `mnt-irt:` references
  it adds are checked, and the credential of any one added irt is enough, as in
  RIPE's own implementation. `AddedMntIrt`, `CheckIrt` and `CheckIrts` are the
  pieces, and `IrtRegistry` looks irt objects up. It is a separate interface,
  so an existing `Registry` implementation is unaffected.

## [0.4.0] - 2026-09-23

### Changed

- **`Irt.Auth` is `[]object.Auth`**, not `[]string`: an irt's `auth:` lines
  decode as a mntner's do, with the same `object/irt-auth` warning for a scheme
  this library does not know. For the text as written, use `Auth.String()`.

### Fixed

- The v0.2.0 migration table listed `Irt.Auth` as changing to `[]object.Auth`,
  but only `Mntner.Auth` did; the irt change takes effect in this release. It
  slipped past the field-drift test, which checks which field a value lands in
  but not its type. A new test requires every attribute to decode to the same
  type in every class that has it.

## [0.3.0] - 2026-09-23

### Added

- **`import-via:` and `export-via:` are parsed** (draft-ietf-grow-rpsl-via,
  implemented by the RIPE Database; 1,784 values in 312 RIPE aut-nums).
  `policy.ParseImportVia` and `ParseExportVia` (and their `…With` variants)
  read them into the `Import`/`Export` AST: each clause's `PeerAction.Via` is
  the peering the routes pass through, such as an exchange's route server. They
  are MP, so without an `afi` clause they apply to every family; `String`,
  `AppliesTo` and `Flatten` (`Term.Via`) work on them as on any policy.
- New rule `policy/via` (Error): a via clause with no via peering is dropped.

### Changed

- **`AutNum.ImportVia` and `ExportVia` are `[]policy.Import` and
  `[]policy.Export`**, not raw `[]string`. They stay separate from `Imports`
  and `Exports`. For the text as written, use `String()` (canonical form) or
  the attributes in `Raw()`.

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
| `Mntner`, `Irt` | `Auth` | `[]string` | `[]object.Auth` (`Irt`: from v0.4.0) |
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

[Unreleased]: https://github.com/rkolesnichenko/rpsl/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/rkolesnichenko/rpsl/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/rkolesnichenko/rpsl/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/rkolesnichenko/rpsl/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rkolesnichenko/rpsl/releases/tag/v0.1.0
