# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the modules follow [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API. The modules are released together, with the
same version (see [RELEASING.md](RELEASING.md)).

## [Unreleased]

## [0.22.0] - Unreleased

### Added

- `resolve/rtconfig`: router configuration from an evaluated `peval.Policy` — Cisco IOS/IOS-XE,
  Junos, Cisco IOS-XR and BIRD 2 — what IRRToolSet's `RtConfig` does, on this engine.
  `Generator.WriteImport`/`WriteExport`/`WriteDefault`/`WritePrefixList`/`WriteASPathList`/
  `WriteNetworks` write to an `io.Writer`, all-or-nothing; `WriteSessions` writes BIRD's
  per-neighbour `protocol bgp` blocks, once, after every other call. `Capabilities()` reports
  what each vendor can express; a construct it cannot is an `*UnsupportedError` wrapping
  `ErrUnsupported`, naming one of the `Cause*` constants.
- `rpslconf` template mode: reads an IRRToolSet-style `@RtConfig` template from stdin and writes
  router configuration for the sessions and lists it names; `-config` chooses the dialect. `-v`
  prints the binary's version (`rpslq` gains the same flag).
- `rpslconf` release binaries, alongside `rpslq`'s, for every platform `scripts/release.sh`
  already built `rpslq` for.
- `peval.Why*` constants and `peval.Whys()`: `Undecided.Why`'s values are now a stable,
  documented set rather than free text.
- `resolve.NewASNSet`, for building an `ASNSet` from a fixed list of ASNs.
- `irrtest.WithLegacyClasses`, so the test IRRd answers IRRd 2/3's `!man` query, which
  IRRToolSet's `rtconfig` and `peval` read aut-nums with.
- `scripts/build-irrtoolset.sh`, which builds IRRToolSet 5.1.3's `rtconfig` and `peval` for the
  differential tests (natively on Linux, in Docker elsewhere) and installs them for `PATH`; CI
  runs it so the differentials execute on every push.
- `FuzzTranslateRegexp` (`resolve/rtconfig`) and `FuzzParseTemplate` (`resolve/internal/rpslconf`):
  the fuzz targets are now 40.

### Changed

- `Undecided.Why`'s values are now the `Why*` constants. They are the same strings, so no
  consumer comparing them changes behavior.

### Fixed

- `resolve/rtconfig` refuses a `next-hop` action whose address is not of the session's family
  (`next-hop = 192.0.2.1` in an `mp-import: afi any.unicast` evaluated for an IPv6 session) with
  `CauseActionValue`, instead of writing it into the policy: IOS rejected the
  `set ipv6 next-hop` line on load but kept the entry, which then accepted routes with their
  next-hop unchanged. `next-hop = self` is unaffected.
- `resolve/rtconfig` writes no entry for a conjunct holding `NOT community()` (or
  `NOT community.contains()`): a route carries each of no communities, so the negated test
  holds for none. It used to write a community list of no values, which no vendor accepts (BIRD
  `if !() then`, Junos `members [ ]`). `community == {}` keeps its meaning: BIRD writes it, the
  others refuse it as an exact match.
- `NormalizeFilter`'s depth limit no longer depends on the order a memo was filled: reusing a
  filter-set's inlined normal form now re-checks `MaxDepth` against how deep that inlining
  actually reached, not just the depth of the call that first computed it.
- Its per-conjunct test cap (`MaxConjuncts`) is now counted after the two sides' prefix ranges
  are intersected, not before.

## [0.21.0] - 2026-09-30

### Added

- `resolve.NormalizeFilter`: a filter in disjunctive normal form — prefix ranges for what can be
  enumerated, AS-path regexps and community tests kept symbolic, NOT pushed to the leaves — as
  IRRToolSet's peval computes it. `Expander.MaxConjuncts` (default 4,096) caps the conjuncts of
  any disjunction and the tests of any conjunct; a filter-set is inlined once per polarity, a
  repeated test kept once, and every step charged against `MaxVisited`. `Expander.Exclude`
  narrows only its positive prefix literals — never a negated one, nor an AS-path regexp's sets.
- `Expander.Peer` binds PeerAS and set templates (`AS1:AS-CUST:PeerAS`) for `EvalFilter` and
  `NormalizeFilter`; unbound, they are a `*NotEnumerableError` wrapping `ErrUnboundPeer`.
- `resolve/peval`: an aut-num's import, export, via and default policies evaluated for one BGP
  session — ordered clauses of normalized filter and actions; terms that depend on a router the
  session does not name are reported as `Undecided`, never guessed. On RIPE's dumps, a 301-aut-num
  sample evaluated 3,468 import/export sessions (both families, every named peer) into 1,972
  clauses in 15 s, with 58 terms Undecided (a local or peer router not given) and no limit or
  timeout failures. `Expander.Exclude` narrows clause filters only, never peering or router matching.
- `policy.ParseMPFilter`; `(*policy.ASPathRE).String`, `Bind`, `UsesPeer`, `SetNames`.
- `rpslconf -e`: peval on the command line (`resolve/cmd/rpslconf`); `-h` takes `host:port` too.

## [0.20.1] - 2026-09-29

### Fixed

- `release.sh` asked the proxy whether a tag was served with the local module
  cache in place, which answered for a version a `go mod tidy` had just
  resolved; a miss the proxy had cached (v0.20.0: 404 for the root module for
  about 45 minutes) went unseen until step 6. It now asks from an empty module
  cache, so it waits on the proxy, and refreshes it by commit, until it serves.
- `irrd.Source`: when the connection broke on "!j-*" (a server that hangs up on
  a command it does not know), every scoped lookup failed. That lookup now asks
  for its registry with "!s" instead, and after two such failures in a row the
  Source stops sending "!j-*", as for a server that refuses it.

## [0.20.0] - 2026-09-29

### Added

- `src-members:` (draft-ietf-grow-rpsl-registry-scoped-members-00): decoded on as-set and route-set,
  validated (three diagnostics per class), resolved by every backend; `types.SetRef`, `object.DirectMembers`,
  `object.WithSrcMembers`, `irrd.Source.SrcMembers`, rpslq `--src-members`.
- `resolve.PolicySource` (aut-nums and inet-rtrs) over MemSource, Corpus (`KeepPolicy`), DumpLoader,
  nrtm4.Client, irrd, whois, Cache and rpki.Filter.

### Changed

- rpslq `SOURCE::SET` where the set lists its own name: the inner mention now resolves in the `-S` sources, as bgpq4 does.
- rpslq `-L` with `SOURCE::` (source-with-depth): the top's own unscoped mentions resolve in the `-S` sources.
- `whois.Source.MembersByRef` queries `-s <the set's source>` (the claims `ClaimAllowed` keeps), not `Sources`.
- irrd's error for a refused default source list now wraps an "unknown source" error; its message text changes.
- `irrd.Source` learns the server's registries once via `!j-*` for scoped lookups (kept until `Close`).
- A `MemSource` from a `Corpus`, `DumpLoader` or `nrtm4.Client` without `KeepPolicy` answers `AutNum`/`InetRtr` with `ErrNoPolicy`.
- `object.SetMember` gains a `Source` field: unkeyed struct literals break.

### Breaking

- `Source.GetSet` takes a `types.SetRef`: implementers change the parameter and use `ref.Name()`;
  honour `ref.Source()` or return an error for a scoped ref.
- `Expander.Expand*` take a `types.SetRef`: wrap names with `types.Ref(name)`.
- `Missing()` returns `[]types.SetRef`: `String()` prints unscoped refs as before.
- `SetTooLargeError.Name` is a `types.SetRef`.
- `object.Set` gains `SetSrcMembers()`: add it (return nil) to a custom set type.
- `Corpus.SourceOf`/`DumpLoader.SourceOf`: scoped lookups and claims reach every held source.
- `ErrNotFound`'s message is "resolve: not found" (same value).

## [0.19.1] - 2026-09-28

### Added

- **rpslq binaries**: every release carries rpslq for Linux and macOS (amd64,
  arm64) and Windows (amd64), static, built by `release.sh` from the
  published module (so `rpslq -v` names the release), with `SHA256SUMS`.
  `release-dryrun.sh` builds and checks every archive.
- **`docs/rpslq.md`**, rpslq for bgpq4 users: install, what is the same, what
  rpslq adds (`--rpki`, `--dump`, `--whois`, `SOURCE::`, `-d`), and where the
  two differ on purpose.
- **`scripts/release.sh vX.Y.Z`** releases every module as RELEASING.md
  describes: it refuses to start unless the tree, changelog and CI are ready,
  tags and pushes in dependency order, waits for the Go proxy (asking only for
  pushed tags, and by commit when a miss is cached), verifies every module
  from an empty module cache, creates the GitHub release, and resumes after a
  failure. `scripts/release-dryrun.sh` now rehearses by running it against a
  bare repository and a local proxy, including its refusals and a resume.
- **`nrtm4.Client.MaxAge`**: refuse a notification file older than it, as
  IRRd refuses one over 24 hours old, so that a replayed, validly signed file
  cannot roll the mirror back. Zero keeps the draft's default: report it
  (`Status.Stale`) and use it.
- **`rpki.VRPs.AddTo(*resolve.Corpus)`**: IRRd's pseudo routes, put straight
  into a `Corpus`; `rpslq --rpki --dump` uses it instead of writing a million
  objects out as text and parsing them back.

### Fixed

Found by a review of v0.16.0..v0.19.0.

- **A primary key that grows when upper-cased panicked** `Corpus.Delete` and
  the NRTMv4 client ("ɐ" is two bytes, "Ɐ" three): a hostile or broken delta
  could crash a mirror. The key is now read from the string searched, in one
  place (`resolve`; `nrtm4`'s copy is gone), and fuzzed (`FuzzCorpusDelete`).
- **`Corpus` (so `DumpLoader`) dropped a route-set's indirect member** whose
  route has an undecodable `origin:`, which `NewMemSource` and v0.16.0 kept:
  what claims membership is now decided by the engine's own rule. And it
  answered a route with host bits set (`192.0.2.1/24`) masked, where
  `NewMemSource` answers it as decoded; now it too keeps it as decoded. The
  equivalence test now draws both.
- `Corpus.Merge` could hold a route twice (whole and reduced), so that a
  later `Delete` left it served; an update moved an object to the end of load
  order, changing which of two unranked sources' same-named sets wins.
- `nrtm4`: a record at the end of a file could be one byte over the cap;
  `"next_signing_key": null` (or `""`) was refused rather than read as none;
  `Run` retried a failed Sync after 30 seconds, under §5.2's one-minute
  minimum; a snapshot's objects reached `OnDiagnostics` before its hash was
  checked; a redirect could leave the notification file's host, or HTTPS (it
  is refused now, with the caller's `http.Client` too); a new session whose
  notification file is older than the one the mirror came from is refused as
  a rollback.
- `release.sh`: a relative `RELEASE_DIST` broke the binaries step, and with
  `--no-gh-release` the archives were deleted as soon as they were built; they
  now go to `RELEASE_DIST` (made absolute) or `$TMPDIR/rpsl-release-vX.Y.Z`.

## [0.19.0] - 2026-09-27

### Added

- **`resolve.Corpus`**: IRR objects held as the engine uses them — sets and
  membership claimants (`member-of:`) whole, every other route as its prefix,
  origin and source (94 bytes, not 4.7 KB), nothing of the rest. `Put`
  replaces by class, primary key and source; `Delete` takes an NRTM delete;
  `Merge` combines; `Source`/`SourceOf` build the `MemSource`, through the
  same code as `NewMemSource`. RIPE's dumps load in 460 MB of heap instead of
  3.7 GB, and a full RIPE mirror peaks under 1 GB instead of 6.6 GB.
- `DumpLoader.Corpus`, for merging a loader's objects with a mirror's.

### Changed

- **`DumpLoader` holds a `Corpus`.** Its answers are unchanged (held to
  `NewMemSource` over the random IRRs and the largest real sets of RIPE and
  ARIN). `Stats.Kept` counts what is held in either form, so aut-nums and
  inet-rtrs that claim no membership no longer count; and two objects with
  one class, primary key and source in the dumps are one object, the later —
  a registry cannot have both.
- **`nrtm4.Client` holds a `Corpus`.** `Objects()` is replaced by
  `CopyTo(*resolve.Corpus)`, and `Keep` is removed: a mirror holds what the
  engine uses. An update whose `source:` is not the mirrored database's is
  discarded and now leaves the object it names in place, as IRRd does; an
  object of another class is still skipped unparsed.

## [0.18.0] - 2026-09-27

### Added

- **`resolve/nrtm4`: an NRTMv4 mirror client** (draft-ietf-grow-nrtm-v4), the
  protocol IRRd 4 and the RIPE Database publish changes with. `Client.Sync`
  loads the snapshot and applies the deltas since; `Run` keeps polling. The
  notification file's ES256 signature (with in-band key rotation), each
  file's SHA-256 and header, and the delta chain are verified before
  anything is used; a delta applies whole or not at all. Each version is
  published as an immutable `MemSource` (`Source()`), so an expansion sees one
  version whole. Held to an independent server (`internal/nrtmtest`) over
  random histories and every way a server can misbehave, and — opt-in — to
  the RIPE Database's live feed. Standard library only.
- **`resolve.Expandable`**: the classes the engine uses, which `DumpLoader`
  keeps and a mirror keeps by default.
- README: a dump differs from what RADB serves by its scope filter
  (special-purpose origins, bogons) as well as by RPKI and time.

## [0.17.0] - 2026-09-27

### Added

- **`resolve/rpki`: RPKI-aware expansion, as IRRd 4 does it.** IRRd validates
  every route object against the RPKI (RFC 6811) and suppresses the invalid
  ones from its answers and exports, and serves each ROA as a route of the
  source `RPKI`, which RADB lists by default. A registry's own dump or a whois
  server does neither. `ReadJSON` reads the VRP export of rpki-client,
  Routinator and IRRd's `roa_source`; `ApplySLURM` applies an RFC 8416 file;
  `Validate` is IRRd's rule (AS0 covers, never matches); `Filter` makes any
  `Source` suppress the invalid routes; `WriteRPSL` writes IRRd's pseudo
  objects, byte for byte, as a dump for `DumpLoader`. Checked against IRRd's
  own tests and a capture from RADB, a model with random ROAs over every
  backend, and — opt-in — every registry's routes (RADB's and NTT's filtered
  exports are 0.15% and 0.05% invalid by today's VRPs; BELL's unfiltered dump
  79%, none of which RADB serves).
- **rpslq `--rpki file` and `--slurm file`**: the routes the VRPs make invalid
  are left out, from any source, and a `--dump` gains the pseudo routes as the
  registry `RPKI` (chosen with `-S` like any other), so an offline expansion
  matches bgpq4 against RADB. Held to bgpq4 against an RPKI-aware server on
  random IRRs. `-d` traces each route left out.
- `resolve/internal/irrtest` emulates IRRd's RPKI-aware mode (`WithRPKI`).
- `scripts/fetch-irr-dumps.sh rpki` fetches the VRPs NTT exports for IRRd.

## [0.16.0] - 2026-09-25

### Added

- **`resolve.DumpLoader.SourceOf`**: a `MemSource` over the loaded dumps'
  objects from some registries only, in the precedence given — the dumps as
  if those registries alone had been loaded, without reading them again.
- **rpslq reads bgpq4's `SOURCE::OBJECT`** (`RIPE::AS-FOO`): the set, and its
  indirect members, are looked up in that registry, and what it reaches —
  nested sets, its ASes' routes — in the default sources, as bgpq4 does. Over
  IRRd, whois and dumps alike. `RIPE::AS65001` takes that AS's routes from
  RIPE alone. Held to bgpq4 on random IRRs; four corners where bgpq4 slips
  are pinned as divergences.
- **rpslq `-d`** traces each question it asks of its source — the set or
  routes asked for, the registry, what came back, how long it took — and a
  count at the end, to stderr. The list itself is unchanged.

### Fixed

- `rpslq --dump` with `-S` uses only the registries `-S` names, in its order,
  as `-S` does for a server; it only ranked them, and unioned every
  registry's routes.

## [0.15.0] - 2026-09-25

### Added

- **`rpsl.ARIN` (`object.ARIN`)**, a validation profile for ARIN's IRR: its
  five classes (route, route6, aut-num, as-set, route-set), each IRRd 4's
  table, plus the `created:` and `last-modified:` ARIN generates, at most one
  each; any other class is `dict/unknown-class`. It is derived from the IRRd
  profile in code, since ARIN documents its templates only in prose. Under the
  IRRd profile, 187,209 of ARIN's 212,104 objects raised a diagnostic, nearly
  all for `created:`; under ARIN's, 54 legacy aut-nums without `admin-c:` and
  `tech-c:` do. The real-data test now validates ARIN's dump with it, and
  `bulk-ripe -validate arin` selects it.

### Changed

- **`types.ParseRouterID` refuses a name whose last label is all digits**
  (`1.2.3`, `256.0.0.1`, `1.2.3.4.5`): no top-level domain is (RFC 3696 §2), so
  such a router is a mistyped address, as the policy parser already reads it.
  An rtr-set member so written is now an Error (`object/rtr-set-members`),
  naming the cause. No registry's data has one.

## [0.14.0] - 2026-09-25

### Added

- **`resolve.Expander.Exclude`** (`resolve.Exclusion`): sets and AS numbers
  an expansion leaves out, as bgpq4's `EXCEPT` does. An excluded set is never
  followed, fetched or reported missing, and an excluded AS contributes
  nothing, wherever an expansion meets them — nested sets, AS members,
  indirect aut-num members, references inside filter-sets. The set an Expand
  call names is expanded as asked. Held to the model oracle over every
  backend.
- **rpslq at bgpq4's feature level.** Every vendor bgpq4 writes: Cisco IOS XR
  (`-X`), Arista EOS (`-e`), OpenBGPD (`-B`), Nokia SR OS classic and MD-CLI
  (`-N`, `-n`) and SR Linux (`-n2`), MikroTik v6 and v7 (`-K`, `-K7`),
  Huawei and Huawei XPL (`-U`, `-u`), user formats (`-F`). Every kind of
  list: route-filters, extended access-lists and prefix-sets (`-E`), Junos
  route-filter-lists (`-z`), input and output as-path lists (`-f`, `-G`),
  Junos as-lists (`-H`), OpenBGPD as-sets (`-B -t`). And aggregation (`-A`),
  more-specifics (`-R`, `-r`), sequence numbers (`-s`), `-w`, `-W`, `-M`,
  `-a`, `-T`, `-v`, `$IRRD_SOURCES`, prefixes as objects, and `EXCEPT`. The
  aggregation is bgpq4's own radix tree, ported node for node, so aggregated
  lists match too. Tests hold every vendor, kind and shape to the bgpq4
  binary, and rpslq refuses exactly what bgpq4 refuses.
- `EXCEPT` also applies inside route-sets, where bgpq4 ignores it, and `-m 32`
  (or `-m 128`) means no limit, where bgpq4 then drops a range's
  more-specifics: both pinned in `resolve/testdata/bgpq4/divergences.md`.

### Fixed

- rpslq writes an IPv4-compatible IPv6 address (`::1.2.3.0/120`) as bgpq4
  does, dotted, in every vendor format; it wrote `::102:300/120`.
- A prefix range wholly longer than `-m` (`::/0^65-128` under `-6 -m 64`) no
  longer walks every more-specific before adding nothing — 2^64 steps there.

### Changed

- **rpslq reads its command line as bgpq4 does**, with getopt: bundled
  options (`-6Ab`), attached arguments (`-lNAME`), options after the objects.
  Its own options, which bgpq4 lacks, are long now: `-whois`, `-dump`,
  `-ranges` and `-timeout` are `--whois`, `--dump`, `--ranges` and
  `--timeout`, and `-a` (the server's `!a` expansion) is `--server-expand`,
  since `-a AS` is bgpq4's option for OpenBGPD's `deny from AS`. The former
  spellings are refused with a pointer to the new ones.
- **rpslq's `-L` counts levels as bgpq4 does**, the named set being the first:
  `-L n` allows n-1 levels of nesting (it allowed n). Where sets nest deeper,
  bgpq4 leaves the deeper ones out and rpslq fails, naming `-L`; `-L 1`, with
  which bgpq4 drops every nested set, is refused. Without `-L`, the engine's
  default of 32 levels of nesting stands.
- rpslq holds up to 8,388,608 prefixes in a list (was 1,048,576), counting
  prefixes rather than the tree's nodes: AS-HURRICANE alone now holds 1.16
  million IPv4 prefixes, which bgpq4 lists (and rpslq does, identically, in
  about 6 s and 580 MB).

## [0.13.0] - 2026-09-25

### Added

- **`irrd.Source.ASSetPrefixes`**: an as-set expanded by the server itself,
  with IRRd 4's `!a` query — one query where the engine's expansion makes one
  per AS. The answer is the server's, under its rules, so it is not part of
  `resolve.Source`. A missing as-set is `ErrNotFound`, a route-set
  `ErrSetClass`, and a server without `!a` the new **`irrd.ErrQueryRefused`**.
- **`rpslq -a`** expands as-sets that way, as plain bgpq4 does. The largest
  sets then take seconds, as with bgpq4 (AS-HURRICANE over RADB: 8.4 s against
  bgpq4's 7.7 s, identical output), where the engine's own expansion takes
  about 20 s: RADB answers a client about 1,200 queries a second, however they
  are sent. The default stays on the engine's own checks.

## [0.12.0] - 2026-09-25

### Added

- **`rpslq`, a bgpq4-style filter generator** on the expansion engine:
  `go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslq@latest`. It
  writes prefix lists (Cisco IOS, JSON, BIRD, Junos, plain) and AS lists
  (JSON, BIRD, plain) for as-sets, route-sets and AS numbers, over IRRd,
  whois or offline dumps. Flags follow bgpq4's, and its output is bgpq4's
  byte for byte — held to it by a test on random IRRs, and matching it live
  on RADB for AS-HURRICANE. `-ranges` writes RPSL ranges instead of every
  prefix they hold.
- **`irrd.Source.Pipeline`**: pipelined queries, as bgpq4 sends them. Up to
  `Pipeline` queries share one persistent connection, their commands written
  back to back and their answers read in order; a connection that fails is
  replaced and its waiting queries retried once. Expanding AS-HURRICANE's
  routes over RADB went from failing after seven minutes (sixteen
  connections, reset by the server) to 22 seconds on one connection.

## [0.11.0] - 2026-09-25

### Added

- **`object.IRRd` (`rpsl.IRRd`), a validation profile for IRRd-run
  registries**: IRRd 4's class tables, which RADB and the IRRs it mirrors
  apply to what they accept, read from IRRd's `rpsl_objects.py`. It differs
  from `RIPE` where the registries do — `mnt-by:` optional on aut-num and
  domain, `changed:` still allowed, `rev-srv:`, `geoidx:` and `roa-uri:`
  defined, `last-modified:` ignored, `filter:` required on a filter-set.
  Against it RADB's 1.38 million objects raise 22 Errors (routes without
  `mnt-by:`). The source is kept in `object/testdata/irrd` at IRRd v4.5.3 and
  checked against the profile, and, with `RPSL_LIVE=1`, against IRRd's latest
  release.
- **Typed fields for the attributes IRRd defines and RIPE does not**:
  `Domain.SubDom`, `DomNet` and `Refer`; `InetRtr.RsIn` and `RsOut`;
  `Inetnum.RevSrv` and `Inet6num.RevSrv`; `Route` and `Route6` `GeoIdx` and
  `RoaURI`; `Irt.AbuseMailbox`.
- `bulk-ripe -validate irrd`.

### Changed

- The opt-in real-data test validates RADB and its ten mirrors against the
  IRRd profile, as it validates RIPE's dumps against RIPE's.

## [0.10.0] - 2026-09-24

### Added

- **`auth` decides whole updates, under the RIPE Database's or IRRd's rules.**
  `auth.RIPE` and `auth.IRRd` are `Rules`; `Authorise` takes an `Update`
  (`Create`, `Modify` or `Delete` of an object) and a credential, applies every
  check that registry makes, and returns a `Decision` naming each.
  - RIPE, as its whois server implements it: the object's maintainers (the
    stored version's for a change), and on creation the parent's — the less
    specific inetnum or inet6num, the as-block of an aut-num, the covering route
    or address space of a route (`mnt-routes:`, `mnt-lower:`, `mnt-by:`), the
    address space of a reverse domain (`mnt-domains:` first), the object a
    hierarchical set name names — plus irt and `mnt-ref:` consent for new
    references. A domain may also be deleted by its address space's
    `mnt-domains:`.
  - IRRd, with its default settings: the submitted and stored versions'
    maintainers, and on creation the `mnt-by:` of a route's address space (or
    less specific route) and of the aut-num a set's name begins with. New
    maintainers are refused: they are an administrator's to create.
- **`auth.Database`**, the lookups Authorise needs — the stored version of an
  object, an object by class and key, the objects covering an address range,
  the as-blocks holding an AS — and **`auth.MemDatabase`** over decoded
  objects, for tests and dumps.
- **`object.Domain.ReverseRange`**, the addresses a reverse zone covers
  (`in-addr.arpa`, RIPE's `0-127.2.0.192.in-addr.arpa` range form, `ip6.arpa`).
- An opt-in real-data check: a sample of the RIPE Database's routes, authorised
  for creation against their surroundings, all find their parent.

### Changed

- `auth.CheckMntners` and `CheckIrts` say that a maintainer or irt with no
  `auth:` lines accepts no credential, rather than that the credential was
  rejected.

## [0.9.1] - 2026-09-24

### Security

- **`auth.MntIrtChange` failed open.** It read `mnt-irt:` only from
  `Inetnum`/`Inet6num` values, so pointers to them, or an object known only by
  its text, added no reference and the update passed without the irt's
  consent. Pointers are read, and any other object from its text.
- **`auth.RouteCreation` took permission from any aut-num and any address
  space.** An attacker's own AS and inetnum authorised a route for someone
  else's prefix. `RouteRequest` now carries `OriginAS` (`RouteRequestFor`
  fills it): the origin must be that AS's aut-num, and the space must cover
  the route. A request without `OriginAS` is refused.
- **`resolve.ClaimAllowed` folded names with Unicode case rules**, so a
  maintainer or source spelled with a Kelvin sign matched one spelled with
  `K`. Names fold ASCII letters only.
- **The RDAP guard also refuses** IPv4-translated addresses
  (`::ffff:0:0:0/96`) and the discard-only `100::/64`.

### Fixed

- **`auth.RouteAuthority` used `mnt-lower:` for the object's own prefix and
  for an aut-num.** `mnt-lower:` guards what lies below its object (RFC 2725
  §4): it applies only to address space strictly less specific than the route,
  and an aut-num's authority is `mnt-routes:`, then `mnt-by:`.
- `auth.ReferralChain` refused a chain of exactly `maxDepth` maintainers.
- **A tab separates an `auth:` scheme or a `changed:` date**, as a space does.
- **Streaming:** a `\r` ending a 64 KiB read of an over-long line was taken
  for the line's end, which could split an object the lexer reads as one. A
  finished object is yielded as soon as the next begins, not when the next
  ends too. Ranging over the iterator from inside its own loop panics, rather
  than silently ending the outer loop.
- **`ast.Object.Format` with `Align: 0` keeps the separator as written**, as
  documented.
- **An aut-num whose key does not decode no longer claims membership as
  AS0**, nor is a route whose origin does not decode indexed as AS0's.
- **whois reported an object over the stream's size cap as not found.** It
  is an error.
- **Router expressions:** a term whose last label is all digits
  (`256.0.0.1`, `10.1.1`) is a mistyped address and an Error, not an inet-rtr
  name. In TC's aut-nums, 987 values such as `from AS-X 100 accept …` (a
  preference written where a router goes) move from Warning to Error, and no
  longer restrict the peering to a router named `100`.
- **An `inject:` condition's OR or AND chain is flat**: 1,000 terms used to
  exceed the nesting cap and lose the condition.
- **IPv6 zones and IPv4-mapped addresses** in `ifaddr:`, `interface:` and
  router addresses are read as before — without the zone, as the IPv4
  address — with a Warning; a router address no longer keeps its zone.

### Added

- `auth.RouteRequest.OriginAS`.
- **New Warning `policy/range-op-empty`**: an operator after a prefix list
  that keeps none of its ranges (`{1.0.0.0/8}^64`).
- Fuzz targets for the network backends: `FuzzReadFrame`, `FuzzParseMembers`
  (resolve/irrd) and `FuzzScanResponse` (resolve/whois).
- A current "Known limitations" section in the README.

### Changed

- CI pins its actions by commit, checks out without persisting credentials,
  and times out after 30 minutes. `check.sh` no longer hides a failing
  coverage run.

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

[Unreleased]: https://github.com/rkolesnichenko/rpsl/compare/v0.21.0...HEAD
[0.21.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.20.1...v0.21.0
[0.20.1]: https://github.com/rkolesnichenko/rpsl/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.19.1...v0.20.0
[0.19.1]: https://github.com/rkolesnichenko/rpsl/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/rkolesnichenko/rpsl/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/rkolesnichenko/rpsl/compare/v0.9.0...v0.9.1
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
