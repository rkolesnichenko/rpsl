# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/) once
the first tags are cut. Until then, every module's inter-module `require` is
pinned at `v0.0.0` and resolves locally through `go.work` (see
[README.md#Releasing](README.md#releasing)).

## [Unreleased]

### Fixed — typed objects and validation (2026-09-21)

- **Every profiled attribute reaches the typed struct.** The decoders dropped
  data the profiles declare (`aut-num` `descr`/`member-of`, `mntner`
  `upd-to`/`mnt-nfy`, `route` `pingable`/`inject`/`components`/…, `inet-rtr`
  `alias`/`interface`, `filter-set` `mp-filter`, …).
  `TestDecoderSurfacesEveryProfiledAttribute` now fails when a profile lists an
  attribute its decoder does not surface.
- **`RFCStrict` follows the RFC 2622/4012 tables:** `descr`, `tech-c`,
  `mnt-by`, `changed` and `source` are required on every class, `admin-c` only
  where the RFC says so. `peering-set` and `filter-set` need one of
  `peering`/`mp-peering` or `filter`/`mp-filter` (new `ClassSpec.OneOf`), and
  the `dictionary` class is known.
- **`RIPE` knows `key-cert`, `poem` and `poetic-form`**, which it used to
  report as unknown classes.
- **Suspect values are diagnosed** instead of passing silently:
  - an empty primary key (Error, `object/empty-key`);
  - a set name of the wrong class, e.g. `as-set: RS-FOO`
    (`object/<class>-name-class`);
  - an IPv6 `route` or IPv4 `route6` (`object/<class>-afi`);
  - host bits set in a route prefix (`object/<class>-host-bits`);
  - a `holes:` prefix outside the route (`object/<class>-holes-outside`).
- `inetnum`/`inet6num` `country:` is multi-valued, as in the RIPE database.
- `peering-set` reads `peering:` and `mp-peering:` in document order.

### Changed (breaking) — typed objects

- Every typed struct embeds `object.Common` (`Descr`, `AdminC`, `TechC`,
  `Remarks`, `Notify`, `MntBy`, `Changed`, `Source`). Field access is
  unchanged through promotion; composite literals must set them via `Common`.
- `Inetnum.Country` and `Inet6num.Country` are `[]string`.
- `FilterSet.Filter` holds only `filter:`; `mp-filter:` is `FilterSet.MpFilter`.

### Added — tooling and release (2026-09-21)

- `scripts/check.sh`: every module under `-race`, gofmt, leaf isolation, engine
  purity, staticcheck/govulncheck when installed, and (with `FUZZTIME`) all nine
  fuzz targets. CI (`.github/workflows/ci.yml`) runs it on Go 1.23 and stable.
- Opt-in real-data regression (`RPSL_REALDATA`, dumps via
  `scripts/fetch-ripe-dumps.sh`): lossless streaming of the RIPE split dumps,
  bounded error rates, and order-independent expansion of the largest real sets.
- Opt-in live smoke test of the backends against RADB, RIPE and RDAP
  (`RPSL_LIVE=1`). It found that IRRd closes a connection after one command
  unless `!!` is sent: per-query mode with `Sources` set (the `!s` command came
  first) got EOF on every query. Fixed.
- `String()` on `resolve.ASSet`, `PrefixSet` and `RangeSet` (e.g. `[AS1 AS2]`).
- `examples/bulk-ripe` reports decompressed bytes (`parsed_bytes`) and
  throughput on them, beside the on-disk figures.
- `RELEASING.md`: the per-module tag and `require`-bump procedure.

### Fixed — network backends (2026-09-21)

- **Cancellation works.** irrd and whois used the context only to dial, and
  `Timeout` defaulted to none, so a server that accepted and never answered hung
  a query forever; cancelling now aborts a pending read at once, and a
  context deadline reports `context.DeadlineExceeded`.
- **whois server errors are reported:** any `%ERROR` other than 101 ("no
  entries") returns `whois.ErrServer`; RIPE rate limiting (201) used to look like
  "no data" and silently shrink filters. `%` server-comment lines are removed
  before parsing — a `%WARNING:…` line glued to an object used to become its
  class and hide it.
- **irrd:**
  - A lying length header no longer forces a 256 MiB allocation (memory follows
    the bytes received; new `MaxResponse`).
  - A reused pooled connection the server closed is retried once instead of
    aborting the expansion.
  - A refused `!s` source list is an error (it made every set "not found").
  - `Close()` stops pooling (a later query re-pooled and leaked its connection).
  - `MaxConns` bounds concurrent connections (50 goroutines opened 56).
- **rdap:**
  - The SSRF guard runs on the dialed IP, catching `localhost`, `127.1`,
    numeric-host forms and DNS rebinding; IPv4-mapped addresses are unwrapped,
    and more special-purpose ranges are refused.
  - A trailing `/` in `BaseURL` no longer yields `//autnum/…`, and `LookupIP`
    sends the masked prefix.
  - It sends a `User-Agent`, reports 429 as `ErrRateLimited{RetryAfter}`, and
    drains error bodies so connections are reused.

### Changed (breaking) — backends

- irrd/whois `Timeout` 0 means `DefaultTimeout` (60 s); negative means none.
- `irrd.MaxConns` bounds concurrent connections (default 4, was 2 idle only).
- Removed `rdap.SetSource` (an exported no-op). New: `irrd.Source.MaxResponse`,
  `whois.ErrServer`, `rdap.ErrRateLimited`, `rdap.Client.UserAgent`.

### Fixed — streaming and the syntactic layer (2026-09-21)

- **Read errors are reported.** `Parse` treated any reader error as end of
  input, so a corrupt gzip dump looked complete; it now ends with an
  `rpsl/read-error` diagnostic on the object in progress.
- **Streams are lossless.** Concatenating every yielded object's `String()`
  reproduces the input byte for byte (the first blank line after each object was
  dropped): an object owns the trivia before it, the last object the trailing
  trivia.
- **Memory is bounded for real.** `MaxObjectBytes` now also caps the blank/comment
  lines before an object (40 MiB of `\n` allocated ~38 GiB; now ~72 KB) and each
  line as it is read (a 50 MiB line allocated 101 MiB; now ~70 KB), and no longer
  charges leading blank lines to the object that follows.
- **Linear-time lexing.** Folding continuation lines re-copied the attribute for
  every line (1.7 GB allocated for a 40k-line `remarks:` block).
- **Stream-relative positions:** spans and diagnostics of streamed objects,
  including Decode's, point into the stream rather than the object.
- `ast.Set` replaces in place (it moved the attribute to the end, and could
  change `Class()`); `Append` rejects names/values RPSL cannot represent and folds
  newlines into continuation lines (they were silently mangled on re-parse).
- New diagnostics: `lexer/invalid-attribute-name` (incl. a leading BOM),
  `rpsl/multiple-objects` from `ParseObject`, `rpsl/trivia-too-large`. A lone
  `\r` at end of input is a line terminator, not part of the value.

### Changed (breaking) — syntactic layer

- `Parse` and a zero `ParseOptions` apply `DefaultMaxObjectBytes` (64 MiB); a
  negative `MaxObjectBytes` means unlimited.
- Streamed objects include their leading blank/comment lines in `String()`, and
  their positions are stream-relative.
- `ast.Object.Append`/`Set` return an error wrapping `ErrInvalidAttribute`.
- New `lexer.TokenizeAt`.

### Fixed — expansion engine (2026-09-21)

- **Results no longer depend on member order.** A set first reached at the depth
  limit was marked visited with its children cut, so a later, shorter path to it
  was skipped (e.g. a 60-set ring expanded to 51 of 60 ASNs). Discovery is now
  breadth-first: every set is fetched once, at its shortest nesting distance.
- **Range operators on route-set members work** (`RS-FOO^+`, `AS1^24`; RFC 2622
  §5.2), composed along each path. New `Expander.ExpandPrefixRanges` returns the
  ranges before materialization (bgpq4's le/ge form).
- **The prefix budget counts distinct prefixes only**, streamed through the new
  lazy `types.PrefixRange.All()`; `MaxPrefixes: math.MaxInt` no longer overflows.
- **Nothing is dropped silently:** exceeding `MaxDepth` is an error (it silently
  truncated), a missing top-level set is an error wrapping `ErrNotFound`, missing
  nested sets are listed by `Missing()`, `AS-ANY`/`RS-ANY` return `ErrAnySet`,
  and an operator applied through a cycle returns `ErrCyclicOperator`.
- **Indirect membership follows RFC 2622 §5.1-5.2**: aut-num claimants for
  as-sets, route claimants for route-sets only.
- Each AS's routes are fetched once per call (was once per reference).
- An as-set listed in a route-set no longer draws a class-mismatch warning
  (RFC 2622 §5.2 allows it); a zero `PrefixRange` no longer materializes to
  `::/0`.

### Changed (breaking) — engine

- `ErrSetTooLarge` gains `Limit` (`LimitPrefixes`/`LimitVisited`/`LimitDepth`)
  and its message names the cap; `MaxDepth` is the shortest nesting distance and
  is enforced as an error.
- Removed `Expander.Sources` (never read) and `ErrUnsupportedOperator`. New:
  `RangeSet`, `ErrCyclicOperator`, `ErrAnySet`, `Missing()` on all results.
- `NewMemSource` takes an optional source precedence; with none, the first
  definition of a duplicated set wins (the last one silently did).

### Fixed — policy parser (2026-09-21)

- **Policy values are never truncated silently.** Every `import`/`export`/
  `default`/`filter`/`peering` value is parsed completely or diagnosed
  (`policy/trailing`, `policy/expect-filter`, `policy/expect-peering`,
  `policy/empty`). On the RIPE aut-num dump the old parser dropped policy content
  from 4,302 values with no diagnostic, mostly implicit-OR filters such as
  `announce AS-UARNET AS-UAIX` (RFC 2622 §5.4), which it read as `AS-UARNET`.
- **Structured policies** (RFC 2622 §6.6): the `;` before `except`/`refine` no
  longer discards the block, and `except`/`refine` are right-associative.
- **Peering AS-expressions** with `AND`/`OR`/`EXCEPT` and parentheses, full router
  expressions, range operators on filter terms (`AS-FOO^+`, `PeerAS^0-32`),
  prefix-list operators composed per RFC 2622 §5.2, and `PeerAS` set-name
  templates (`AS1:AS-CUSTOMERS:PeerAS`).
- **AS-path regexps** support `[...]`, `[^...]`, AS ranges, `~*`/`~+`/`~{m,n}`,
  `PeerAS`, and anchors anywhere. Unknown bytes are errors rather than being
  skipped, which had turned `<[^AS1]>` into `<^AS1>`.
- **`mp-*` without an `afi` clause applies to every family** (RFC 4012 §2.5), and
  aut-num `import`/`mp-import` (and export/default) keep document order, which is
  their precedence.
- Real-data effect: policy diagnostics on the RIPE aut-num dump fell from 647 to
  23, all on 13 genuinely malformed lines.

### Changed (breaking) — policy

- `ASPathRE` anchors are atoms (`ASPathStart`/`ASPathEnd`); `AnchorStart`/
  `AnchorEnd` are removed. New regexp nodes: `ASPathClass`, `ASPathASNRange`,
  `ASPathPeerAS`, `ASPathSetTemplate`; `ASPathRepeat.Same`.
- `FilterPeerAS`, `FilterASExpr`, `FilterSetRef` gain `Op types.RangeOperator`;
  new `FilterSetTemplate`, `ASSetTemplate`, `SetNameTemplate`.
- `Import`/`Export`/`Default` gain `MP`; new `ParseMPImport`/`ParseMPExport`/
  `ParseMPDefault`. `AutNum.Imports`/`Exports`/`Defaults` are in document order.
- Policy diagnostic columns are 1-based; nesting past the cap reports once.

### Fixed (2026-09-21)

- **Comma-separated list values are split** (RFC 2622 §2). `members`,
  `mp-members`, `mbrs-by-ref`, `member-of`, `mnt-by`, `holes` and rtr-set
  `members` were parsed as one value per line, so `members: AS1, AS2` decoded
  as a single unrecognized member and indirect membership never matched.
- **No phantom AS0.** An unparseable set member (from a decoder or an IRRd `!i`
  payload) was the zero-valued `MemberAS` and expanded to AS0. It is now
  `MemberInvalid`, which the engine skips.
- **Set names are strictly validated**, closing IRRd `!i` command injection
  (pooled-connection desync) and whois flag injection through set names, and
  stopping `RS-FOO^+` from being looked up as a set literally named `RS-FOO^+`.
- **The engine re-checks every indirect membership claim** with the new
  `resolve.ClaimAllowed`, so a lenient `Source` can no longer widen a set.
- `ParsePrefixRange` rejects signed lengths such as `^+24`.

### Changed (breaking)

- `types.SetName` fields are unexported: use `Class()`, `Components()`,
  `String()`, `Canonical()`, `IsZero()`. It is now comparable. Mixed-class
  hierarchical names (`AS-X:RS-Y`) are rejected per RFC 2622 §5.
- `object.MemberKind`: `MemberInvalid` is the new zero value; `SetMember` gains
  `Op types.RangeOperator` for route-set members such as `AS1^24` / `RS-FOO^+`.
  A prefix or range operator inside an as-set is now `MemberInvalid`.
- `Expander.ExpandPrefixes` returns `resolve.ErrUnsupportedOperator` for a
  range operator applied to an AS or set member, rather than a silently wrong
  result, until range-level expansion lands.

### Added

- `types.RangeOperator` / `ParseRangeOperator` with RFC 2622 §5.2 composition
  (`Apply`); `ast.Attribute.List`; `object.ParseSetMember`;
  `resolve.ClaimAllowed`; the `object/list-empty-item` diagnostic; fuzz targets
  `FuzzParseSetName`, `FuzzParseRangeOperator`, `FuzzAttributeList`.

### Shipped (as of 2026-06-23)

- **`lexer` + `ast`** — hand-written line-oriented scanner with a total-partition
  guarantee (every source byte belongs to exactly one token's `Raw`), generic
  lossless object model, byte-for-byte `Object.String() == source` round-trip.
- **`types` + `object`** — leaf value types (`ASN`, `SetName`, `PrefixRange`,
  `AddrFamily`, `NICHandle`) and typed decoding for every common class
  (`AutNum`, `Mntner`, `Person`, `Role`, `Route`, `Route6`, `AsSet`,
  `RouteSet`, `Inetnum`, `Inet6num`, `AsBlock`, `InetRtr`, `Irt`, `Domain`,
  `Organisation`, plus the peering/filter/rtr-set variants).
- **`policy`** — full RFC 2622 §6 / RFC 4012 §2.5 grammar parsed into a sealed
  AST: `Import`/`Export`/`Default` with `afi`-scoped factors, `except`/`refine`,
  filter combinators, AS-path regexps preserved as their own AST.
- **`resolve`** — pure expansion `Expander` with `MaxDepth=32`,
  `MaxPrefixes=1<<20`, `MaxVisited=1<<17` budgets (all three return
  `ErrSetTooLarge` on breach), in-memory `MemSource`, dual-membership union,
  cycle-skipping DFS that matches `bgpq4`.
- **`resolve/{irrd,whois,rdap}`** — three live backends, all socket use isolated
  to those subpackages so `cd resolve && go list -deps .` excludes `net`.
- **Validation profiles** — `RIPE` (lenient, tolerates RIPE-only attrs) and
  `RFCStrict`, both data-driven from `object/profiles.go`.
- **Hardening** — `ParseOptions.MaxObjectBytes` for the streaming parser,
  per-backend `MaxResponse` caps on `whois`/`rdap`, RDAP body cap +
  redirect/scheme guards, `MaxVisited` engine cap.
- **GB-scale integration harness** — `examples/bulk-ripe` streams a RIPE bulk
  dump through the library with throughput + diagnostic-histogram + optional
  resolve smoke-test.
