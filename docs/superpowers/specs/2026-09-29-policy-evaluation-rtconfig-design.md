# Policy evaluation and RtConfig-style config generation

Status: design, awaiting review · 2026-09-29 · target releases v0.21.0, v0.22.0

## 1. Summary

The library parses every aut-num policy into an AST, flattens EXCEPT and REFINE
(`policy.Flatten`), expands every set class and, since v0.20.0, serves aut-nums
and inet-rtrs through `resolve.PolicySource`. Nothing consumes those policies.
This milestone is the consumer: what IRRToolSet's `peval` and `RtConfig` do, on
this engine.

Three layers, each shippable on its own:

1. **Engine core (`resolve`).** A filter evaluated for a bound peer (`PeerAS`,
   `AS1:AS-CUST:PeerAS`), into a *normal form*: what can be enumerated folds
   into prefix ranges; AS-path regexps and community tests stay symbolic,
   never evaluated. This is peval.
2. **Policy evaluation (`resolve/peval`).** An aut-num's policies for one BGP
   session — local AS and router, peer AS and router, address family — as the
   ordered clauses (normalized filter, actions) a route-map implements.
3. **Config generation (`resolve/rtconfig`, `resolve/cmd/rpslconf`).** Cisco
   IOS, Junos, IOS-XR and BIRD 2 printers, and a CLI reading rtconfig's
   `@RtConfig` template language.

Ship points: v0.21.0 is layers 1–2 plus `rpslconf -e` (peval mode); v0.22.0 is
layer 3. Each gets its own implementation plan and PR.

### Decisions taken in brainstorming

| Question | Decision |
|---|---|
| Scope | Full RtConfig: evaluator and vendor printers |
| Oracle for layer 3 | *Semantic* differential against IRRToolSet (same decisions and attributes on sampled routes), not byte-for-byte; deliberate differences pinned |
| Vendors | IOS/IOS-XE, Junos, IOS-XR (IRRToolSet oracle), BIRD 2 (model only) |
| CLI | New binary reading `@RtConfig` templates plus one-shot flags; rpslq untouched |
| Architecture | Layered with a vendor-neutral DNF (§4), not a monolith, not an `re2dfa` port |

## 2. Guardrails, as they bind this design

- **AS-path regexps are never evaluated against paths by the library.** They
  are *translated* into vendor syntax (design §7 anticipates exactly this). The
  as-sets a regexp names are *expanded* — a registry lookup, not path
  evaluation — so a printer needs no I/O.
- **Test-only exception, confirmed in brainstorming:** the test oracles (§9.1,
  §9.3, `FuzzTranslateRegexp`) match regexps against *synthetic* paths in
  internal test code. No exported API does.
- **Purity.** `resolve`, `resolve/peval` and `resolve/rtconfig` import no `net`.
  Sockets stay in the existing backends; only `cmd/rpslconf` opens them.
- **Never approximate.** A term that cannot be decided for a session is
  reported (`Undecided`); a construct a vendor cannot express is
  `ErrUnsupported`; a partial result is never returned as a whole one.
- **rpslq stays bgpq4's.** Nothing here changes its options or output.

## 3. What the IRRToolSet spike found (2026-09-29)

A throwaway spike ran IRRToolSet 5.1.3 against `irrtest`. Its artifacts
(templates, 50 peval cases, rtconfig output per vendor, wire logs, the Linux
build recipe, the irrtest diff) are in the session scratchpad
(`irrtoolset-spike/`); the plan moves what it needs into `resolve/testdata`.

**Running it.**
- The Homebrew arm64 bottle mis-parses every command-line option (a variadic
  ABI bug in `irrutil/Argv.cc`); only `IRR_HOST`/`IRR_PORT`/`IRR_SOURCES` work,
  so it can print cisco only.
- A Linux source build works at `-O0` (the GCC 14 `-O2` build segfaults
  printing any prefix set) and matched the bottle where both run. There is no
  apt package; CI must build it.
- 7–40 ms per invocation.

**Wire.** It sends `!!`, `!s<src>`/`!s-*`, `!s-lc`, `!v`, `!i<set>,1` (as-sets
and route-sets: the server expands), `!m<class>,<key>` for filter-sets and
peering-sets, `!man,ASn`, `!mir,NAME`, `-K -r -i origin ASn`, `q`. IRRd 4 —
RADB's 4.4.2 included — answers `D` to `!man`/`!mir`, so IRRToolSet cannot read
an aut-num from any IRRd 4; its `-f cache.rpsl` file supplies them instead, with
identical output. Set expansion is therefore the *server's*, already held to
bgpq4; the oracle checks policy logic and rendering only.

**irrtest needs three changes:** `!v` must contain "version" (IRRToolSet
segfaults otherwise); `!s-*` must answer `C`; the IRRd port must answer
RIPE-style `-K -r -i origin ASn` with primary-key lines ending `\n\n\n`, as IRRd
4 does.

**IRRToolSet bugs — each becomes a pinned divergence (§9.4):**

| # | Input | rtconfig/peval does | Correct |
|---|---|---|---|
| D1 | `AS-FOO AND NOT AS10`, `NOT AS10` | `NOT ANY` | AS-FOO's routes less AS10's |
| D2 | route-set member `AS-BAZ^24-26` | `permit 0.0.0.0/0` (hijack-relevant) | AS-BAZ's routes, ^24-26 |
| D3 | IPv6 `^+` ranges, v6 filter-sets | enumerates without end | ranges |
| D4 | IPv6-only mp-import | an IPv4 route-map entry with no match: permits all IPv4 | no IPv4 entry |
| D5 | `import-via:` | silently ignored | evaluated (§6); printers refuse (§7) |
| D6 | `default:` with `pref` on cisco; any default on Junos | pref dropped; "default not implemented" | rendered |
| D7 | `configureRouter` | drops router-specific clauses | deferred (§8) |
| D8 | `importGroup` with a template | empty policy | deferred (§8) |
| D9 | exit status | 0 after "no object for AS1" | non-zero |
| D10 | peval prints `AS2-AS3`, PeerAS as `AS4294967295` | not re-parseable | `NormalFilter.String` parses back |

**Rendered correctly by rtconfig** (so usable as oracle): specification order,
`pref=N` → local-preference 1000−N, `med` → metric, `community.append` →
`set community … additive`, `aspath.prepend`, AND/OR over prefix sets,
EXCEPT/REFINE, community matches, AS-path regexps, `NOT <regexp>` as
deny-then-permit, PeerAS templates — on cisco, junos and ciscoxr.

## 4. Layer 1 — engine core (`resolve`, additive)

### 4.1 Peer binding

```go
type Expander struct {
    // … existing fields …

    // Peer binds PeerAS for EvalFilter and NormalizeFilter: PeerAS denotes
    // Peer's routes, and a template (AS1:AS-CUST:PeerAS, in a filter, an AS
    // expression or an AS-path regexp) the set it names for Peer. Zero leaves
    // them unbound: a *NotEnumerableError from EvalFilter, as before. It binds
    // inside filter-sets too.
    Peer types.ASN
}
```

AS0 is never a peer, so zero is "unbound". `Exclude` treats a bound PeerAS as
it treats an AS term: excluded only where met inside a filter-set.

### 4.2 Normal form

```go
// NormalizeFilter evaluates f into disjunctive normal form. What can be
// enumerated folds into prefix ranges; AS-path regexps and community tests stay
// symbolic and are never evaluated (design §13). NOT is pushed to the leaves.
// AS-ANY and RS-ANY in filter position denote every route, as ANY does (RFC
// 2622 §5.1, §5.2).
func (e *Expander) NormalizeFilter(ctx context.Context, f policy.Filter) (NormalFilter, error)

// NormalFilter matches a route when any of its conjuncts does; one with no
// conjuncts matches nothing.
type NormalFilter struct {
    Conjuncts []Conjunct
    missing   []types.SetRef
}

func (f NormalFilter) Missing() []types.SetRef
// String renders f as RPSL that policy.ParseFilter reads back to a filter
// matching the same routes.
func (f NormalFilter) String() string

// Conjunct matches a route when every part does.
type Conjunct struct {
    Prefixes    RangeSet         // the route lies in one of these; ANY is 0.0.0.0/0^0-32
                                 // and ::/0^0-128, trimmed to the Expander's AFI
    NotPrefixes RangeSet         // …and in none of these; only ranges meeting Prefixes are kept
    Paths       []PathMatch      // each must hold
    Communities []CommunityMatch // each must hold
}

// AnyPrefix reports whether Prefixes is every prefix of the Expander's AFI, so
// a printer can leave the prefix match out.
func (c Conjunct) AnyPrefix() bool

type PathMatch struct {
    Negated bool
    RE      *policy.ASPathRE         // PeerAS and templates bound
    Sets    map[types.SetName]ASNSet // every as-set RE names, expanded
}

type CommunityMatch struct {
    Negated bool
    Test    policy.FilterCommunity
}

const (
    // … LimitPrefixes, LimitVisited, LimitDepth …
    LimitConjuncts // MaxConjuncts: conjuncts one NormalizeFilter built (String: "MaxConjuncts")
)

type Expander struct {
    // …
    MaxConjuncts int // cap on conjuncts per NormalizeFilter (default 1<<12; <0 unlimited)
}
```

**Construction.**
- Literals: a prefix list, set reference, AS expression, bound PeerAS or bound
  template is an enumerable literal (a `RangeSet`, via the existing `filterEval`
  machinery: memo, fixpoint over filter-set cycles, `MaxVisited`, `MaxPrefixes`,
  `Missing`). A regexp or community test is a symbolic literal.
- NOT is pushed down by De Morgan; a negated enumerable literal goes to
  `NotPrefixes`, a negated symbolic one sets `Negated`.
- An OR whose operands are all enumerable folds to one literal (a union)
  *before* distribution, and an AND of enumerable literals to one (the existing
  range intersection). Only ORs mixing in symbolic literals multiply conjuncts.
- Within a conjunct, positive prefix literals intersect, negated ones union.
  A conjunct whose `Prefixes` is empty is dropped. `NotPrefixes` ranges that
  meet no `Prefixes` range are dropped. Conjuncts are deduplicated.
- Unbound PeerAS or template (Peer zero): `*NotEnumerableError`, as EvalFilter.
- `FilterPathRE` with a nil `Regexp` (it did not parse): `*NotEnumerableError`
  naming it — a printer cannot translate what did not parse.

**Contract with EvalFilter.** EvalFilter is unchanged. For every filter without
AS-ANY/RS-ANY, if NormalizeFilter returns only conjuncts with no `NotPrefixes`,
`Paths` or `Communities`, the union of their `Prefixes` equals EvalFilter's
answer; otherwise EvalFilter returns the `*NotEnumerableError` it returns today.

## 5. Layer 2 — policy evaluation (`resolve/peval`, new package)

```go
package peval

// Session is one BGP session, seen from Local. Routers are optional.
type Session struct {
    Local, Peer       types.ASN
    LocalRtr, PeerRtr netip.Addr       // zero: not given
    AF                types.AddrFamily // selects mp-* terms (Import.Terms); AF.AFI trims prefixes
}

// Evaluator evaluates an aut-num's policies for a session. All I/O goes
// through Src. Expander is a template — limits, Exclude, Concurrency — whose
// Src, AFI and Peer every call sets. Wrap Src in resolve.Cache to share
// lookups across calls; within one call each set is expanded once.
type Evaluator struct {
    Src      resolve.PolicySource
    Expander resolve.Expander
    Source   string // registry to read Local's aut-num from; "" = precedence
}

func (v *Evaluator) Import(ctx context.Context, s Session) (Policy, error)    // import: and mp-import:
func (v *Evaluator) Export(ctx context.Context, s Session) (Policy, error)    // export: and mp-export:
func (v *Evaluator) ImportVia(ctx context.Context, s Session) (Policy, error) // import-via:
func (v *Evaluator) ExportVia(ctx context.Context, s Session) (Policy, error) // export-via:
func (v *Evaluator) Default(ctx context.Context, s Session) (Defaults, error)

// Filter is peval: f normalized for peer (0: unbound) in address family af.
func (v *Evaluator) Filter(ctx context.Context, f policy.Filter, af types.AFI, peer types.ASN) (resolve.NormalFilter, error)

// Policy is what Local does with the session's routes. A route takes the first
// clause it matches — the RFC 2622 §6.1 specification-order rule — and a route
// matching none is refused (import) or not announced (export).
type Policy struct {
    Clauses   []Clause
    Undecided []Undecided // terms the session might match that could not be decided
    missing   []types.SetRef
    rtrs      []string
}
func (p Policy) Missing() []types.SetRef
func (p Policy) MissingRouters() []string // inet-rtr names a peering named that Src does not have

type Clause struct {
    Index   int                  // the attribute's position in AutNum.Imports (Exports, ImportVia, ExportVia)
    Term    policy.Term          // the flattened term, as written: provenance
    Actions []policy.Action
    Filter  resolve.NormalFilter // PeerAS bound (§5.2)
    Remote  policy.Peering       // *-via only: the peering beyond the via one
}

type Defaults struct {
    Clauses   []DefaultClause
    Undecided []Undecided
    missing   []types.SetRef
    rtrs      []string
}
func (d Defaults) Missing() []types.SetRef
func (d Defaults) MissingRouters() []string

type DefaultClause struct {
    Index    int // position in AutNum.Defaults
    Peering  policy.Peering
    Actions  []policy.Action
    Networks *resolve.NormalFilter // nil: no networks clause
}

type Undecided struct {
    Index int
    Term  policy.Term
    Why   string // "peer router not given", "peering regexp", "protocol OSPF", …
}
```

### 5.1 Evaluation

1. `Src.AutNum(ctx, s.Local, v.Source)`; not found wraps `resolve.ErrNotFound`,
   `ErrNoPolicy` passes through.
2. For each attribute in document order: skip it unless `AppliesTo(s.AF)`; skip
   it into `Undecided` if `Protocol` or `IntoProtocol` is set and is not BGP4
   (compared without case); else `Terms(s.AF)` (`Flatten`).
3. For each term, decide whether its peering matches the session (§5.3). A
   match becomes a `Clause` with the term's filter normalized (§5.2); a term
   that cannot be decided becomes `Undecided` and contributes no clause.
4. `Missing()` gathers sets missing from peerings and filters, sorted;
   `MissingRouters()` the inet-rtr names not found.

Errors are returned whole — `ErrFlattenTooLarge`, `*resolve.SetTooLargeError`,
`*resolve.NotEnumerableError` (a filter naming a regexp that did not parse),
context errors. There is no partial `Policy`: a partial filter is a wrong one.

### 5.2 Binding

Each clause's filter is normalized with `Expander.Peer = s.Peer` and
`Expander.AFI = s.AF.AFI`. For a `*-via` clause, `Peer` is Remote's AS when
Remote is a single AS number (`PeeringAS{AS: ASNum}`); otherwise, if the filter
uses PeerAS or a template, the term is `Undecided` ("PeerAS beyond a via
peering names no single AS").

### 5.3 Matching a peering

| Peering part | Session value | Rule |
|---|---|---|
| `ASNum` | Peer | equal |
| `ASSetRef` | Peer | `ExpandAS` contains it (memoised per call); missing set: no match, Missing |
| AS-ANY | Peer | always |
| `ASSetTemplate` | Peer | bound to Peer, then as `ASSetRef` |
| `ASExprBinary` | Peer | AND / OR / EXCEPT as booleans |
| `Router` (peer side) | PeerRtr | router expression (below) |
| `AtRouter` (local side) | LocalRtr | router expression (below) |
| `PeeringSetRef` | — | `ExpandPeerings`; matches if any listed peering does (nested sets already replaced) |
| `PeeringRegexp` | — | Undecided ("peering regexp") |

Router expression against an address `a`:

- `RouterAddr`: equal.
- `RouterName`: `Src.InetRtr(name, "")`; matches if `a` is among its `ifaddr:`
  and `interface:` addresses. Not found: no match, recorded in
  `MissingRouters()`.
- `RouterSetRef`: `ExpandRouters`; each `RouterID` compares as an address or,
  for a name, as `RouterName`.
- `RouterExprBinary`: AND / OR / EXCEPT as booleans.
- **Router not given** (zero address) and the term constrains that side:
  `Undecided` ("peer router not given" / "local router not given"). Never
  guessed either way.

No DNS: every lookup is forward (§8.2 of the 2026-09-28 spec).

### 5.4 Default

`Default` reads `AutNum.Defaults` the same way: `AppliesTo(s.AF)`, the peering
matched by §5.3, `Networks` normalized (nil when absent).

## 6. `*-via` in this milestone

`ImportVia`/`ExportVia` match the *via* peering against the session (the route
server is the BGP neighbour) and carry the peering beyond it in `Remote`.
IRRToolSet ignores via entirely (D5), so nothing checks its rendering; the
printers refuse via clauses (`ErrUnsupported`) until a design for rendering
them — an AS-path condition on Remote — has an oracle.

## 7. Layer 3 — printers (`resolve/rtconfig`, new package, pure)

```go
package rtconfig

type Vendor uint8

const (
    IOS   Vendor = iota + 1 // Cisco IOS / IOS-XE ("cisco")
    Junos                   // "junos"
    IOSXR                   // "ciscoxr"
    BIRD2                   // "bird"
)

func ParseVendor(s string) (Vendor, error) // rtconfig's -config names, plus "bird"

type Generator struct {
    Vendor Vendor
    // MaxPreference maps RPSL pref N to local-preference MaxPreference−N, as
    // rtconfig's cisco_max_preference does (default 1000). pref > MaxPreference
    // is an error.
    MaxPreference int
    Names         Naming
}

// Naming holds rtconfig's naming and numbering knobs (§8.2), with its defaults.
type Naming struct {
    MapName         string // cisco_map_name, "MyMap_%d_%d"
    MapFirstNo      int    // cisco_map_first_no, 1
    MapIncrementBy  int    // cisco_map_increment_by, 1
    PrefixACLNo     int    // prefix_acl_no
    ASPathACLNo     int    // aspath_acl_no
    CommunityACLNo  int    // community_acl_no
    AccessListNo    int    // cisco_access_list_no
    JunosPolicyName string // junos_policy_name, "policy_%d_%d"
}

func (g *Generator) WriteImport(w io.Writer, s peval.Session, p peval.Policy) error
func (g *Generator) WriteExport(w io.Writer, s peval.Session, p peval.Policy) error
func (g *Generator) WriteDefault(w io.Writer, s peval.Session, d peval.Defaults) error
func (g *Generator) WritePrefixList(w io.Writer, f resolve.NormalFilter) error // access_list
func (g *Generator) WriteASPathList(w io.Writer, m resolve.PathMatch) error    // aspath_access_list

// ErrUnsupported is wrapped, naming the term and the vendor, whenever a vendor
// cannot express what a policy says. Nothing is approximated or dropped.
var ErrUnsupported = errors.New("rtconfig: not expressible for this vendor")
```

A `Generator` numbers lists and maps across calls, as rtconfig does across one
template; it is not safe for concurrent use.

### 7.1 Rendering

- **Structure.** Each clause's conjuncts become consecutive permit entries of
  one route-map / policy-statement / route-policy / BIRD filter, each carrying
  the clause's actions, followed by the implicit deny. Route-map first-match
  is the RFC's specification order. Import and export also write the
  neighbour attachment (`neighbor … route-map … in`, Junos `import`, XR
  `route-policy … in`, BIRD `import filter`).
- **Negation stays inside the lists**, so a route failing clause *k* falls
  through to clause *k+1*: `NotPrefixes` become deny entries ahead of the
  permits of the same prefix list; a negated regexp becomes a path list of
  deny-then-permit-any.
- **Prefix lists.** IOS `ip prefix-list`/`ipv6 prefix-list`, Junos
  `route-filter` in the policy term, XR `prefix-set`, BIRD `[ p{m,n}, … ]`. An
  any-prefix conjunct has no prefix match. Entry rendering reuses
  `internal/filtergen` where its output fits.
- **Regexps.** `policy.ASPathRE` → IOS/XR `ios-regex`, Junos as-path regex,
  BIRD path mask; an as-set becomes an alternation from `PathMatch.Sets`.
  `ErrUnsupported`: `~*`/`~+`/`~{m,n}` over more than a single AS; two positive
  regexps in one conjunct on IOS (same-type matches are ORed); what a BIRD mask
  cannot say.
- **Communities.** Standard (`1:2`) and well-known ones. Contains → a
  community list / set; `==` → `exact-match` where the vendor has one, else
  `ErrUnsupported`. Large and extended communities: `ErrUnsupported` until
  `policy` types them.
- **Actions.** `pref`, `med` (and `med = igp_cost` where the vendor has it),
  `community =`/`.=`/`.append()`/`.delete()`, `aspath.prepend()`, `next-hop`.
  Any other RP-attribute: `ErrUnsupported`.
- **Refused this milestone:** via clauses (§6); a SAFI other than unicast.
- **Capability table.** Vendor × feature, in `docs/rpslconf.md`, generated from
  the code and held to it by a test, as `docs/diagnostics.md` is.

## 8. CLI — `resolve/cmd/rpslconf`

Logic in `resolve/internal/rpslconf`; `main` stays a shim, as rpslq's does.

### 8.1 Modes

- `rpslconf [flags] < template` — rtconfig mode: lines that are not
  `@RtConfig` commands pass through unchanged (the keyword is matched without
  case, as rtconfig does).
- `rpslconf [flags] -e '<filter>' [--peer AS]` — peval mode: prints
  `NormalFilter.String()`. A leading `afi <list>` is read with the new
  `policy.ParseMPFilter`.

```go
// ParseMPFilter parses an mp-filter with an optional leading afi clause
// ("afi ipv6.unicast AS-FOO"), as peval accepts it. No afi clause: nil AFIs.
func ParseMPFilter(s string) ([]types.AddrFamily, Filter, []ast.Diagnostic)
```

### 8.2 Template commands

| Command | Status |
|---|---|
| `import`/`export <AS> <rtr> <AS> <rtr>` | supported; AF from the router addresses' family |
| `default <AS> <AS>` | supported |
| `set <knob> = <value>` | `cisco_map_name`, `cisco_map_first_no`, `cisco_map_increment_by`, `prefix_acl_no`, `aspath_acl_no`, `community_acl_no`, `cisco_access_list_no`, `cisco_max_preference`, `junos_policy_name`, `sources`, and the deprecated `cisco_*_acl_no` spellings |
| `access_list filter <f>`, `aspath_access_list filter <f>` | supported |
| `printPrefixes`/`printPrefixRanges "<fmt>" filter <f>` | supported, with `%p %l %L %n %m %k %K %%` |
| `networks <AS>`, `v6networks <AS>` | supported |
| `printSuperPrefixRanges`, `configureRouter`, `importGroup`, `exportGroup`, `importPeerGroup`, `static2bgp`, `*pkt_filter` | "not supported yet" (error). rtconfig's own versions are broken (D7, D8) or have no oracle |

### 8.3 Flags and exit status

`-config cisco|junos|ciscoxr|bird` (default cisco), `-h host`, `-p port`,
`-s sources`, as rtconfig names them; `--whois` and `--dump files…` (loaded with
`Corpus.KeepPolicy`) as rpslq has them; `-e`, `--peer`. The code that opens a
backend moves from `internal/rpslq` to a shared internal package; rpslq's
behaviour and tests are unchanged. Any error — including an aut-num not found,
`ErrUnsupported`, a limit — exits non-zero (D9); Undecided terms and missing
sets are warnings on stderr.

## 9. Tests

Every layer is held to an oracle independent of the code under test.

1. **Route model (test-only, `resolve/internal/routemodel`).** A brute-force
   RFC matcher: does a `policy.Filter` accept a concrete route (prefix, AS
   path, communities), given a model IRR — straight from the generator's model,
   never from parsed text or `filterEval`. Random filters over the random IRRs
   of `model_test.go` (NOT/AND/OR, prefix lists, every set class, operators,
   regexps with sets and `~*`, communities, PeerAS and templates, AS-ANY) are
   checked on boundary-biased sampled routes: `NormalizeFilter` accepts exactly
   what the model accepts, over MemSource and every backend against `irrtest`.
   `EvalFilter` equals the union of pure conjuncts (§4.2). `MaxConjuncts` holds
   at exactly the true count.
2. **Policy model.** Random aut-nums: import/export/mp-*/`*-via`/default,
   EXCEPT/REFINE with and without afi clauses, peering-sets, AS expressions,
   router addresses, inet-rtr names, rtr-sets, protocols. The oracle applies RFC
   2622 §6 per route — first term whose peering and filter match, its actions —
   *without* `Flatten`, and marks a term Undecided exactly when a needed router
   is not given. Checked over MemSource, Corpus with `KeepPolicy`, irrd and
   whois against `irrtest`.
3. **Config simulator (test-only, `resolve/internal/cfgsim`).** Parses the IOS
   (extended ACLs and prefix-lists), Junos, XR and BIRD subsets we emit — and
   rtconfig emits — into a route-map model, and runs it on the sampled routes.
   For all four vendors, our config's decision and attributes equal peval's.
   It is BIRD's only semantic oracle; when `bird` is installed, every BIRD
   config the tests emit must also pass `bird -p` (syntax).
4. **IRRToolSet differential.** Random IPv4 import/export policies: sets from
   `irrtest`, aut-nums and inet-rtrs through `-f cache.rpsl`, one template fed
   to rtconfig and to rpslconf, both outputs through `cfgsim`: same decision and
   attributes on every sampled route, for cisco, junos and ciscoxr. Runs when
   `rtconfig` is installed, as the bgpq4 tests do; a checked-in snapshot of
   rtconfig's output keeps the fixed cases running without it. D1–D10 are
   pinned in `resolve/testdata/rtconfig/divergences.md`, each with a test, so a
   change on either side fails. `scripts/build-irrtoolset.sh` builds the `-O0`
   binary in Docker; CI builds and caches it. `irrtest` gets §3's three changes.
5. **peval differential (narrow).** peval against `rpslconf -e` on the cases
   where peval is right (prefix lists, sets, AND/OR, NOT over prefixes); the
   route model is the oracle for the rest.
6. **Fuzzing, 36 → 40 targets.** `FuzzNormalizeFilter` (no panic; caps hold;
   `String()` parses back to a filter the route model says matches the same
   sampled routes); `FuzzTranslateRegexp` (every parsed regexp's vendor
   translation, or `ErrUnsupported`; a translation matches the same synthetic
   paths as the RFC matcher); `FuzzParseTemplate`; `FuzzParseMPFilter`.
7. **Contracts.** The capability table matches the code; every `Undecided.Why`
   and `ErrUnsupported` cause is documented in `docs/rpslconf.md`.
8. **Real data (`RPSL_REALDATA`).** RIPE's dumps with `KeepPolicy`: for a sample
   of aut-nums, import and export for every peer AS their policies name, in
   both families, rendered for all four vendors. No panic, bounded time; the
   report counts Undecided and `ErrUnsupported` by cause.
9. **Invariants.** `cd resolve && go list -deps . ./peval ./rtconfig` has no
   `net`; leaf isolation unchanged.

## 10. Documentation and release

- `docs/rpsl-go-design.md`: §8 gains the normal form and peer binding; a new
  section for `resolve/peval` and `resolve/rtconfig`; §12 status; §13 notes the
  test-only regexp matcher.
- `docs/rpslconf.md`: rpslconf for rtconfig users — template commands, knobs,
  the capability table, Undecided causes, divergences from rtconfig and why.
- `resolve/README.md`, README status table, CHANGELOG.
- CLAUDE.md: engine traps (Undecided, never guess a router; negation inside
  lists; `ErrUnsupported` never approximates), commands (fuzz list, the
  rtconfig differential and its build script).
- v0.21.0 (layers 1–2, `rpslconf -e`) is additive. v0.22.0 (layer 3) moves the
  backend-opening code out of `internal/rpslq`, an internal change.

## 11. Out of scope

- Evaluating regexps or community tests against paths — ever, in the library.
- `configureRouter`, groups, `static2bgp`, packet filters (§8.2).
- Rendering `*-via` clauses; multicast SAFIs in printers.
- Typed large and extended communities in `policy`.
- Peer-consistency checks and linting (AS X exports to Y what Y imports from X):
  the next consumer of `peval`.
- Arista, Nokia, FRR, OpenBGPD printers.

## 12. Risks

- **The oracle is old and partly broken.** IRRToolSet runs only as an `-O0`
  source build, reads aut-nums from a file, and has ten known bugs. The
  in-repo models (§9.1–9.3) are the primary oracles; IRRToolSet guards against
  our models sharing a misreading of the RFC.
- **DNF growth.** A filter mixing many ORs with regexps multiplies conjuncts;
  `MaxConjuncts` makes that an error, not a hang. Real-data counts (§9.8) show
  whether the default fits.
- **The simulator is ours.** `cfgsim` reads vendor syntax as we understand it.
  Where both configs go through it, a misreading shared by printer and
  simulator would hide; the IRRToolSet differential (a second author's
  printer) is the check on that for three vendors, and BIRD's syntax is
  checked by `bird -p` in CI when installed.
- **Routers without a peering address.** Sessions named by inet-rtr name, not
  address, are not supported by the template (rtconfig takes addresses too).
