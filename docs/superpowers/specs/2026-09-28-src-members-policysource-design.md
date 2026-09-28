# Registry-scoped set members and PolicySource

Status: design, awaiting review · 2026-09-28 · target release v0.20.0

## 1. Summary

Two changes land together so that `resolve.Source` breaks once before v1:

1. **`src-members:`** — draft-ietf-grow-rpsl-registry-scoped-members-00 (GROW WG
   document, April 2026). An as-set or route-set may name each nested set
   together with the registry it lives in (`RIPE::RS-SECOND`), and a resolver
   must fetch it from that registry only. This touches every layer: a scoped
   reference type in `types`, a typed attribute and validation in `object`,
   scoped lookups through `resolve.Source` and every backend.
2. **`PolicySource`** — a sibling interface of `Source` that also serves
   aut-nums and inet-rtrs, the objects routing policy names outside sets. It is
   shaped for the next milestone, a `peval`/RtConfig-style policy evaluator, and
   has no consumer in this change (§8 checks its shape against a sketch).

Only the first breaks `Source`. The second is additive.

## 2. The draft, as it binds this design

Quoted or paraphrased from -00; section numbers are the draft's.

**Syntax (§2.1, §2.2).** `src-members:` is optional and multi-valued.

| Class | Value: list of |
|---|---|
| as-set | `as-number`, or `registry-name::as-set-name` |
| route-set | an IPv4 or IPv6 `address-prefix-range`; `registry-name::route-set-name`, optionally followed by a range operator; `registry-name::as-set-name`; `as-number` |

A set reference MUST carry a registry. An operator is allowed only on a prefix
range and on a scoped route-set; an ASN or scoped as-set in `src-members:`
carries none (stricter than `members:`, where RFC 2622 §5.2 allows `AS1^24`
and `AS-FOO^+`).

**Resolution (§2.3).**

1. Include every `src-members:` member. A scoped set is matched on both
   registry and primary key; a registry unknown to the resolver matches no set.
2. Include each `members:`/`mp-members:` member whose primary key is not already
   in `src-members:`. Ambiguity among same-named sets without a scope stays
   undefined, as before.
3. The scope selects where the referenced object is fetched and nothing more:
   its own nested references are resolved from its own `src-members:`, or by
   the default source selection. The restriction does not cascade.

**Query parameter (§2.3.2).** Software MUST let the user restrict the initial
lookup to a registry (`RIPE::AS-DEMO`), and that restriction MUST NOT cascade.

**Validation (§3.1, §3.3).** For authoritative registries: every `src-members:`
reference, registry removed, MUST also appear in `members:`/`mp-members:`
(repeated attributes combined); references in `src-members:` MUST be unique
without their registry (`RIPE::AS-OTHER, ARIN::AS-OTHER` is rejected). A member
only in `members:`/`mp-members:` is permitted.

**Generation (§3.2)** of `members:` from `src-members:` is registry-software
behaviour and is out of scope here (§11).

**Security (§5).** Cycle detection MUST; depth or size limits RECOMMENDED. The
engine already has both.

## 3. Decisions and rejected alternatives

| Decision | Chosen | Rejected, and why |
|---|---|---|
| How scope travels through the engine | A new opaque, comparable `types.SetRef{source, name}` is the engine's reference and graph key | Scope inside `types.SetName`: SetName is also a set's own name, what `member-of:` and `checkSet` compare; a scoped fetch would fail `set.SetName() == ref`, and consumers' map keys would change meaning silently. An optional `ScopedSource` interface found by type assertion: every wrapper must forward it, and a backend without it must fail closed or silently fall back to precedence — the collision the draft exists to prevent |
| Where §2.3 steps 1–2 live | `object.DirectMembers`, pure, over one object | In `resolve`: lint and `rpslq -d` want the same answer the engine uses |
| A same-key conflict (§3.3) in data | Both entries dropped, with an Error; the key resolves through `members:` as today | Picking one: arbitrary, and the draft forbids the object outright |
| Profiles | Opt-in `object.WithSrcMembers(p)`; pinned profiles unchanged | Adding to RIPE/IRRd/ARIN: they are fixture-checked against what those registries run, which has no `src-members:` |
| src-members over IRRd | `irrd.Source.SrcMembers bool`, off by default: also fetch `!m` | Always: doubles set queries against RADB's rate cap for data no IRRd holds. Unsupported: leaves rpslq's main backend without it |
| PolicySource shape | Sibling interface embedding `Source`: `AutNum`, `InetRtr`, each registry-scopable | Generic `GetObject(class, key)`: untyped. Merged into `Source`: forces every expansion-only backend to implement it |
| Aut-nums in `Corpus` | Kept as lossless text, decoded per call | Kept decoded: 707 MB for RIPE's 39,918 aut-nums, more than the whole Corpus (measured, §7.2) |

## 4. `types`

`types` stays a leaf; nothing below imports anything of ours.

```go
// SetRef is a reference to a set, optionally scoped to one registry
// (draft-ietf-grow-rpsl-registry-scoped-members: "RIPE::AS-FOO"). It is opaque
// and canonical, as SetName is: the source is upper-cased, so every spelling of
// a reference is == and one map key. An unscoped ref leaves the choice of
// registry to the Source's precedence.
type SetRef struct {
    source string // "" or a canonical source name
    name   SetName
}

// Ref returns the unscoped reference to name.
func Ref(name SetName) SetRef

// NewSetRef returns name scoped to source, which ParseSourceName validates.
// An empty source gives the unscoped reference.
func NewSetRef(source string, name SetName) (SetRef, error)

// ParseSetRef parses "AS-FOO" or "RIPE::AS-FOO". Whitespace around "::" is an
// error.
func ParseSetRef(s string) (SetRef, error)

func (r SetRef) Source() string  // "" when unscoped
func (r SetRef) Name() SetName
func (r SetRef) IsScoped() bool
func (r SetRef) IsZero() bool
func (r SetRef) String() string  // "RIPE::AS-FOO" or "AS-FOO"

// ParseSourceName validates and canonicalizes an IRR source name: ASCII
// letters, digits, '-' and '_', upper-cased, so it is safe in an IRRd "!s" or
// a whois "-s" query.
func ParseSourceName(s string) (string, error)
```

- `ParseSourceName` replaces the three copies of this check: irrd's and whois's
  `validSourceName` and rpslq's `SOURCE::` parsing.
- Case folding is done in place; no offset found in an upper-cased copy is ever
  used to slice the original (the v0.19.0 "ɐ" panic).
- `ParseSetRef` splits at the first `::`. A set name cannot contain `:` twice in
  a row, so the split is unambiguous.

## 5. `object`

### 5.1 Types

```go
type SetMember struct {
    Kind   MemberKind
    AS     types.ASN
    Set    types.SetName
    Source string // NEW: the registry of a MemberSet from src-members:; "" otherwise
    Range  types.PrefixRange
    Op     types.RangeOperator
    Raw    string
}

// Ref returns the reference a MemberSet names, scoped when Source is set.
func (m SetMember) Ref() types.SetRef

// ParseSrcMember parses one src-members: list item for a set of class
// container (draft §2.1, §2.2). As-set: an ASN or REG::as-set. Route-set: also
// a prefix range, and REG::route-set with an optional range operator. A set
// reference without a registry, and a range operator on an ASN or a scoped
// as-set, are errors. On failure it returns a MemberInvalid member carrying
// Raw, as ParseSetMember does.
func ParseSrcMember(item string, container types.SetClass) (SetMember, error)

type AsSet struct    { …; SrcMembers []SetMember } // src-members:
type RouteSet struct { …; SrcMembers []SetMember } // src-members:

type Set interface {
    NamedSet
    SetMembers() []SetMember // members: plus mp-members:, as written (unchanged)
    SetSrcMembers() []SetMember // NEW: src-members:, as written (a method named SrcMembers would clash with the field)
}

// DirectMembers returns the members a resolver follows (draft §2.3 steps 1-2):
// every src-members: member, then each members:/mp-members: member whose key
// no src-members: member has. It reads one object and does no I/O.
func DirectMembers(s Set) []SetMember
```

### 5.2 Member keys

A member's key is its primary key with the registry removed. §2.3 step 2, §3.1
and §3.3 all compare keys.

| Member | Key |
|---|---|
| Nested set (`AS-X`, `RIPE::AS-X`, `RS-Y^+`) | the canonical set name |
| AS number (`AS1`, `AS1^24`) | the ASN |
| Prefix range (`192.0.2.0/24^+`) | the canonical `types.PrefixRange`, operator included (a range has no primary key but itself) |

So `members: AS1^24` with `src-members: AS1` follows `AS1` without the
operator, as the draft's primary-key rule says, and `members: RS-Y^-` with
`src-members: RIPE::RS-Y^+` follows `RIPE::RS-Y^+`.

### 5.3 Decoding and diagnostics

The decoder reads `src-members:` on as-set and route-set whatever the profile,
combining repeated attributes (§3.1). It emits:

| Rule | Severity | When |
|---|---|---|
| `object/as-set-src-members`, `object/route-set-src-members` | Error | An item that does not parse: a set without a registry, an operator where §2 allows none, a prefix in an as-set |
| `object/as-set-src-members-unlisted`, `object/route-set-src-members-unlisted` | Warning | A key not in `members:`/`mp-members:` (§3.1). The resolver still follows it (§2.3 step 1) |
| `object/as-set-src-members-conflict`, `object/route-set-src-members-conflict` | Error | One set name under two registries (§3.3). Both entries are left out of `SrcMembers`, so that name resolves through `members:` by precedence, as it does today |

A name listed twice under the same registry is a duplicate, not a conflict,
and is kept once.

### 5.4 Profiles

```go
// WithSrcMembers returns p that also admits src-members: (optional,
// multi-valued) on as-set and route-set, named p.Name()+"+src-members".
func WithSrcMembers(p Profile) Profile
```

The RIPE, IRRd and ARIN profiles stay as their fixtures pin them until a
registry deploys the attribute. `TestEveryAttributeLandsInItsOwnField` adds
`WithSrcMembers(RFCStrict)` to its profiles, which is what makes it require
`SrcMembers` to be fed.

## 6. `resolve` engine

### 6.1 The Source break

```go
type Source interface {
    // GetSet fetches the set ref names. An unscoped ref is resolved by the
    // Source's precedence. A scoped ref is resolved only in that registry —
    // any registry the Source holds, even one its default list leaves out —
    // and a registry it does not know is ErrNotFound (draft §2.3 step 1).
    // For a scoped ref the returned set's SetSource() must be ref.Source().
    GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error)

    // Unchanged. Routes are never scoped: member ASes' routes come from the
    // default precedence (the scope does not cascade, §2.3), as bgpq4 does for
    // SOURCE::SET.
    OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

    // Unchanged. Claims already come only from set.SetSource().
    MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error)
}

// ErrNotFound's message becomes "resolve: not found" (it now also covers
// aut-nums and inet-rtrs); the value, and errors.Is, are unchanged.
```

### 6.2 Entry points

`ExpandAS`, `ExpandPrefixRanges`, `ExpandPrefixes`, `ExpandRouters`,
`ExpandPeerings` and `ExpandFilterSet` take a `types.SetRef` in place of a
`types.SetName`. An unscoped caller writes `types.Ref(n)`. A scoped top is
§2.3.2's query parameter; it does not cascade, which is the same rule as for
nested scopes (§6.3).

`EvalFilter` is unchanged: set references inside a filter have no registry
syntax, and become unscoped refs.

### 6.3 Discovery and evaluation

| Now | After |
|---|---|
| `setGraph.nodes map[string]*setNode`, keyed by canonical name | `map[types.SetRef]*setNode` |
| `seen map[string]bool` | `map[types.SetRef]bool` |
| `nestedNames(set) []types.SetName`, from `SetMembers()` | `nestedRefs(set) []types.SetRef`, from `object.DirectMembers`; a member with `Source` gives a scoped ref. `nestable` still judges by `ref.Name().Class()` |
| `members(set)` returns `SetMembers()` | returns `object.DirectMembers(set)` for as-sets and route-sets |
| `setGraph.missing []types.SetName` | `[]types.SetRef`, sorted by `String()` |
| evaluation states (set name, operator stack) | (`SetRef`, operator stack) |
| `ordered()` sorts by name | sorts by `SetRef.String()` |

Consequences:

- **No cascade, by construction.** A node's nested refs come only from its own
  object, so a set fetched as `RIPE::AS-X` resolves its members by its own
  `src-members:` or by precedence.
- **One name in two scopes is two nodes.** `RIPE::AS-X` and `AS-X` are fetched
  separately, count separately against `MaxVisited`, and have their own
  evaluation states, even when precedence would pick RIPE's copy anyway. The
  cost is at most one extra fetch per scoped reference and the union is the
  same; merging them would need the Source to report which registry won — a
  second method, and a second break.
- Cycle detection, `MaxDepth` (shortest distance, breadth-first), `MaxPrefixes`
  and the operator-stack fixpoint are unchanged but for the key. Registries are
  finite, so the states stay finite.
- `Concurrency` still cannot change a result: a level is merged in its own
  order.

### 6.4 checkSet

`checkSet(ref, set)` keeps its rules on name and class, and adds one: when
`ref` is scoped and `set.SetSource()` is not `ref.Source()` (compared without
regard to ASCII case), the Source has answered a different question, and the
fetch fails with an error, as a set of another name does. A backend that
ignores scoping cannot quietly answer by precedence.

### 6.5 Results, errors, exclusion

- `ASNSet.Missing()`, `PrefixSet.Missing()`, `RangeSet.Missing()`,
  `RouterSet.Missing()` and `PeeringSet.Missing()` return `[]types.SetRef`. An
  unknown registry is listed as missing, as an absent set is (§2.3 step 1).
- `SetTooLargeError.Name` becomes a `types.SetRef` (the top). `AnySetError`
  keeps a `types.SetName`: `AS-ANY` is the whole IRR in any registry.
- A scoped top not found returns an error wrapping `ErrNotFound` that names the
  ref: `expand RIPE::AS-X: resolve: not found`.
- `Exclusion.Sets` stays `[]types.SetName` and matches `ref.Name()` under any
  scope — EXCEPT's "wherever it is met". rpslq already refuses `SOURCE::` in
  EXCEPT.

## 7. Backends

### 7.1 MemSource and Corpus

Both keep building through the one function behind `NewMemSource` and
`Corpus.Source`, so they cannot answer differently.

```go
type MemSource struct {
    sets    map[types.SetName][]object.NamedSet // every held copy, precedence order (winner first)
    dflt    func(source string) bool            // sources unscoped lookups and routes see
    routes  map[types.ASN][]netip.Prefix        // default sources only
    claims  map[types.SetName][]object.Object   // every held source; ClaimAllowed filters by set.SetSource()
    autnums map[types.ASN][]policyEntry         // precedence order; see §9
    rtrs    map[string][]policyEntry            // canonical inet-rtr name → entries
}
```

- Unscoped `GetSet` returns the first copy whose source `dflt` admits — what it
  returns today.
- Scoped `GetSet` returns the copy whose `SetSource()` equals `ref.Source()`, or
  `ErrNotFound` when there is none, including for a registry it does not hold.
- `NewMemSource(objs, precedence...)` admits every source by default, so its
  behaviour is unchanged.
- **`Corpus.SourceOf(sources...)` and `DumpLoader.SourceOf`** still limit
  unscoped lookups and routes to those sources; scoped lookups and claims see
  every source the Corpus holds (bgpq4's `-S RADB` beside `RIPE::AS-X`). Only
  index slices are added; the objects are the Corpus's own. The meaning differs
  from today's only for scoped refs, of which there are none yet.

### 7.2 What keeping aut-nums costs

Measured on the local RIPE dump (`ripe.db.aut-num.gz`), heap after GC:

| Form | 39,918 RIPE aut-nums | Per object |
|---|---|---|
| decoded `object.AutNum` | 707 MB | 18.2 KB |
| lossless text (`String()`) | 95 MB | 2.5 KB |

RIPE has 123 inet-rtrs; RADB has 10,095 aut-nums. §9 keeps text.

### 7.3 irrd.Source

```go
type Source struct {
    …
    // SrcMembers, when set, also fetches each as-set and route-set whole
    // ("!m", pipelined beside "!i") to read its src-members: and source:.
    // Members still come from "!i", which folds in indirect members. Off by
    // default: IRRd does not implement the draft, and it doubles set queries.
    SrcMembers bool

    scoped map[string]*Source // registry → sub-source with Sources = {registry}, made on first use
}
```

- A scoped lookup goes through the registry's sub-source: the same `Addr`,
  `Dial`, limits and pipelining, on connections of its own that send
  `!s<REG>`. Switching `!s` on a shared pipelined connection would race with
  the queries in flight on it; rpslq already restricts this way for
  `SOURCE::`.
- Sub-sources draw on the parent's `MaxConns` budget; `Close` closes them.
- For a scoped lookup the set synthesized from `!i` carries `Source`, so
  `checkSet` passes. With `SrcMembers`, `!m` also supplies `source:` for
  unscoped sets.
- An unknown registry: IRRd answers `!s` with
  `F One or more selected sources are unavailable.` (verified against
  whois.radb.net, 2026-09-28). On a scoped lookup this is `ErrNotFound`; the
  query fails alone and the connection stays in step. A bad default `Sources`
  list stays a loud error, as today.
- Data can name any registry, so a probe per name would cost a connection and
  a sub-source each (final review: 2,000 `FAKEi::` src-members, 2,001 dials).
  The root Source learns the server's registries once with `!j-*` (IRRd 4
  lists every real source, `RIPE:N:0-66028019`; verified against
  whois.radb.net and IRRd's `handle_irrd_database_serial_range`, 2026-09-28),
  kept until `Close`; an unlisted registry is `ErrNotFound` with no query.
  `!s-lc` would not do: it lists only the default sources. A server that
  refuses `!j` falls back to the probe above; a refused registry's sub-source
  is dropped and at most 1,024 refused names are remembered.

### 7.4 whois.Source

- A scoped `GetSet` queries `-s <REG> -r -T <class> <name>`; the whole object
  comes back, with `src-members:`. No option is needed.
- An unknown registry: RIPE answers `%ERROR:102: unknown source` (verified
  against whois.ripe.net, 2026-09-28); IRRd answers
  `%% ERROR: One or more selected sources are unavailable.` (verified against
  whois.radb.net). On a scoped lookup either is `ErrNotFound`; with the default
  `Sources` list both stay `*ServerError`.
- `MembersByRef` queries `-s <set.SetSource()>` when the set has a source.
  `ClaimAllowed` drops claims from any other source, so this only saves bytes —
  and it finds a scoped set's claimants when its registry is not in `Sources`.

### 7.5 Wrappers, mirrors, test servers

| | Change |
|---|---|
| `Cache` | Keys sets by `SetRef` and claims by (set source, set name) — two same-named sets from two registries have different claimants; caches `AutNum`/`InetRtr` by (source, key) |
| `rpki.Filter` | Passes `GetSet(ref)`, `AutNum` and `InetRtr` through; it filters routes and claimants only |
| `nrtm4.Client` | A mirror is one registry: a scoped ref to it resolves, any other is `ErrNotFound`. `CopyTo` into a shared Corpus gets §7.1. New `KeepPolicy`, passed to its Corpus |
| `DumpLoader` | New `KeepPolicy`, passed to its Corpus |
| `irrtest` | A draft-following mode, independent of the engine as `nrtmtest` is of `nrtm4`: stores `src-members:`, returns them from `!m` and whois, honours `!s`/`-s` and gives §7.3/§7.4's replies for a registry it does not hold |

### 7.6 rpslq

- `topSource` is deleted: `SOURCE::SET` is an Expand call with a scoped top
  ref. `restrict` stays for `SOURCE::AS`, where bgpq4 fetches the routes
  themselves from one registry.
- Dump and whois backends honour `src-members:` as the objects carry them.
- `--src-members` (long only) sets `irrd.Source.SrcMembers`.
- On data carrying `src-members:`, rpslq over a dump differs from bgpq4, which,
  like IRRd, does not implement the draft. The difference is pinned in
  `resolve/testdata/bgpq4/divergences.md` with a test. Real data has no
  `src-members:` today, so existing parity tests are unaffected.

## 8. PolicySource

```go
// PolicySource is a Source that also serves the objects routing policy names
// outside sets: aut-nums, whose import/export/default policies a policy
// evaluator reads, and inet-rtrs, which router expressions and peerings name.
// source scopes a lookup as a SetRef does: "" is the Source's precedence, and a
// registry it does not hold is ErrNotFound.
type PolicySource interface {
    Source
    AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error)
    InetRtr(ctx context.Context, name, source string) (object.InetRtr, error)
}

// ErrNoPolicy is returned by a wrapper (Cache, rpki.Filter) whose inner Source
// is not a PolicySource.
var ErrNoPolicy = errors.New("resolve: source serves no policy objects")
```

Scoping lets an evaluator read AS3333's policy from RIPE rather than a stale
proxy aut-num in RADB. Filter-sets, rtr-sets and peering-sets keep coming from
`GetSet`.

### 8.1 Backends

| | AutNum / InetRtr |
|---|---|
| `NewMemSource` | Indexes the decoded aut-nums and inet-rtrs it is given |
| `Corpus` | `KeepPolicy bool`, set before the first `Put`: every aut-num and inet-rtr is kept as source-interned text under its existing `wholeKey`, so `Delete` and NRTM replacement work unchanged. An aut-num that claims membership is already kept decoded and answers directly |
| MemSource from a Corpus | Decodes per call (`rpsl.ParseObject`, `object.Decode`) and caches nothing, so it stays immutable and safe to share. Decode diagnostics are dropped: the loader reported them. Wrap it in `Cache` for repeated lookups |
| `irrd.Source` | `!maut-num,AS1`, `!minet-rtr,<name>`, decoded and checked to be the object asked for; scoped via the sub-source. An inet-rtr name must be DNS characters before it is sent |
| `whois.Source` | `[-s REG] -r -T aut-num AS1`, `-T inet-rtr <name>`, with `Sources` precedence as `GetSet` has |
| `Cache`, `rpki.Filter` | As in §7.5; `ErrNoPolicy` over a plain `Source` |

Engine purity holds: the Corpus's decoding uses the root `rpsl` package, which
has no `net` in its dependencies.

### 8.2 Shape check: a peval sketch (not part of this change)

```go
// ImportFilter is the filter local applies to routes from peer, for af —
// peval's core, over PolicySource.
func ImportFilter(ctx context.Context, src resolve.PolicySource, local, peer types.ASN,
    af types.AddrFamily) (resolve.RangeSet, error) {
    an, err := src.AutNum(ctx, local, "")                   // PolicySource
    …
    e := &resolve.Expander{Src: src}
    for _, imp := range an.Imports {
        terms, err := imp.Terms(af)                         // policy.Flatten
        …
        for _, t := range terms {
            ok, err := peeringNames(ctx, e, t.Peering, peer) // ASExpr → ExpandAS(types.Ref(set));
            …                                               // PeeringSetRef → ExpandPeerings;
                                                            // router exprs → InetRtr, ExpandRouters
            if ok {
                return e.EvalFilter(ctx, t.Filter)          // PeerAS: needs a bound peer
            }
        }
    }
    …
}
```

Every lookup the sketch needs exists. Matching a router address against
`at rtr.example.net` or `at RTRS-X` takes forward lookups only (the rtr-set's
routers, then each inet-rtr's `ifaddr:`), so no reverse index is needed. The one
gap is binding `PeerAS` and per-peer set templates to the peer, which is an
`Expander` option for the peval milestone and not a `PolicySource` concern.

## 9. policyEntry

```go
// policyEntry is an aut-num or inet-rtr a MemSource serves: decoded when it
// was given decoded (NewMemSource, or a Corpus claimant), else its text.
type policyEntry struct {
    source string
    obj    object.Object // nil when held as text
    text   string
}
```

Unscoped lookups take the first entry by precedence that `dflt` admits; scoped
ones the entry of that source.

## 10. Tests

Each behaviour is held to an oracle independent of the code under test.

1. **Engine model.** `model_test.go`'s random IRRs (two sources, sets in both)
   gain members with a registry; sets with `src-members:`-only, unlisted and
   conflicting entries; scoped refs to a registry that does not exist; a scoped
   top; one name reachable scoped and unscoped; cycles through scoped refs;
   operators on scoped route-set refs. The oracle applies §2.3 from the model,
   never through `DirectMembers` or parsed text. `TestModelMemSource` and
   `TestModelBackends` hold MemSource, a Corpus-built MemSource, `Cache`,
   `whois` and `irrd` (`SrcMembers` on) to it: ASNs, both families' prefixes,
   `Missing()`.
2. **"Off" means today.** `irrd.Source` with `SrcMembers` off, over draft data
   in `irrtest`, equals the oracle that ignores `src-members:`.
3. **The draft's worked example.** Figure 1's five objects resolve `RS-FIRST` to
   AS65000 and AS65001, with `OTHER`'s RS-SECOND never fetched (asserted with a
   counting Source), in every backend.
4. **Corpus parity.** `TestCorpusMatchesMemSource` adds a scoped `GetSet` for
   every (source, name), unscoped under `Source()` and `SourceOf(...)`, and with
   `KeepPolicy` `AutNum`/`InetRtr` for every key × source, scoped and not.
5. **Concurrency.** `TestConcurrencyDoesNotChangeResults`'s 200 random graphs
   include scoped refs.
6. **Object layer.** The draft's examples kept verbatim in
   `object/testdata/src-members-draft.txt`, as `rfc-examples.txt` keeps the
   RFCs': Figure 2 decodes clean; Figure 3 gives exactly one unlisted Warning
   for `NTTCOM::RS-SRCMBRONLY` and one for `2001:db8::/32`; Figure 4 gives the
   conflict Error. Table tests for `ParseSrcMember` (every §2 form, every
   operator placement allowed and refused) and for `DirectMembers` (§5.2's
   keys, operator precedence).
7. **Contracts.** The drift test with `WithSrcMembers(RFCStrict)`;
   `TestAttributeTypesAgreeAcrossClasses` on both set classes;
   `TestDiagnosticRulesAreDocumented` forces the six rules into
   `docs/diagnostics.md`.
8. **Fuzzing, 33 → 35 targets.** `FuzzParseSetRef` (types): never panics; what
   it accepts, `String()` parses back to an equal ref, and its source matches
   `[A-Z0-9_-]+`; seeds include non-ASCII around `::`. `FuzzParseSrcMember`
   (object): an accepted member's `Ref()` round-trips. `src-members:` seeds for
   `FuzzDecode`.
9. **bgpq4 and rpslq.** The existing differential generates no `src-members:`
   and is unchanged. Deleting `topSource` changes two pinned `SOURCE::` cases
   in `rpslq_bgpq4_test.go`, `source-cycle` and `source-with-depth` — the scope
   no longer cascades, so a self-reference resolves unscoped and joins another
   registry's copy, which is what bgpq4 does too, so `source-cycle` now agrees
   with bgpq4 (`source-with-depth` still diverges, with a new count); the
   random `SOURCE::` differential, `TestRpslqSourcePrefixMatchesBgpq4`, is the
   proof that nothing else moved. The §7.6 divergence gets its
   pinned test.
10. **Real data** (`RPSL_REALDATA`). RIPE's dumps loaded with `KeepPolicy` use
    at most 150 MB more heap than without it (95 MB of aut-num text, measured,
    plus index headroom); decoding each aut-num on demand equals decoding it at
    load.
11. **Live** (`RPSL_LIVE`). whois `-s RIPE` and irrd `!sRIPE` on RADB (which
    mirrors RIPE) for a stable set and aut-num; a made-up registry is
    `ErrNotFound` on both, pinning §7.3/§7.4's replies.
12. **Invariants.** `cd types && go list -deps ./...` shows only itself;
    `cd resolve && go list -deps .` has no `net`.

## 11. Out of scope

- Generating `members:` from `src-members:` (§3.2): registry-software behaviour.
- Scoped AS numbers (`RIPE::AS1`) in the engine: the draft gives ASNs no
  registry. rpslq keeps `SOURCE::AS` as bgpq4 has it.
- A peval or config generator: the next milestone (§8.2).
- Adding `src-members` to the RIPE, IRRd or ARIN profiles: when a registry
  deploys it.

## 12. Documentation and release

- `docs/rpsl-go-design.md`: §8.1 (the Source contract), §8.2–8.3 (scoped
  membership, no cascade, two nodes per name), §8.9 (`KeepPolicy`), §10
  (the edge case), §5 (`SetRef`), §6 (`SrcMembers`).
- CLAUDE.md engine traps: the scope does not cascade; `SourceOf` restricts
  unscoped lookups only; a scoped `checkSet` refuses the wrong registry;
  `KeepPolicy` holds text, never decoded aut-nums. Also correct "rpslq-only
  options are `--long`", which `-P` and `-c` already contradict.
- `docs/diagnostics.md`, `docs/rpslq.md` (`--src-members`), README status.
- CHANGELOG v0.20.0, **Breaking**, each with its one-line fix:
  `Source.GetSet(types.SetRef)`; `Expand*(types.SetRef)`;
  `Missing() []types.SetRef`; `SetTooLargeError.Name`; `object.Set` gains
  `SetSrcMembers()`; `SourceOf` lets scoped lookups reach every held source;
  `ErrNotFound`'s message.

## 13. Risks

- **The draft is -00.** Syntax or rules may change before an RFC; the grammar
  lives in one parser and one function (`ParseSrcMember`, `DirectMembers`), and
  the draft's examples are kept verbatim, so a revision is a diff in one place.
- **No deployment yet.** No registry or IRRd release carries `src-members:`
  (IRRd 4.5's notes do not mention it), so real-data tests cannot exercise it;
  the model and `irrtest`'s draft mode are the evidence.
- **PolicySource without a consumer.** §8.2 is the check; if the peval
  milestone finds a missing lookup it can still be added before v1, as an
  additive change.
