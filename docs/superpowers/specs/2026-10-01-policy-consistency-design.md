# Policy consistency and lint

Status: design, awaiting review · 2026-10-01 · target release v0.23.0

## 1. Summary

Since v0.21.0 the library evaluates an aut-num's policy for one BGP session
(`resolve/peval`), and since v0.22.0 renders it as router configuration
(`resolve/rtconfig`). This milestone is the consumer the v0.22 design named
next: whether two neighbours' policies agree.

For a session between A and B in one address family, it compares what A's
`export:` toward B permits announcing with what B's `import:` from A accepts,
and the reverse. It also lints one aut-num on its own: dead clauses, missing
sets, routers and aut-nums, undecidable terms. One engine serves two users:

- an **operator** checking their own AS against its neighbours, in seconds,
  over a live IRR or a dump;
- an **audit** sweeping a whole registry dump and reporting totals.

The release adds a prefix-set algebra to `types`, a pure package
`resolve/consist`, an optional reverse index on `resolve.Corpus`, and a CLI,
`rpslcheck`.

### Decisions taken in brainstorming

1. **Direction:** policy consistency, the named next consumer of `peval`.
   More printers, RtConfig parity and typed communities wait.
2. **Users:** both the operator and the audit, over one per-pair check.
3. **Approach A, exact or undecided.** Prefix parts are compared exactly by a
   new set algebra. AS-path and community tests are compared by identity
   only. Whatever cannot be decided is reported as undecided, never guessed.
   Regexps are never evaluated against paths (CLAUDE.md scope guardrail).
4. **Accept sets, not actions.** Consistency compares which routes pass, not
   what is done to them. Actions matter to lint only.
5. **`Given`:** a finding over symbolic tests is stated conditionally ("any
   route passing these tests with a prefix in these ranges is refused"),
   rather than demoted to undecided.
6. **`PrefixSpace` lives in `types`**, beside `PrefixRange`.
7. **Lint rules:** shadowed, empty, missing set, missing router, missing
   aut-num, undecided, limit. Not over-broad export (it needs business
   relationships RPSL does not state) and not partial shadowing (noise).
8. **CLI `rpslcheck`;** exit status 0 clean, 1 a Warning, 2 command line,
   3 could not complete; `--sweep` only over `--dump`.

## 2. Architecture

```
types.PrefixSpace         exact prefix-set algebra (new, in the types leaf)
resolve.Conjunct.Space    a normal-form conjunct's prefix region (new method)
resolve.PolicyIndex       AutNums + NamedBy, implemented by a Corpus MemSource (new)
resolve/peval             unchanged: per-session clauses
resolve/consist           Check, Lint, Peers (new, pure)
resolve/internal/rpslcheck, resolve/cmd/rpslcheck   the CLI (new)
```

Imports run `consist → peval → resolve → types`. `resolve/consist` is pure:
no `net`, all I/O through `resolve.PolicySource`, context-cancellable, every
limit explicit. The purity check becomes
`cd resolve && go list -deps . ./peval ./rtconfig ./consist | grep -x net`
(must print nothing).

## 3. The prefix algebra (`types.PrefixSpace`)

```go
// PrefixSpace is an exact set of prefixes of both families, closed under
// union, intersection and difference. The zero value is the empty set.
// Values are immutable: operations return new spaces that may share
// structure with their operands, so a PrefixSpace is safe to share.
type PrefixSpace struct{ v4, v6 *spaceNode }

// SpaceOf returns the union of rs. An empty range adds nothing.
func SpaceOf(rs ...PrefixRange) PrefixSpace

// FullSpace returns every prefix of one family (AFIAny: both).
func FullSpace(afi AFI) PrefixSpace

func (s PrefixSpace) Union(t PrefixSpace) PrefixSpace
func (s PrefixSpace) Intersect(t PrefixSpace) PrefixSpace
func (s PrefixSpace) Minus(t PrefixSpace) PrefixSpace
func (s PrefixSpace) IsEmpty() bool
func (s PrefixSpace) Subset(t PrefixSpace) bool // s.Minus(t).IsEmpty(), without building it
func (s PrefixSpace) Equal(t PrefixSpace) bool
func (s PrefixSpace) Contains(p netip.Prefix) bool

// Example returns the shortest prefix in s; among the shortest, the lowest
// address, IPv4 before IPv6. ok is false when s is empty.
func (s PrefixSpace) Example() (p netip.Prefix, ok bool)

// Ranges yields s as disjoint ranges in canonical order (family, address,
// then low length). SpaceOf of what it yields is Equal to s.
func (s PrefixSpace) Ranges() iter.Seq[PrefixRange]
```

**Representation.**

- Each family is a binary trie over prefix bits. A node at prefix `p` (length
  L) carries a length mask of 129 bits: bit ℓ set means "every prefix under
  `p` of length ℓ is in the set". Only bits ℓ ≥ L are meaningful.
- **Canonical form.** A bit sits at the highest node where it holds. When both
  children of a node hold bit ℓ, it is lifted to the node. A node never holds
  a bit an ancestor holds. A node with an empty mask and no children is
  removed. Two spaces holding the same set are therefore structurally
  identical: `Equal` is a structural walk, and `Ranges` reads each node's
  maximal runs of set bits, which are disjoint by construction.
- **Operations** are one recursive merge. Before combining two nodes, an
  ancestor's bits are pushed down into both children (bit ℓ at `p` becomes
  bit ℓ at `p0` and `p1` when ℓ > L, and stays at `p` when ℓ = L). Masks are
  then combined bitwise (or, and, and-not), and the result is renormalized on
  the way up.
- **Cost.** The number of nodes is at most the input ranges times the prefix
  depth. Nothing ever enumerates prefixes, so `::/0^0-128` is one node.
- **Representation of `PrefixRange`.** `SpaceOf(r)` puts r's window
  `[r.Lo(), r.Hi()]` on r's prefix node. An empty range adds nothing.

**Bridge.** In `resolve`:

```go
// Space returns the prefixes the conjunct's prefix tests accept:
// SpaceOf(Prefixes) minus SpaceOf(NotPrefixes); every prefix of the
// Expander's family when AnyPrefix.
func (c Conjunct) Space() types.PrefixSpace
```

## 4. Consistency (`resolve/consist`)

### 4.1 API

```go
package consist

// Checker compares neighbours' policies and lints aut-nums. It holds no
// per-call state, so one value serves concurrent calls; wrap Eval.Src in
// resolve.Cache to share lookups across them.
type Checker struct {
	Eval      peval.Evaluator // Src, Expander limits, Source (registry)
	MaxRanges int             // cap on Finding.Ranges; 0 means 64
}

// Pair is one BGP session seen from both ends, in one address family.
// The routers are optional: a term that needs one becomes Undecided, as in
// peval.
type Pair struct {
	A, B       types.ASN
	AF         types.AddrFamily
	ARtr, BRtr netip.Addr
}

// Check compares A's export toward B with B's import from A (AtoB), and
// B's export toward A with A's import from B (BtoA). A missing aut-num is a
// NoAutNum finding, not an error. The error is a limit, a cancelled context
// or a Source failure.
func (c *Checker) Check(ctx context.Context, p Pair) (Report, error)

type Report struct {
	Pair       Pair
	AtoB, BtoA Direction
	missing    []types.SetRef
	routers    []string
}

// Missing lists the sets either side named that the Source does not have;
// MissingRouters the inet-rtrs. Both sorted, as peval's.
func (r Report) Missing() []types.SetRef
func (r Report) MissingRouters() []string

// Direction is one way routes flow: From's export toward To against To's
// import from From. No findings: the two agree.
type Direction struct {
	From, To types.ASN
	Findings []Finding
}

type Finding struct {
	Kind      Kind
	Severity  ast.Severity        // Warning or Info, by Kind (below)
	Example   netip.Prefix        // NotImported/NotExported/Undecided: one prefix in Ranges
	Ranges    []types.PrefixRange // the difference, canonical (PrefixSpace.Ranges)
	Truncated bool                // Ranges stopped at MaxRanges
	Given     []string            // symbolic tests a route must also pass; empty: unconditional
	Export    []int               // exporting side's clause Index values involved
	Import    []int               // importing side's clause Index values involved
	Why       string              // Undecided only: one of the Why constants
}

type Kind uint8

const (
	NotImported Kind = iota // Warning: From permits announcing routes To refuses
	NotExported             // Info: To accepts routes From does not permit announcing
	NoImport                // Warning: From exports to To; no import term of To covers From
	NoExport                // Info: To imports from From; no export term of From covers To
	NoAutNum                // Warning: From's or To's aut-num is not in the Source
	Undecided               // Info: part of the comparison cannot be decided
)

func (k Kind) String() string // "not-imported", "not-exported", "no-import", "no-export", "no-aut-num", "undecided"

const (
	WhySymbolic          = "symbolic test on one side only" // an AS-path or community test the other side does not hold
	WhyImporterUndecided = "importer has undecided terms"   // To's import has a term peval cannot decide
	WhyExporterUndecided = "exporter has undecided terms"   // From's export has a term peval cannot decide
)

// Whys returns every Why value Check can report, as peval.Whys does.
func Whys() []string

// Peers lists the AS numbers as's import, export and default peerings name.
func (c *Checker) Peers(ctx context.Context, as types.ASN) (PeerList, error)

type PeerList struct {
	Forward []types.ASN // named by as's peerings, as-sets expanded; ascending
	Reverse []types.ASN // aut-nums whose peerings name as (resolve.PolicyIndex only); ascending
	Skipped []string    // peerings that name no AS list: AS-ANY, regexps; as written
	NoIndex bool        // the Source keeps no reverse index (not a PolicyIndex, or ErrNoIndex), so Reverse is empty
}
```

### 4.2 Semantics

- **Accept sets.** peval resolves EXCEPT and REFINE into ordered clauses, and
  every RPSL clause accepts. So the routes a policy accepts are the union of
  its clauses' filters. A route a decided clause accepts is accepted whatever
  an earlier undecided term does. The decided clauses are therefore a lower
  bound on what a side accepts.
- **Per family.** A Pair names one family, peval trims prefixes to it, and
  every space is of that family. `announce ANY` covers the session's family
  only.
- **"Announces" means "permits announcing".** The comparison is of policy
  text, not of what a router holds. A customer's `announce ANY` toward a
  provider that imports `AS-CUST` is a NotImported Warning: the text claims a
  leak the provider would refuse.
- **NoImport / NoExport.** When From has export terms toward To but To has no
  decided import term whose peering covers From, the direction is NoImport
  (and nothing else is compared). Symmetrically for NoExport. When neither
  side has a term for the other, the direction has no findings: the two
  simply do not peer in the registry. When the uncovered side has undecided
  terms, the finding is Undecided with the matching Why, not NoImport.
- **NoAutNum.** A missing aut-num on either side is one NoAutNum finding in
  each direction; nothing else is compared.

### 4.3 The comparison

For one direction From → To, after peval has evaluated From's export toward
To and To's import from From:

1. **Signatures.** A conjunct's signature T is its sorted, canonical list of
   symbolic tests: each `PathMatch` as its normalized regexp text with its
   expanded sets and polarity, and each `CommunityMatch` as its normalized
   text and polarity. A pure-prefix conjunct has the empty signature.
2. **Export side.** For each signature T, `E_T` is the union of `Space()` over
   From's decided export conjuncts with signature exactly T.
3. **What To surely accepts.** `Sure_T` is the union of `Space()` over To's
   decided import conjuncts whose signature is a subset of T. A route
   passing T passes those tests too, so it is accepted when its prefix lies
   in `Sure_T`.
4. **What To may accept.** `Maybe_T` is the union of `Space()` over To's
   decided import conjuncts whose signature is not a subset of T.
5. **The remainder.** `R_T = E_T − Sure_T`.
   - `R_T ∩ Maybe_T` may or may not be accepted: an Undecided finding,
     `WhySymbolic`, with `Given` = T.
   - `R_T − Maybe_T` is refused: a NotImported finding with `Given` = T.
6. **Demotion.** When To's import has any Undecided term, every NotImported
   finding of the direction becomes Undecided, `WhyImporterUndecided`.
7. **NotExported** is the same computation with the roles swapped: `I_T`
   from To's import, `Sure_T` and `Maybe_T` from From's export. Demotion
   uses `WhyExporterUndecided`.

Each finding's `Example` is `Example()` of its space, and its `Ranges` are
the space's canonical ranges, at most `MaxRanges` (then `Truncated`).
`Export` and `Import` list the clause `Index` values whose conjuncts
contributed to the space. Findings are ordered by Kind, then `Given`, then
Example, so a Report is deterministic.

A non-empty `Given` makes a finding conditional and exact: it does not claim
any route passes T (that would need a regexp evaluated), only that any route
that does, with a prefix in Ranges, is refused.

## 5. Lint

```go
// Lint evaluates as's import, export and default policies toward each peer
// in Peers' Forward list (as's own policies name nothing toward the others),
// in ipv4.unicast and ipv6.unicast, with no routers given, and
// reports what is wrong or dead in them. It returns an error wrapping
// resolve.ErrNotFound when as's own aut-num is not in the Source.
func (c *Checker) Lint(ctx context.Context, as types.ASN) ([]Issue, error)

// Issue is a Diagnostic (Rule, Severity, Message, and the Span of the
// attribute inside the aut-num's text) plus where it applies. Identical
// issues across sessions are merged: Peers and AFs list every session that
// has it, ascending.
type Issue struct {
	ast.Diagnostic
	Attr  string // the attribute as written: "import", "mp-import", "export", …
	Index int    // the attribute's position, as peval's Clause.Index
	Peers []types.ASN
	AFs   []types.AddrFamily
}
```

| Rule | Severity | Fires when |
|---|---|---|
| `lint/shadowed` | Warning | every route a clause accepts is accepted by an earlier decided clause (§4.3's subset rule, per signature), so its actions never apply |
| `lint/empty` | Info | a clause's filter normalizes to no conjuncts |
| `lint/missing-set` | Warning | a filter or peering names a set the Source does not have |
| `lint/missing-router` | Warning | a peering names an inet-rtr the Source does not have |
| `lint/no-aut-num` | Warning | a peering names an AS whose aut-num the Source does not have |
| `lint/undecided` | Info | a term peval cannot decide; the message carries the Why |
| `lint/limit` | Warning | a session's evaluation hit a limit; the other sessions are still linted |

- **Shadowing is exact.** Clause k is shadowed when, for every signature T
  among its conjuncts, its `E_T` is a subset of the union of earlier decided
  clauses' conjuncts with signatures that are subsets of T. Undecided terms
  only ever add accepted routes, so they never make a covered clause
  uncovered: `lint/shadowed` is never a guess. Partial shadowing is not
  reported.
- **`lint/empty` and `lint/missing-set` together.** A clause that is empty
  because its sets are missing gets both.
- The rules are documented in `docs/diagnostics.md`, which
  `TestDiagnosticRulesAreDocumented` holds to the code.

## 6. The reverse index

```go
// resolve
// PolicyIndex is a PolicySource that can list its aut-nums and, for an AS,
// the aut-nums whose import, export or default peerings name it directly.
type PolicyIndex interface {
	PolicySource
	// AutNums yields every aut-num held, ascending. ErrNoPolicy when the
	// Source holds only some (a Corpus without KeepPolicy).
	AutNums() (iter.Seq[types.ASN], error)
	// NamedBy returns the aut-nums naming as, ascending; as-set peerings
	// are not indexed. ErrNoIndex when the Source keeps no index (a Corpus
	// without IndexPeers).
	NamedBy(as types.ASN) ([]types.ASN, error)
}

var ErrNoIndex = errors.New("resolve: the source keeps no peer index")

// Corpus: set before the first Put. IndexPeers implies KeepPolicy.
IndexPeers bool
```

- With `IndexPeers`, `Corpus.Put` parses an aut-num's policy values once to
  collect the AS numbers its peerings name. The parsed policies are dropped
  at once; only the map of ASN to the ASNs naming it is kept, so the corpus
  memory rule holds (CLAUDE.md: never retain decoded objects). An NRTM
  replacement or delete updates the index.
- `*MemSource` implements `PolicyIndex`. One built by `NewMemSource` answers
  both methods (it holds every aut-num it is given, decoded); one built from
  a Corpus answers as that Corpus was configured, with `ErrNoPolicy` or
  `ErrNoIndex` otherwise. `Cache` and `rpki.Filter` pass both through when
  their inner Source is a `PolicyIndex`, and return `ErrNoIndex` when not.
- Peerings through as-sets are not reverse-indexed: expanding every as-set
  peering in a registry at load is unbounded. Forward peers still expand
  them, under the Expander's limits.

## 7. The CLI (`rpslcheck`)

`resolve/cmd/rpslcheck` is a shim; the logic is `resolve/internal/rpslcheck`.
Backends open through `resolve/internal/backend` with the flags `rpslq` and
`rpslconf` take: `-h`, `-p`, `-s`, `--whois`, `--dump files…`.

```
rpslcheck AS65001            lint AS65001, then check it against every peer (Forward and Reverse), both families
rpslcheck AS65001 AS65002    check that one pair, and lint both
rpslcheck --sweep --dump …   audit every aut-num in the dumps
  --af ipv4|ipv6|both        families (default both)
  --json                     one JSON object per finding and issue
  --sample N --seed S        sweep a seeded random sample of N aut-nums
  -c N                       concurrent checks (default GOMAXPROCS)
  -v                         version
```

- **Text output** groups findings by peer and direction: the Kind and
  severity, the attributes on each side with their line numbers in the
  aut-num text, the example, the ranges, and `Given` when non-empty.
- **The sweep** builds the pairs from `AutNums()` and each aut-num's forward
  peers, each unordered pair once, in each family asked for. It ends with
  totals:
  - pairs and directions checked;
  - directions by outcome (consistent, each Kind, Undecided by Why);
  - lint issues by rule;
  - limits hit;
  - the ten aut-nums with the most Warnings.
- **Deterministic.** Output is in input order and identical for `-c 1` and
  `-c 8`.
- **`--sweep` requires `--dump`.** Walking a registry over a live server would
  be hundreds of thousands of queries against someone else's service.
- **Exit status.** 0: no Warning. 1: at least one Warning. 2: the command
  line. 3: the check could not complete: an unreachable server, the named
  AS's aut-num not found, or (outside a sweep) a limit. In a sweep, a pair
  that hits a limit is counted, not fatal.
- `rpslcheck` joins `rpslq` and `rpslconf` in `scripts/release.sh`: built for
  the same five platforms, version-checked, attached to the GitHub release.

## 8. Tests

There is no external oracle: IRRToolSet has no consistency checker, and the
academic tools (Nemecis, about 2004) do not run today. The in-repo models are
the oracles, built as the filter and policy models are: random inputs, and a
brute-force answer from the generator's model, never from parsed text.

### 8.1 `PrefixSpace` against brute force (`types`)

- **Universe:** IPv4 prefixes under `10.0.0.0/24` with lengths 24–32 (511
  prefixes) and IPv6 under `2001:db8::/120` with lengths 120–128. Ranges are
  also drawn whose prefix lies above the universe root (`10.0.0.0/8^24-26`)
  and whose window reaches past it.
- **Property test:** random expression trees of `SpaceOf`, `Union`,
  `Intersect`, `Minus`, evaluated both ways. They must agree on membership of
  every universe prefix, `IsEmpty`, `Subset`, `Example` (the minimum by
  length, then address), and `Equal` (true exactly when the sets are equal:
  canonicity). `SpaceOf(Ranges()...)` is `Equal` to the space, and its ranges
  are disjoint.
- **`FuzzPrefixSpace`:** an operation sequence decoded from bytes, checked the
  same way. Fuzz targets: 41.
- **Benchmarks:** `SpaceOf` over 100k ranges; `Minus` of two such spaces.

### 8.2 The consistency model (`resolve`, `TestModelConsist`)

- The policy model's generator draws two aut-nums with import and export
  policies toward each other: EXCEPT/REFINE, lists, afi clauses, as-set and
  AS-number peerings, regexps with sets, community tests, routers given and
  not.
- Routes are sampled (prefix, path, communities), and the oracle evaluates
  each side per route from the model, regexps included, in test code only (as
  the filter model's `goRE` does).
- **Soundness.** An unconditional NotImported example is announced and
  refused on every sampled path and community set with that prefix. A
  conditional one holds for every sampled route passing its `Given`.
- **Completeness.** Every sampled route the model finds announced and refused
  lies in a NotImported finding's ranges with its `Given` satisfied, unless
  an Undecided finding's ranges hold its prefix. `MaxRanges` is set so nothing
  is truncated. The same for NotExported, NoImport, NoExport and NoAutNum.
- **Exactness on pure-prefix policies.** For policies drawn with pure-prefix
  filters in the small universe, both directions are checked against the
  whole universe: findings, their ranges, and `lint/shadowed` must equal the
  oracle's exactly.
- **Backends:** `MemSource`, a `Corpus` with `KeepPolicy` and `IndexPeers`, and
  `irrd`/`whois` against `irrtest`, as `TestModelPolicyBackends` does.
- **`NamedBy`** equals a brute-force scan of the generated aut-nums, before and
  after random replacements and deletes.

### 8.3 Table tests

- customer → provider with matching sets: consistent;
- a customer's `announce ANY`: NotImported, Warning;
- `accept ANY` against a narrow export: NotExported, Info;
- one-sided policies: NoImport, NoExport; neither side: no findings;
- a missing aut-num: NoAutNum both ways;
- a regexp on the export side only: `Given`; on both sides identically: compared exactly;
- an undecided import term: demotion to Undecided;
- legacy `import:` against `mp-import:`, per family;
- an as-set peering on one side, an AS number on the other;
- every lint rule firing, and partial shadowing not firing.

### 8.4 The CLI

Golden text and JSON output; every exit status; `--sweep` refused without
`--dump`; a sweep's output identical for `-c 1` and `-c 8`; `-v`; release.sh
building and checking `rpslcheck` (`scripts/release-dryrun.sh`).

### 8.5 Real data (opt-in, `RPSL_REALDATA`)

- Sweep RIPE: all of it if it runs in minutes, a seeded sample otherwise.
  Measure the time and the cost of `IndexPeers`.
- **Invariant:** each unconditional NotImported example is re-checked against
  the two sides' clause spaces with `Contains`, so the comparison and the
  algebra agree on every case they meet.
- The totals go into the CHANGELOG and `docs/rpslcheck.md` as measured.

## 9. Docs and invariants

- `docs/rpslcheck.md`: the operator's page.
- `docs/rpsl-go-design.md`: §8.11 consistency and lint; §11 items 3 and 5 (the
  model, the fuzz target); §12 status.
- `docs/diagnostics.md`: the `lint/*` rules.
- CLAUDE.md: the module layout line for `resolve/consist`; an engine-trap
  bullet (exact or undecided, `Given`, never evaluate a regexp, demotion);
  the purity line with `./consist`; the fuzz count and list.
- README status table: `resolve/consist` and `rpslcheck`.

## 10. Review Focus

1. A symbolic conjunct never yields an unconditional finding.
2. An importer's undecided term always demotes NotImported (and an
   exporter's, NotExported).
3. `PrefixSpace` stays canonical after `Minus`: mask push-down is where bugs
   hide.
4. `announce ANY` covers the session's family only.
5. Sweep output depends on neither map order nor `-c`.

## 11. Out of scope

- Comparing actions (communities set by one side and expected by the other,
  preferences).
- Consistency across a route server (`import-via:`/`export-via:` make it a
  three-party question) and of `default:` policies; lint still covers their
  sets and routers.
- Multicast families.
- Business-relationship inference and over-broad export checks.
- Reverse-indexing as-set peerings.
- Evaluating AS-path regexps or community tests: ever, in the library.

## 12. Risks

- **Undecided may dominate real data.** If many real policies use regexps
  that the other side does not repeat, most directions end conditional or
  undecided. The real-data sweep measures it; `Given` keeps conditional
  findings useful.
- **Algebra bugs are silent.** A wrong `Minus` produces plausible ranges. The
  brute-force property test and fuzzing over a universe small enough to
  enumerate are the defence; the real-data invariant is the second.
- **The model is ours.** The consistency oracle reuses the policy model's
  generator; a misreading shared by the generator and peval would hide.
  peval's own oracles (the policy model, the IRRToolSet differential) are the
  check on that layer.
- **Index memory.** `IndexPeers` parses every aut-num's policies at load. The
  real-data run measures the time and the heap; if either is out of line,
  the index becomes a separate pass over the dump instead.
