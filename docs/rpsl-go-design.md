# `rpsl` — a complete RPSL parser, type system, and set-expansion engine for Go

## 1. What this is and where it sits

A library that takes raw RPSL (the text of RIPE/ARIN/RADB/etc. database objects) and produces **typed, validated, semantically-parsed objects**, plus a **resolver** that expands set references (`as-set`, `route-set`, …) into concrete ASNs and prefixes.

The existing Go option, `frederic-arr/rpsl-go`, deliberately stops at raw `key: value` extraction with no validation, no value parsing, and no set expansion. Everything past the lexer is greenfield. The reference points to learn from are non-Go: the RIPE `whois` codebase (flex/bison grammar, Java object model), IRRToolSet's `RtConfig`, and `bgpq4` (the de-facto set-expansion tool). The goal is to be the first library that does in Go what `bgpq4` + a real RPSL object model do together, but as an importable, testable package rather than a CLI.

Three RFCs define the surface area: **RFC 2622** (core RPSL), **RFC 2650** (using RPSL in practice / the dictionary), and **RFC 4012** (RPSLng: `mp-*` attributes, `route6`, the `afi` dictionary, `except`/`refine`). RIPE has also accumulated documented deviations from the base spec, so a "spec-pure" parser will fail on real data — the design treats RIPE/IRRd reality as the target, with RFC text as the skeleton.

### Design principles

1. **Layered, independently useful.** Lexing → generic object model → typed objects → policy AST → resolution. A consumer who only wants `mnt-by` attributes pays nothing for the policy-expression parser. A consumer who wants `as-set` expansion never has to know the lexer exists.
2. **Lossless round-trip at the syntactic layer.** Parsing then re-serializing a generic object reproduces it byte-for-byte (modulo normalization the caller opts into). This is what lets the library be used for *editing* objects, not just reading them, and it's where most parsers quietly fail.
3. **Errors are values, parsing is resilient.** A malformed `import:` line must not prevent you from reading `mnt-by:` on the same object. Diagnostics carry line/column spans; partial results are the norm.
4. **The resolver is an interface, not a hardcoded transport.** Set expansion needs a backing data source (live IRR, local IRRd mirror, in-memory corpus). The engine is pure; I/O is injected.

---

## 2. Module layout

```
rpsl/
  lexer/        # tokens, scanner, line-folding, comment handling
  ast/          # generic object + attribute model (lossless)
  types/        # leaf value types: ASN, Prefix, PrefixRange, NICHandle, SetName, AddrFamily…
  object/       # typed objects: AutNum, AsSet, RouteSet, Route, Route6, Mntner, Peering…
  policy/       # the import/export/default grammar → AST (the deep end)
  resolve/      # set-expansion engine + Source interface + caching/limits
  rpsl.go       # top-level façade: Parse, ParseObject, Decode
```

Each leaf is its own package so `go get` of `rpsl/types` (just the value types — handy on its own) doesn't drag in the resolver. The top-level `rpsl` package re-exports the common path.

---

## 3. Lexer

RPSL is line-oriented and looks trivial until it isn't. The lexer owns every quirk so nothing downstream has to.

Rules it must get right:

- **Attribute lines** are `name:` followed by a value. `name` is case-insensitive in practice (RIPE lowercases; RADB is mixed).
- **Continuation** of a value onto the next line happens when the next line begins with a space, a tab, or a `+`. A lone `+` continuation line means "a blank line is part of the value" (used in `remarks:` / `descr:`). This single rule breaks naive `strings.Split(s, "\n")` parsers.
- **Comments** start with `#` and run to end of line — *anywhere*, including mid-value. They must be stripped for semantic parsing but preserved for lossless round-trip, so the token carries both the raw and the comment-stripped span.
- **Object boundaries** are one or more blank lines. But inside a `remarks:` block a "blank" line is really a `+` continuation, so boundary detection happens *after* folding, not before.
- **EOF without trailing newline**, `\r\n` vs `\n`, trailing whitespace, and tabs-vs-spaces all appear in the wild.

```go
package lexer

type Kind uint8
const (
    KindAttribute Kind = iota // a folded "name: value" unit
    KindBlankLine             // object separator candidate
    KindComment               // a full-line comment (value preserved)
)

type Token struct {
    Kind    Kind
    Name    string // lowercased attribute name, "" for non-attribute
    Raw     string // exact bytes incl. continuation + comments (for round-trip)
    Value   string // comment-stripped, continuation-joined value
    Span    Span   // byte offsets + line/col of first and last physical line
}

type Span struct{ StartLine, StartCol, EndLine, EndCol, StartByte, EndByte int }
```

The scanner is a hand-written state machine over `bufio.Scanner` lines (not regex). Folding is done in the lexer so the `Value` handed up is already the logical value, while `Raw` lets `ast` reproduce the original.

---

## 4. Generic object model (`ast`)

Below the typed layer sits a model that can represent *any* object, including classes the typed layer doesn't know about. This is the lossless layer.

```go
package ast

type Attribute struct {
    Name    string // canonical lowercase
    Value   string // logical value
    Raw     string // original bytes for round-trip
    Span    lexer.Span
    Comment string // trailing/inline comment, if any
}

type Object struct {
    attrs []Attribute // ordered; RPSL is order-significant for some classes
}

// Accessors mirror what people actually need, and match the prior art's
// ergonomics (GetFirst/GetAll) so migration from frederic-arr/rpsl-go is trivial.
func (o *Object) Class() string                 // first attribute name = class
func (o *Object) Key() string                   // primary key value(s)
func (o *Object) GetFirst(name string) (Attribute, bool)
func (o *Object) GetAll(name string) []Attribute
func (o *Object) Has(name string) bool

func (o *Object) String() string                // lossless re-serialization
func (o *Object) Append(name, value string)     // editing support
func (o *Object) Set(name string, values ...string)
```

Ordering matters: in an `aut-num`, the *sequence* of `import:` lines encodes precedence (the specification-order rule). So `attrs` is a slice, never a map. `GetAll` preserves document order.

---

## 5. Leaf value types (`types`)

These are the small, reusable, comparable value types every higher layer is built from. Built on `net/netip` so they interoperate with the rest of a modern Go networking stack (and with `bart`/`netipx`).

```go
package types

type ASN uint32                  // 32-bit ASNs; ParseASN("AS65001") -> 65001
func (a ASN) String() string     // "AS65001"

type SetName struct {            // hierarchical: AS1:AS-CUSTOMERS:RS-FOO
    Components []string           // each is an ASN or a set name
    Class      SetClass           // inferred from the *set* component prefix
}

type SetClass uint8 // AsSet ("as-"), RouteSet ("rs-"), RtrSet ("rtrs-"),
                    // FilterSet ("fltr-"), PeeringSet ("prng-")

type PrefixRange struct {        // 192.0.2.0/24^+  /  ^-  /  ^24  /  ^24-28
    Prefix netip.Prefix
    Op     RangeOp              // Exact, Minus, Plus, Length(n), Range(n,m)
    Lo, Hi uint8
}
// Materialize enumerates concrete prefixes the range denotes, bounded by a cap.
func (r PrefixRange) Materialize(maxPrefixes int) ([]netip.Prefix, error)

type AddrFamily struct { AFI AFI; SAFI SAFI } // RFC 4012 afi dictionary
// afi ipv4.unicast, ipv6.unicast, any.unicast, any, …
```

The `^operator` parsing on prefix ranges is one of the spots regex parsers fumble; making it a first-class type with an explicit `Materialize` (and a hard cap) keeps the fan-out controllable.

---

## 6. Typed objects (`object`)

A typed wrapper per class, each backed by an `ast.Object` so you can always drop back to raw. Construction is via a class registry, so unknown classes degrade gracefully to the generic object instead of erroring.

```go
package object

type AutNum struct {
    AS        types.ASN
    AsName    string
    Imports   []policy.Import   // parsed import: AND mp-import:
    Exports   []policy.Export   // parsed export: AND mp-export:
    Defaults  []policy.Default
    AdminC    []types.NICHandle
    MntBy     []string
    Source    string
    raw       *ast.Object
}

type AsSet struct {
    Name      types.SetName
    Members   []types.SetName // ASNs and nested set names (raw, unexpanded)
    MbrsByRef []string        // mntner names enabling indirect membership
    raw       *ast.Object
}

type RouteSet struct {
    Name      types.SetName
    Members   []RouteSetMember // prefix-ranges, set names, or AS numbers
    MpMembers []RouteSetMember // RFC 4012 mp-members (may carry IPv6)
    MbrsByRef []string
    raw       *ast.Object
}

type Route struct {            // and Route6, sharing a common interface
    Prefix    netip.Prefix
    Origin    types.ASN
    MemberOf  []types.SetName  // indirect route-set membership claims
    Holes     []netip.Prefix
    Source    string
    raw       *ast.Object
}
```

Decoding into a typed object is fallible *per attribute*: `DecodeAutNum` returns the `AutNum` it could build plus a `[]Diagnostic` for the lines it couldn't, rather than failing whole-object. This is the resilience principle made concrete.

---

## 7. The policy AST (`policy`) — the actual hard part

This is what separates a real RPSL library from an attribute scanner. An `import:`/`export:` value is a small language. RFC 4012's `mp-import:` adds address-family scoping and the `except`/`refine` block structure.

Grammar in scope (EBNF sketch, RFC 2622 §6 + RFC 4012 §2.5):

```ebnf
policy-expr   = afi-clause? import-factor
              | policy-expr "except" afi-clause? "{" policy-expr-list "}"
              | policy-expr "refine" afi-clause? "{" policy-expr-list "}"

afi-clause    = "afi" afi-list                         (* ipv6.unicast, any, … *)

import-factor = "from" peering-spec
                ( "action" action-list )?
                "accept" mp-filter

peering-spec  = as-expr [ router ] [ "at" router ]
              | peering-set-name
              | "<" as-regexp ">"                       (* AS-path regexp *)

action-list   = action ( ";" action )* ";"?
action        = rp-attr "=" value
              | rp-attr ".=" value                       (* append, e.g. community *)
              | "pref" "=" int | "med" "=" int | "dpa" "=" int
              | "community" methodcall

mp-filter     = filter-term ( ("AND"|"OR"|"NOT") filter-term )*
filter-term   = "ANY" | "PeerAS"
              | "{" prefix-range-list "}"               (* explicit prefixes *)
              | as-expr                                  (* AS / as-set, expands *)
              | filter-set-name
              | "<" as-path-regexp ">"
              | "(" mp-filter ")"
```

Modeled as a sealed interface hierarchy (Go's stand-in for sum types — the pattern you'd reach for coming from a real type-system language):

```go
package policy

type Import struct {
    AFI    types.AddrFamily // zero value = unscoped (legacy import:)
    Expr   Expr             // the structured policy expression
}

// Expr is the sealed AST node. Concrete types below.
type Expr interface{ isExpr() }

type Factor struct {        // "from X action Y accept Z"
    Peering Peering
    Actions []Action
    Filter  Filter
}

type Except struct{ Base Expr; AFI types.AddrFamily; Refinements []Expr }
type Refine struct{ Base Expr; AFI types.AddrFamily; Refinements []Expr }

func (Factor) isExpr() {}
func (Except) isExpr() {}
func (Refine) isExpr() {}

// Filter is itself a sealed tree (AND/OR/NOT over leaves).
type Filter interface{ isFilter() }
type FilterAny      struct{}
type FilterPeerAS   struct{}
type FilterPrefixes struct{ Ranges []types.PrefixRange }
type FilterASExpr   struct{ AS ASExpr }           // resolves via the engine
type FilterSet      struct{ Name types.SetName }  // fltr-… reference
type FilterBinary   struct{ Op FilterOp; L, R Filter }
type FilterNot      struct{ Inner Filter }
type FilterPathRE   struct{ Regexp string }       // <^AS1+ AS2*$> — keep as AST, see §9
```

Two deliberate calls here:

- **AS-path regular expressions** (`<...>`) are parsed into their own AST (operators `^ $ . * + ? | ( ) { }` over AS / as-set terms) but *not evaluated* against live paths — evaluation is a BGP-table concern, not a registry concern. Keeping them structured (rather than as opaque strings) means a consumer can still translate them to a router config, which is the main real use.
- **Actions** are kept as typed key/op/value triples rather than fully interpreting every RP-attribute, because the RP-attribute dictionary is open-ended (RFC 2622 §9 / the `dictionary` object). The common ones (`pref`, `med`, `community`, `aspath.prepend`) get typed helpers; the rest round-trip faithfully.

The parser for this layer is a hand-written recursive-descent parser over a small token stream (operators, parens, braces, keywords, identifiers, prefixes). Recursive descent — not a parser generator — because the error recovery needs to be good (resume at the next `;` or `}`) and because the grammar is small enough that a generator adds dependency weight without buying much.

---

## 8. The resolution engine (`resolve`) — set expansion

This is the feature nobody ships in Go. Expanding `as-set AS-FOO` or `route-set RS-BAR` into concrete prefixes is a graph traversal over objects that the engine must *fetch*, with cycles, fan-out blow-ups, source conflicts, and two different membership mechanisms.

### 8.1 The Source interface (injected I/O)

```go
package resolve

type Source interface {
    // GetSet fetches a set object by name. May consult multiple IRRs;
    // ordering/trust is the Source's concern. Returns ErrNotFound cleanly.
    GetSet(ctx context.Context, name types.SetName) (object.Set, error)

    // OriginatedRoutes returns the prefixes a given AS originates,
    // from route/route6 objects. Needed because an as-set or route-set
    // member that is a bare ASN expands to that AS's routes.
    OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

    // MembersByRef supports the mbrs-by-ref / member-of indirect mechanism:
    // objects maintained by listed mntners that claim member-of this set.
    MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error)
}
```

Backends to ship: an in-memory `Source` (for tests and for loading an IRRd snapshot/`.db` dump), an HTTP/RDAP+WHOIS `Source`, and a thin `Source` over a local IRRd mirror's query port. The engine never opens a socket itself.

### 8.2 Dual membership

A set's members come from **two** places and the engine must union them:

1. **Direct** — the `members:` / `mp-members:` attribute lists ASNs, prefix-ranges, and nested set names.
2. **Indirect** — other objects assert `member-of:` *this* set. Per RFC 2622 this is only honored when the set carries `mbrs-by-ref:` and the asserting object is maintained by one of the listed mntners (or `mbrs-by-ref: ANY`). Skipping the mntner check is a common correctness bug; the engine enforces it via `Source.MembersByRef`.

### 8.3 Traversal, cycles, and limits

```go
type Expander struct {
    Src        Source
    MaxDepth   int           // default 32; as-set nesting is rarely > a few
    MaxPrefixes int          // hard cap on output set size (fan-out guard)
    AFI        types.AFI     // constrain to v4 or v6
    Sources    []string      // IRR source precedence, e.g. ["RIPE","RADB"]
    cache      *resultCache  // memoize set -> expansion within a run
}

// ExpandAS returns the transitive set of ASNs denoted by an as-set (or a
// bare AS, trivially). Detects cycles, dedups, respects MaxDepth.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error)

// ExpandPrefixes returns concrete prefixes for a route-set, an as-set
// (= union of routes originated by member ASes), or a bare AS.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
```

Engine mechanics that matter:

- **Cycle detection.** as-sets reference each other, sometimes cyclically (`AS-A` includes `AS-B` includes `AS-A`). DFS with a visited-set keyed by canonical set name; a revisit is skipped, not an error (matches `bgpq4` behavior).
- **Memoization within a run.** The same sub-set is referenced from many places; cache expansions for the duration of one top-level call. Caching *across* calls belongs to the `Source`, not the engine, because freshness policy varies.
- **Fan-out guard.** Real as-sets (e.g. some tier-1 customer cones) expand to *hundreds of thousands* of prefixes. `MaxPrefixes` returns a typed `ErrSetTooLarge{Name, Count}` rather than OOM-ing — the caller decides whether to chunk or reject. This is a lesson learned the hard way by every team that has fed an unfiltered as-set into a router.
- **AFI constraint.** A v4 expansion must drop `route6`-only members and `mp-members` IPv6 entries, and vice versa. The `afi` dictionary from RFC 4012 makes this explicit; `any` means both.
- **Source precedence.** When the same set name exists in multiple IRRs, the `Sources` order decides which wins (or whether to union). Hijack-relevant; surfaced as configuration, not buried.

### 8.4 Prefix-range materialization

A `route-set` member like `192.0.2.0/24^16-24` denotes every more-specific in that length window. The engine defers to `types.PrefixRange.Materialize`, but applies `MaxPrefixes` *during* enumeration so a single pathological `^0-32` can't blow the budget before the cap check.

---

## 9. Top-level façade

```go
package rpsl

// ParseObject parses exactly one object (lenient: returns object + diagnostics).
func ParseObject(text string) (*ast.Object, []Diagnostic)

// Parse parses a stream of blank-line-separated objects (IRR dumps, whois output).
func Parse(r io.Reader) iter.Seq2[*ast.Object, []Diagnostic]  // Go 1.23 iterators

// Decode upgrades a generic object to its typed form.
func Decode(o *ast.Object) (object.Object, []Diagnostic)

type Diagnostic struct {
    Severity Severity // Error | Warning | Info
    Message  string
    Span     lexer.Span
    Rule     string   // e.g. "rpsl4012/except-afi", machine-filterable
}
```

The `iter.Seq2` streaming API matters for IRR dumps — RADB's full dump is multi-GB; you parse it lazily, one object at a time, never holding the whole thing.

---

## 10. The edge cases that will actually bite

A spec-pure parser dies on real data. Budget explicitly for:

- **RIPE deviations.** RIPE's RPSL diverged from RFC 2622 over 25 years (extra attributes, dropped features, `auth:` formats, `abuse-c:`). The class/attribute dictionary should be data-driven (a loadable table), with a built-in RIPE profile and an RFC-strict profile, so you can validate against either.
- **`changed:` / legacy attributes** that RFC strict mode rejects but every historical dump contains.
- **Empty and `+`-only continuation lines** inside `remarks:`/`descr:` (see §3) — the classic round-trip breaker.
- **`mbrs-by-ref: ANY`** — indirect membership open to any maintainer; easy to either over- or under-apply.
- **Mixed-case set names and ASNs** (`as-FOO`, `As65001`) — canonicalize for comparison, preserve for output.
- **`as-set` members that are `route-set`-shaped** and other class-confusion in messy registries — validate member class against context, emit a warning, don't crash.
- **32-bit ASNs in dot notation** (`AS1.10`) still seen in older objects.
- **AS-path regexps with nested braces** `{m,n}` repetition vs. the `{...}` prefix-list braces — the lexer must disambiguate by context (inside `<...>` it's a regexp).

---

## 11. Testing strategy

The correctness bar is "matches the tools operators already trust," so testing is differential and corpus-driven:

1. **Golden round-trip corpus.** A directory of real objects from RIPE/RADB/ARIN; assert `Parse → String` is byte-identical. This guards the lossless property and catches lexer regressions.
2. **Policy-AST table tests** straight out of the RFC 2622/4012 examples (they're conveniently exhaustive — `pref`, multi-peering, `except`/`refine`, `afi` scoping).
3. **Differential expansion tests vs. `bgpq4`.** For a fixed offline IRR snapshot, expand a basket of as-sets/route-sets with both this engine and `bgpq4 -j`/`-b`, diff the prefix/ASN sets. Any divergence is a bug in one of them — and finding `bgpq4` bugs would itself be a credibility win.
4. **Fuzzing** (`go test -fuzz`) on the lexer and the policy parser. RPSL text from the internet is adversarial by nature; the parser must never panic, only diagnose.
5. **Fan-out / cycle property tests** with synthetic set graphs (generated cyclic and deep nestings) to verify limits and termination.

---

## 12. Suggested build order

1. `lexer` + `ast` + lossless round-trip + the golden corpus harness. *Shippable on its own* — already strictly better than the existing library for read/edit use.
2. `types` + `object` typed decoding for the non-policy classes (`mntner`, `person`, `role`, `route`, `route6`, the set classes' *raw* members). Covers the bulk of what people query.
3. `policy` parser for `import`/`export`/`default`. The intellectually hardest, most differentiating layer.
4. RFC 4012: `mp-*`, `afi`, `except`/`refine`, `route6`.
5. `resolve` engine + in-memory `Source` + differential tests vs `bgpq4`.
6. Live/IRRd/RDAP `Source` backends.

Stop-and-ship points after 1, 2, and 5 — each is independently useful, so the project delivers value long before it's "complete."

---

## 13. Naming and scope guardrails

- Publish leaves as separate modules (`rpsl/types`, `rpsl/lexer`) so minimal consumers stay dependency-light.
- Keep the engine **pure**: no global state, no implicit network, context-cancellable, all limits explicit. This is what makes it safe to embed in a server doing thousands of expansions.
- Resist scope creep into BGP-table evaluation (AS-path regexp matching against live routes) — that belongs in a separate `bgp` consumer, and conflating them is how RPSL tools become unmaintainable.
