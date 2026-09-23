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
rpsl/                  # ROOT module: top-level façade + object/ + policy/
  rpsl.go              # Parse, ParseWith, ParseObject, Decode, Validate
  object/              # typed objects: AutNum, AsSet, RouteSet, Route, Route6, Mntner, …
  policy/              # the import/export/default grammar → AST (the deep end)

  lexer/               # separate go-get module: tokens, scanner, line-folding
  ast/                 # separate go-get module: generic Object/Attribute + Diagnostic/Severity
  types/               # separate go-get module: ASN, Prefix, PrefixRange, NICHandle, SetName, AddrFamily, …
  auth/                # RFC 2725 authorisation model; cryptography injected
  resolve/             # separate go-get module: pure expansion Expander + Source interface
    irrd/              #   socket-using Source over an IRRd query port
    whois/             #   socket-using Source over plain WHOIS (RIPE-DB)
    rdap/              #   RDAP registration client (registration metadata only)
```

Four leaves (`lexer`, `ast`, `types`, `resolve`) ship as independently `go get`-able modules so a minimal consumer of `types` never transitively pulls in the resolver. The top-level `rpsl` façade, `object`, and `policy` live in the ROOT module — they share the same release cadence as the façade. The `resolve/{irrd,whois,rdap}` subpackages are inside the `resolve` module but isolated so that `cd resolve && go list -deps .` does **not** include `net`: every socket lives only in a backend subpackage.

Imports run strictly downward: `resolve → object → policy → types → ast → lexer`, with the three `resolve/*` backends sitting at the same level as `resolve` and depending on `object` for typed values. The direction is invariant — never the reverse.

For local development the modules are wired together with a root `go.work` (`use`), which overrides the inter-module `require`s — they name the latest release — with the local directories. See [README.md#Releasing](../README.md#releasing) for the per-module tagging order when publishing.

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
    KindBlank                 // empty/whitespace-only line — object-separator candidate
    KindComment               // a standalone full-line comment (first byte is '#')
    KindMalformed             // not a valid attr/continuation/comment/blank; diagnose, but preserved for round-trip
)

type Token struct {
    Kind     Kind
    Name     string    // canonical lowercased attribute name, "" for non-attribute kinds
    Value    string    // comment-stripped, continuation-joined logical value (attributes only)
    Raw      string    // exact source bytes for this token (lossless)
    Span     Span      // byte offsets + 1-based line/col of first and last physical line
    Segments []Segment // maps Value offsets back to source positions
}

type Span    struct{ StartLine, StartCol, EndLine, EndCol, StartByte, EndByte int }
type Segment struct {
    ValStart, ValEnd int // half-open range within Token.Value
    SrcLine, SrcCol  int // 1-based source position of the segment's first byte
    SrcByte          int // source byte offset of the segment's first byte
}
```

The scanner is a hand-written state machine over the lines of its input (not regex), read lazily. Folding is done in the lexer so the `Value` handed up is already the logical value, while `Raw` lets `ast` reproduce the original. Its line rules — what is blank, what starts an attribute — are exported (`IsBlankLine`, `StartsAttribute`) and used by the streaming parser too, so the stream never splits objects differently from how the lexer reads them.

### 3.1 The total-partition invariant

The shipped `Tokenize` is a **total partition** of the input: every byte of the source belongs to exactly one token's `Raw`, in order, with no gaps and no overlaps. Concatenating each token's `Raw` reproduces the source byte-for-byte. This is what makes the lossless round-trip guarantee (§1.2) a property of the lexer rather than an obligation on the layers above — `ast.Object.String` only has to glue `Raw` slices back together; it never has to reconstruct anything. `KindMalformed` exists so the invariant survives hostile input: bytes that aren't a valid attribute, continuation, comment, or blank line still get a token, with a diagnostic surfaced at the `rpsl` façade (`lexer/malformed-line`).

The `Segments` slice is the secondary lossless contract: a folded attribute value joins one segment per physical line (the name line plus each continuation), with each segment mapping `Value` offsets back to source line/column/byte. That lets `ast.Attribute.SpanAt` produce a precise source span for *any* sub-range of a folded value — essential for diagnostics that point at a single offending token inside a multi-line policy expression.

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
func (o *Object) Key() string                   // value of the class (first) attribute
func (o *Object) GetFirst(name string) (Attribute, bool)
func (o *Object) GetAll(name string) []Attribute
func (o *Object) Has(name string) bool

func (o *Object) String() string                // lossless re-serialization
func (o *Object) Append(name, value string) error       // validated; newlines fold into continuations
func (o *Object) Set(name string, values ...string) error // replaces in place, keeping alignment
```

Ordering matters: in an `aut-num`, the *sequence* of `import:` lines encodes precedence (the specification-order rule). So `attrs` is a slice, never a map. `GetAll` preserves document order.

---

## 5. Leaf value types (`types`)

These are the small, reusable, comparable value types every higher layer is built from. Built on `net/netip` so they interoperate with the rest of a modern Go networking stack (and with `bart`/`netipx`).

```go
package types

type ASN uint32                  // 32-bit ASNs; ParseASN("AS65001") -> 65001
func (a ASN) String() string     // "AS65001"

type SetName struct {            // hierarchical: AS1:AS-CUSTOMERS
    canon string                  // unexported: only ParseSetName builds one
    class SetClass                // shared by every set component
}
// ParseSetName enforces RFC 2622 §2/§5: set components use [A-Za-z0-9_-] and end
// in a letter or digit, at least one component is a set, all set components
// share a class. So a SetName is safe to interpolate into an IRRd/whois query.
// It holds only the canonical form (set components upper-cased, ASNs asplain),
// so every spelling of a name is == and one map key: Class(), String(),
// Components(), IsZero(). The original spelling stays in the ast layer.

type SetClass uint8 // ClassAsSet ("as-"), ClassRouteSet ("rs-"), ClassRtrSet
                    // ("rtrs-"), ClassFilterSet ("fltr-"), ClassPeeringSet ("prng-")

type PrefixRange struct {        // 192.0.2.0/24^+  /  ^-  /  ^24  /  ^24-28
    prefix netip.Prefix          // opaque and canonical: host bits cleared
    lo, hi uint8                 // the window of lengths it denotes
}
// NewPrefixRange(p, lo, hi) and ParsePrefixRange build one; Prefix(), Lo(),
// Hi() read it and Op() is the most specific spelling of its window, so
// "/8^24-24" and "/8^24" are == and one map key. IsEmpty() reports a range that
// denotes nothing, such as a parsed "192.0.2.1/32^-".
// Materialize enumerates concrete prefixes the range denotes, bounded by a cap.
func (r PrefixRange) Materialize(maxPrefixes int) ([]netip.Prefix, error)

type RangeOperator struct {      // an operator without a prefix: RS-FOO^+, AS1^24-32
    Op   RangeOp
    N, M uint8
}
// Apply composes an outer operator over a range (RFC 2622 §2, §5.2): ^n-m over
// ^k-l becomes ^max(n,k)-m if m >= max(n,k), otherwise the prefix is deleted;
// ^+ over ^k-l is ^k-32 and ^- is ^(k+1)-32 (the operator applies to every
// prefix the inner range contains).
func (o RangeOperator) Apply(r PrefixRange) (PrefixRange, bool)

type AddrFamily struct { AFI AFI; SAFI SAFI } // RFC 4012 afi dictionary
// afi ipv4.unicast, ipv6.unicast, any.unicast, any, …
```

The `^operator` parsing on prefix ranges is one of the spots regex parsers fumble; making it a first-class type with an explicit `Materialize` (and a hard cap) keeps the fan-out controllable.

---

## 6. Typed objects (`object`)

A typed wrapper per class, each backed by an `ast.Object` so you can always drop back to raw. Construction is via a class registry, so unknown classes degrade gracefully to the generic object instead of erroring.

```go
package object

// Common holds the RFC 2622 §3.1 attributes every class carries; each typed
// struct embeds it, so obj.MntBy, obj.Source, … read the same everywhere.
type Common struct {
    Descr   []string
    AdminC  []types.NICHandle
    TechC   []types.NICHandle
    Remarks []string
    Notify  []string
    MntBy   []string
    Changed []string
    Source  string
}

// Registry holds what RIPE's templates add across classes (org:, abuse-c:,
// mnt-lower:, mnt-routes:, created:, …); embedded beside Common, so every
// attribute either profile lists has a typed home.
type Registry struct {
    Org           []string
    SponsoringOrg string
    AbuseC        types.NICHandle
    MntLower, MntRoutes, MntDomains, MntIrt, MntRef []string
    Created, LastModified string
}

type AutNum struct {
    Common
    Registry
    AS        types.ASN
    AsName    string
    MemberOf  []types.SetName
    Imports   []policy.Import  // parsed import: AND mp-import:, in document order
    Exports   []policy.Export  // parsed export: AND mp-export:
    Defaults  []policy.Default // parsed default: AND mp-default:
    ImportVia []policy.Import  // parsed import-via:, kept apart from Imports (§7)
    ExportVia []policy.Export  // parsed export-via:
    raw       *ast.Object
}

type AsSet struct {
    Common
    Registry
    Name      types.SetName
    Members   []SetMember // ASNs and nested set names (raw, unexpanded)
    MpMembers []SetMember // mp-members: some IRRs accept it on as-sets; RFC 4012 and RIPE do not
    MbrsByRef []string    // mntner names enabling indirect membership
    raw       *ast.Object
}

type RouteSet struct {
    Common
    Registry
    Name      types.SetName
    Members   []SetMember // prefix-ranges, set names, or AS numbers (with ^op)
    MpMembers []SetMember // RFC 4012 mp-members (may carry IPv6)
    MbrsByRef []string
    raw       *ast.Object
}

type Route struct {             // Route6 has the same shape
    Common
    Registry
    Prefix   netip.Prefix
    Origin   types.ASN
    MemberOf []types.SetName    // indirect route-set membership claims
    Holes    []netip.Prefix
    // … pingable, inject, components, aggr-bndry, aggr-mtd, export-comps
    raw      *ast.Object
}
```

Decoding into a typed object is fallible *per attribute*: `DecodeAutNum` returns the `AutNum` it could build plus a `[]Diagnostic` for the lines it couldn't, rather than failing whole-object. This is the resilience principle made concrete.

Every attribute a validation profile (`object/profiles.go`) lists for a class is surfaced on that class's struct, in its own field; `TestEveryAttributeLandsInItsOwnField` enforces the agreement by reflection — each attribute's value must land in the field named for it, and each of a class's own fields must be fed by some attribute — so a profile entry without a decoder, or a decoder writing the wrong field, fails the build.

---

## 7. The policy AST (`policy`) — the actual hard part

This is what separates a real RPSL library from an attribute scanner. An `import:`/`export:` value is a small language. RFC 4012's `mp-import:` adds address-family scoping and the `except`/`refine` block structure.

Grammar as implemented (RFC 2622 §5-6 + RFC 4012 §2.5). Every value is either
consumed completely or diagnosed — a leftover token is `policy/trailing`, never
silently dropped:

```ebnf
policy      = [afi-list] expr [";"] EOF
expr        = term [";"] ("EXCEPT" | "REFINE") [afi-list] expr   (* right-recursive:
            | term                                                   "performed right to left" *)
term        = factor | "{" { expr ";" } [expr] "}"
factor      = peer-clause {peer-clause} ("accept" | "announce") filter
            | via-clause {via-clause} ("accept" | "announce") filter   (* import-via:, export-via: *)
peer-clause = ("from" | "to") peering ["action" action {";" action} [";"]]
via-clause  = peering ("from" | "to") peering ["action" action {";" action} [";"]]
action      = rp-attr ("=" | ".=") value | rp-attr "." method "(" args ")"
            | rp-attr ("+=" | "-=" | "*=" | "/=" | "<<=" | ">>=") value   (* RFC 2622 Fig. 25 *)
peering     = as-expr [router-expr] ["at" router-expr] | prng-name | "<" regexp ">"
as-expr     = as-and {"OR" as-and}
as-and      = as-prim {("AND" | "EXCEPT") as-prim}       (* EXCEPT binds like AND *)
as-prim     = ASN | as-set | set-template | "(" as-expr ")"
filter      = f-and {["OR"] f-and}                       (* "x y" is "x OR y" *)
f-and       = f-not {"AND" f-not}
f-not       = "NOT" f-not | f-prim
f-prim      = "(" filter ")" | "{" prefix-ranges "}" [op] | "<" regexp ">" | "ANY"
            | ("PeerAS" | ASN | set-name | set-template) [op]
            | ("community" | "community.contains") "(" … ")"   (* RFC 2622 §7 *)
            | "community" "==" "{" community {"," community} "}"
default     = [afi-list] "to" peering ["action" …] ["networks" filter] [";"] EOF
```

A term followed by `(` is an implicit OR with a group (`AS1 (AS2 OR AS3)`), never a
method call. Only the route tests `community(…)` and `community.contains(…)` are
filters; a method that modifies a route (`aspath.prepend(…)`, `community.append(…)`)
is an action and is diagnosed (`policy/filter-method`), as is an unterminated call.

`set-template` is a set name with `PeerAS` components (`AS1:AS-CUSTOMERS:PeerAS`),
an IRR convention common in RIPE data. An mp-* value with no afi clause applies to
every family (RFC 4012 §2.5); a legacy import:/export:/default: to ipv4.unicast,
and an afi clause in one is an error (it is RFC 4012 mp-* syntax) and is ignored.

`import-via:` and `export-via:` (draft-ietf-grow-rpsl-via, implemented by RIPE)
are mp-import:/mp-export: whose every clause first names the peering the routes
pass through — an exchange's route server — as `PeerAction.Via`: `AS6777 from
AS15562 accept AS-SNIJDERS`. They are MP, so no afi clause means every family.
Two readings keep a clause boundary unambiguous where the next clause's via
peering follows the previous clause directly: an action list ends where a
segment runs up to the peer keyword (`… med=100; AS6777 from …`), and a word
that can only begin a peering — an AS number, an as-set or peering-set name —
ends a router expression rather than extending it. A clause with no via peering
is `policy/via` and is dropped. `AutNum` keeps these policies apart from
`Imports`/`Exports`, so a consumer that does not read `Via` cannot mistake a
route-server policy for a direct peering; `Flatten` carries `Via` into each
`Term` and REFINE meets two terms only where their via peerings meet too.

An action is one of the forms above, one per `;`: `pref=10 med=20` or two method
calls without a `;` between them are `policy/action`, not one action with an odd
value. The Figure 25 assignments other than `=` and `.=` are the operator methods
they name (`med += 5` is Method `operator+=`); a comparison (`pref == 10`) tests a
route and is never an action. A prefix list needs its commas. `NOT` is not an AS-
or router-expression operator — RFC 2622 §5.6 example 6 uses it, but the grammar
has none — so it is diagnosed with a pointer to `EXCEPT`.

Modeled as a sealed interface hierarchy (Go's stand-in for sum types — the pattern you'd reach for coming from a real type-system language):

```go
package policy

type Import struct {
    Protocol, IntoProtocol string
    MP   bool               // mp-import: (ParseMPImport) — decides the no-afi default
    AFIs []types.AddrFamily // afi clause as written
    Expr Expr
}

type Expr interface{ isExpr() }                 // sealed
type Factor struct{ Peers []PeerAction; Filter Filter }
type ExprList struct{ Exprs []Expr }            // { e1; e2; }
type Except struct{ Left, Right Expr; AFIs []types.AddrFamily }
type Refine struct{ Left, Right Expr; AFIs []types.AddrFamily }

type Peering interface{ isPeering() }           // PeeringAS{AS, Router, AtRouter}, PeeringSetRef, PeeringRegexp
type RouterExpr interface{ isRouterExpr() }     // RouterAddr, RouterName, RouterSetRef, RouterExprBinary{AND|OR|EXCEPT}
type ASExpr interface{ isASExpr() }             // ASNum, ASSetRef, ASSetTemplate, ASExprBinary{AND|OR|EXCEPT}

type Filter interface{ isFilter() }             // sealed; Op = range operator on the term
type FilterAny struct{}
type FilterPeerAS struct{ Op types.RangeOperator }
type FilterPrefixList struct{ Ranges []types.PrefixRange } // outer {…}^op composed in
type FilterASExpr struct{ AS ASExpr; Op types.RangeOperator }
type FilterSetRef struct{ Name types.SetName; Op types.RangeOperator }
type FilterSetTemplate struct{ Template SetNameTemplate; Op types.RangeOperator }
type FilterPathRE struct{ Raw string; Regexp *ASPathRE } // structured; see below
type FilterCommunity struct{ Op CommunityOp; Values []string; Raw string } // community(…), == {…}
type FilterAnd struct{ Terms []Filter } // "a AND b AND c": one node, 2+ terms
type FilterOr struct{ Terms []Filter }  // "a OR b", and implicit "a b c"
type FilterNot struct{ Inner Filter }
```

AS-path regexps parse into their own sealed tree (`ASPathExpr`): anchors `^`/`$` as
atoms anywhere, `.`, ASNs, as-sets, templates, `PeerAS`, `[...]`/`[^...]` classes
with `AS1 - AS10` ranges, `* + ? {m,n}` and the same-AS `~* ~+ ~{m,n}` forms,
concatenation and `|`. An unknown byte is an error, never skipped, and so is a
term that names any other kind of set (`<RS-FOO>`, RFC 2622 §5.4), an empty `<>`,
a `<` never closed and a `>` that closes nothing. A bare number (`<3333>`) is read
as that AS with a warning, since RPSL writes `AS3333`. Regexp diagnostics point at
the offending token, not the whole `<…>`.

Two deliberate calls here:

- **AS-path regular expressions** (`<...>`) are parsed into their own AST (operators `^ $ . * + ? | ( ) { }` over AS / as-set terms) but *not evaluated* against live paths — evaluation is a BGP-table concern, not a registry concern. Keeping them structured (rather than as opaque strings) means a consumer can still translate them to a router config, which is the main real use.
- **Actions** are kept as typed `{Attr, Method, Op, Args, Value, Raw}` records (`community.append(1:2)` is Attr `community`, Method `append`) rather than fully interpreting every RP-attribute, because the RP-attribute dictionary is open-ended (RFC 2622 §9 / the `dictionary` object). The common ones (`pref`, `med`, `community`, `aspath.prepend`) get typed helpers; the rest round-trip faithfully.

Resource bounds: a value over 1,048,576 tokens is refused before its tokens are built (`policy/too-long`; the largest real value, a RIPE IPv6 bogon filter-set, has about 236,000), diagnostics stop after 100 per value (`policy/too-many-errors`), and nesting — parentheses, braces, NOT, AS-expression operators, AS-path quantifiers — is capped at 1,000. With AND/OR chains flat, the AST is never deeper than that cap, so a consumer's recursive walk cannot overflow its stack.

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
    // objects from the set's own source, maintained by one of its mbrs-by-ref
    // mntners, that claim member-of this set (filtered with ClaimAllowed).
    MembersByRef(ctx context.Context, set object.Set) ([]object.Object, error)
}
```

Backends to ship: an in-memory `Source` (for tests and for loading an IRRd snapshot/`.db` dump), an HTTP/RDAP+WHOIS `Source`, and a thin `Source` over a local IRRd mirror's query port. The engine never opens a socket itself.

### 8.2 Dual membership

A set's members come from **two** places and the engine must union them:

1. **Direct** — the `members:` / `mp-members:` attribute lists ASNs, prefix-ranges, and nested set names.
2. **Indirect** — other objects assert `member-of:` *this* set. Per RFC 2622 this is only honored when the set carries `mbrs-by-ref:` and the asserting object is maintained by one of the listed mntners (or `mbrs-by-ref: ANY`). Skipping the mntner check is a common correctness bug; the engine enforces it via `Source.MembersByRef` and re-checks every claim with `ClaimAllowed`.

   The claim must also come from the set's own `source:`. Maintainer names are unique only within one registry, so without this rule anyone who registers a same-named mntner in a permissive IRR (RADB) could add members to a RIPE set once several IRRs are loaded together. IRRd applies the same rule (its mbrs-by-ref index is keyed by source and set), so `RIPE-NONAUTH` does not claim into `RIPE`. An absent source matches only an absent source.

### 8.3 Traversal, cycles, and limits

```go
type Expander struct {
    Src         Source
    MaxDepth    int       // cap on shortest nesting distance from the top (default 32)
    MaxPrefixes int       // cap on output prefixes, or ranges (default 1<<20)
    MaxVisited  int       // cap on distinct sets fetched per call (default 1<<17)
    AFI         types.AFI // constrain to v4 or v6 (Unspecified / Any = both)
}

// ExpandAS returns the ASNs of every as-set reachable from n, plus indirect aut-num members.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASNSet, error)

// ExpandPrefixRanges returns the prefix ranges of a route-set or as-set (routes
// of member ASes), with member range operators composed — bgpq4's le/ge form.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error)

// ExpandPrefixes is ExpandPrefixRanges, materialized under MaxPrefixes.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
```

(A bare AS is not a SetName; its prefixes come straight from `Source.OriginatedRoutes`.)

Engine mechanics that matter:

- **Two phases.** *Discovery* walks the set graph breadth-first from the named set, fetching every reachable set once — so a set's depth is its shortest nesting distance and the result never depends on member order — together with its indirect members and, for prefix expansions, each member AS's routes (once per AS per call). *Evaluation* builds the result from that graph with no further I/O. Caching *across* calls belongs to the `Source`, because freshness policy varies.
- **Class rules.** Discovery and evaluation follow only the nestings RFC 2622 §5.1-5.2 allows: an as-set lists as-sets; a route-set lists route-sets and as-sets. A route-set listed inside an as-set is invalid data and is not followed — otherwise any nested as-set could inject prefixes that no route object backs. `ExpandAS` takes an as-set and the prefix expansions an as-set or route-set; any other class returns `ErrSetClass`.
- **Cycle detection.** as-sets reference each other, sometimes cyclically (`AS-A` includes `AS-B` includes `AS-A`). A revisit is skipped, not an error (matches `bgpq4` behavior). With range operators, evaluation states are (set, operator stack) pairs, and a stack is identified by what it does — for each family, the lower bound it maps each inner lower bound to (or deletion) and the upper bound the outermost operator sets — so `^+^+` and `^+` are one state. The states are finite: every reachable one is walked once, and cycles through operators (`RS-A` lists `RS-B^+`, `RS-B` lists `RS-A`) terminate at the RFC's least fixpoint rather than being refused. `MaxVisited` bounds the states walked.
- **Range operators on members.** `RS-FOO^+` applies to each range of RS-FOO and `AS1^24` to each route AS1 originates, composing along the path with `types.RangeOperator.Apply` (RFC 2622 §5.2).
- **Fan-out guards (three of them).** Real as-sets (e.g. some tier-1 customer cones) expand to *hundreds of thousands* of prefixes. `MaxPrefixes` bounds distinct output, `MaxVisited` (default `1<<17` = 131,072) bounds the sets fetched, and `MaxDepth` (default 32) bounds the shortest nesting distance. Each returns a `*SetTooLargeError{Name, Limit, Max, Count}` naming the cap — the caller decides whether to chunk or reject; none truncates a result silently.
- **Missing and unexpandable sets.** A missing top-level set is an error wrapping `ErrNotFound`; missing nested sets expand to nothing, as in bgpq4, and are listed by the result's `Missing()`. An existing set with no members is empty, not missing, in every backend: IRRd answers `!i` alike for both, so the irrd `Source` checks with `!m`. `AS-ANY`/`RS-ANY` denote the whole IRR and return `AnySetError`.
- **Indirect membership.** Per RFC 2622 §5.1-5.2, an as-set's indirect members are aut-nums and a route-set's are routes; each claim must pass `ClaimAllowed` (member-of + mbrs-by-ref mntner check), which the engine re-applies to whatever the `Source` returns.
- **AFI constraint.** A v4 expansion must drop `route6`-only members and `mp-members` IPv6 entries, and vice versa. The `afi` dictionary from RFC 4012 makes this explicit; `any` means both. A *SAFI* has no role here: no RPSL set member carries one and there is no multicast route class, so `Expander.AFI` is an `AFI`, and the sub-family matters only where RFC 4012 puts it — in `policy.Import`/`Export`/`Default.AppliesTo`.
- **The other set classes.** `ExpandRouters` walks an `rtr-set` to routers (`types.RouterID`), `ExpandPeerings` a `peering-set` to the peerings it denotes with nested references replaced, and `ExpandFilterSet`/`EvalFilter` a `filter-set`'s expression to prefix ranges. Discovery is the same breadth-first traversal for all of them; only what counts as a nested name, and which indirect claims are honored, differs by class.
- **Filters are only partly enumerable.** `EvalFilter` evaluates `ANY`, prefix lists, route-set/as-set/filter-set references, AS numbers and AS expressions, `OR`, and `AND` (the intersection of two range sets, via `types.PrefixRange.Intersect`). `NOT`, `PeerAS`, community tests, AS-path regexps and per-peer templates have no finite prefix denotation, and return a `*NotEnumerableError` naming the term instead of a quietly smaller answer.
- **Concurrency is optional and invisible.** `Expander.Concurrency` fetches one breadth-first level at a time and merges the answers in the level's own order, so a parallel expansion returns exactly what a serial one does.
- **Source precedence.** When the same set name exists in multiple IRRs, the `Source` decides which wins (`irrd.Source.Sources`, `NewMemSource(objs, "RIPE", "RADB")`). Hijack-relevant; surfaced as configuration, not buried.

### 8.4 Prefix-range materialization

A `route-set` member like `192.0.2.0/24^16-24` denotes every more-specific in that length window. `ExpandPrefixes` streams each range through the lazy `types.PrefixRange.All()` into a deduplicating set and stops at the first prefix over `MaxPrefixes`, so a single pathological `^0-32` cannot blow the budget, overlapping ranges are never double-charged, and memory is bounded by the cap. Library consumers enforcing one budget across many ranges should do the same rather than call `Materialize` per range.

### 8.5 IRRd wire framing

The `resolve/irrd` backend speaks the bog-standard IRRd query protocol. Each response is one frame:

```
A<len>\n<payload>C\n
```

where `<len>` is the byte length of the payload **including** the payload's trailing newline. After `ReadFull(payload)` the next `ReadString('\n')` consumes the `C\n` status line directly — there is no separator newline to skip. Getting this off-by-one wrong silently desynchronizes the reader against pipelined queries; see `resolve/irrd/readframe_test.go` for the canonical wire-shape test. This belongs in the design (rather than as a backend implementation detail) because every future IRRd-style backend has to match it.

---

## 9. Top-level façade

```go
package rpsl

// ParseObject parses exactly one object (lenient: returns object + diagnostics).
func ParseObject(text string) (*ast.Object, []Diagnostic)

// Parse parses a stream of blank-line-separated objects (IRR dumps, whois output).
// Lazy: holds at most one finished object and the one in progress.
func Parse(r io.Reader) iter.Seq2[*ast.Object, []Diagnostic]  // Go 1.23 iterators

// ParseWith is Parse with explicit options.
func ParseWith(r io.Reader, opts ParseOptions) iter.Seq2[*ast.Object, []Diagnostic]

const DefaultMaxObjectBytes = 16 << 20 // largest RIPE object: ~2 MB
const DefaultMaxObjectLines = 1 << 18  // longest RIPE object: ~20,000 lines

type ParseOptions struct {
    // MaxObjectBytes and MaxObjectLines cap one object and, separately, the
    // blank/comment lines before it; over-long lines are discarded as they
    // stream. 0 means the default, negative means unlimited. Breaches are
    // diagnosed ("rpsl/object-too-large", "rpsl/trivia-too-large") and parsing
    // resumes. With the defaults, no input makes the parser use more than about
    // 150 MB; ParseObject, whose text is already in memory, applies no caps.
    MaxObjectBytes int64
    MaxObjectLines int
}

// Decode upgrades a generic object to its typed form.
func Decode(o *ast.Object) (object.Object, []Diagnostic)

// Validate checks an object against a class/attribute profile (RIPE, RFCStrict).
func Validate(o *ast.Object, p Profile) []Diagnostic
```

The `iter.Seq2` streaming API matters for IRR dumps — RADB's full dump is multi-GB; you parse it lazily, one object at a time, never holding the whole thing. The stream is lossless like a single object: each object owns the blank, comment and malformed lines before it (the last object also owns the trailing ones), so concatenating every yielded `String()` reproduces the input byte-for-byte. Positions in streamed objects — and in diagnostics derived from them — are relative to the stream. A read error ends the stream with an `rpsl/read-error` diagnostic rather than posing as end of input, and the default cap keeps even hostile input (no separators, a multi-GB line) within bounded memory.

### 9.1 Where Diagnostic lives

`Diagnostic` and `Severity` live in the **`ast`** module, not in the `rpsl` façade. They have to: `object/` emits diagnostics during typed decoding, and `object` depends on `ast` but not on `rpsl`. The `rpsl` package re-exports both via type aliases (`type Diagnostic = ast.Diagnostic`, `type Severity = ast.Severity`) and const aliases (`Info`, `Warning`, `Error`) so the façade still reads as a single import for typical use.

```go
package ast

type Severity uint8

const (
    Info Severity = iota
    Warning
    Error
)

type Diagnostic struct {
    Severity Severity
    Message  string
    Span     lexer.Span // 1-based line/col + half-open byte range
    Rule     string     // stable machine-filterable id, e.g. "lexer/malformed-line"
}
```

`Rule` is the recommended dispatch key. Severity ordering is `Info < Warning < Error`, so `d.Severity >= ast.Warning` is the canonical "did something go wrong" filter.

---

## 10. The edge cases that will actually bite

A spec-pure parser dies on real data. Budget explicitly for:

- **RIPE deviations.** RIPE's RPSL diverged from RFC 2622 over 25 years (extra attributes, dropped features, `auth:` formats, `abuse-c:`). The class/attribute dictionary is data-driven (a loadable table), with a built-in RIPE profile and an RFC-strict profile, so you can validate against either. The RIPE profile is RIPE's own templates (`whois -t <class>`, kept in `object/testdata/ripe-templates` and checked by `TestRIPEProfileMatchesTemplates`, and against whois.ripe.net by the live test); the RFC-strict profile follows the tables of RFC 2622, 2725, 2726 and 4012.
- **`changed:` / legacy attributes** that RFC strict mode rejects but every historical dump contains.
- **Empty and `+`-only continuation lines** inside `remarks:`/`descr:` (see §3) — the classic round-trip breaker.
- **`mbrs-by-ref: ANY`** — indirect membership open to any maintainer; easy to either over- or under-apply.
- **Mixed-case set names and ASNs** (`as-FOO`, `As65001`) — canonicalize for comparison, preserve for output.
- **`as-set` members that are `route-set`-shaped** and other class-confusion in messy registries — validate member class against context, emit a warning, don't crash.
- **32-bit ASNs in dot notation** (`AS1.10`) still seen in older objects.
- **AS-path regexps with nested braces** `{m,n}` repetition vs. the `{...}` prefix-list braces — the lexer must disambiguate by context (inside `<...>` it's a regexp).

---

## 11. Testing strategy

The correctness bar is "matches the tools operators already trust," so testing is differential and corpus-driven, and the suite is judged by whether it catches bugs: each bug the reviews found was put back in, one at a time, and a test had to fail.

1. **Golden round-trip corpus.** A directory of real objects from RIPE/RADB/ARIN; assert `Parse → String` is byte-identical. This guards the lossless property and catches lexer regressions.
2. **Policy tests from the RFCs.** Table tests for the grammar's forms, and every routing-policy example in RFC 2622, 2650 and 4012 kept verbatim in `policy/testdata/rfc-examples.txt`: each must parse clean, except the one the parser rejects on purpose (RFC 2622's `NOT` in a peering).
3. **A model of the engine.** Random IRRs — as-sets and route-sets in two sources, range operators on every kind of member, indirect members honored and rejected, cycles, missing and invalid members, `AS-ANY` — are expanded by the engine and by a brute-force oracle that evaluates RFC 2622 straight from the generator's model, never from parsed text. They must agree on AS numbers, prefixes of each family, `Missing()`, and on `MaxDepth`/`MaxPrefixes` holding exactly at the true depth and size. The same IRRs are served by `resolve/internal/irrtest`, an in-process server that answers the IRRd and whois protocols as IRRd does, so `irrd.Source`, `whois.Source` and `MemSource` are held to the same oracle.
4. **Differential expansion vs. `bgpq4`.** A real `bgpq4` binary queries `irrtest` serving the same objects the engine expands (bgpq4 recurses through as-sets itself with `-L`; route-sets it asks the server to resolve with `!i…,1`, which `irrtest` implements as IRRd does). Random IRRs must expand identically, AS numbers and both families' prefixes; the golden expansions of the snapshot in `resolve/testdata` are bgpq4's own output, re-checked whenever bgpq4 is installed (CI installs it). Where the two knowingly differ — bgpq4 drops the single-length `^n` form (a bgpq4 bug), neither IRRd nor bgpq4 applies range operators on set and AS members, bgpq4 follows route-sets listed in as-sets — the difference is pinned in `resolve/testdata/bgpq4/divergences.md` and a test, so a change on either side fails. An opt-in run (`RPSL_REALDATA`) does the same for the largest and a random sample of real RIPE sets. An older opt-in diff against bgpq4 on a live IRR runs when `RPSL_BGPQ4_SERVER`/`RPSL_BGPQ4_SET` are set.
5. **Fuzzing** (`go test -fuzz`) of every parser that takes untrusted text — lexer, attribute lists, set names, range operators, prefix ranges, the stream, decoding, editing, and the policy parser (import, filter, peering, AS-path regexp) — for properties, not only for panics:
   - every token's span and segments point at its bytes, and its kind follows the line rules the stream shares;
   - the stream is lossless, splits objects where the lexer sees them end, yields each object exactly as `ParseObject` reads its text (positions shifted), resumes after a break, and under caps drops only whole, diagnosed objects;
   - `Append`/`Set` produce text that parses back to exactly the edit, other attributes' bytes untouched;
   - `Decode` and `Validate` keep diagnostics inside the object, and a clean object decodes the same after changes RPSL gives no meaning to (`+` lines, name case, trailing spaces, CRLF);
   - policy diagnostics stay in the value and under the cap, the AST under the nesting cap, and keyword case or extra whitespace change nothing.
6. **Engine property tests** with synthetic set graphs (cyclic and deep nestings, operator cycles) against brute-force oracles, to verify results, limits and termination, and an oracle for `RangeOperator.Apply` against the per-prefix meaning of RFC 2622 §2.
7. **Contracts.** Every attribute a validation profile lists lands in its own field of the typed struct (`TestEveryAttributeLandsInItsOwnField`), and every diagnostic rule the library emits is in `docs/diagnostics.md` with its severity, and every rule listed there is emitted (`TestDiagnosticRulesAreDocumented`).
8. **Real-data regression** (opt-in, `RPSL_REALDATA`). Streams the RIPE split dumps (`scripts/fetch-ripe-dumps.sh`: as-set, route-set, route, route6, aut-num, filter-set, peering-set) and checks that the stream is lossless, raises no stream-level diagnostics, decodes every route and route6 to a valid prefix, and puts Errors of any one family on at most 0.1 % of objects (at least 3 tolerated); then expands the largest real as-sets and route-sets twice, in opposite input orders, and requires identical results.
9. **Live smoke test** (opt-in, `RPSL_LIVE=1`). Queries RADB (over both the IRRd protocol and whois), RIPE whois and RIPE RDAP read-only and asserts only stable facts (AS3333 originates 193.0.0.0/21; a made-up set is not found). It caught IRRd closing the connection after one command without `!!`, and IRRd's whois parser needing every flag before `-i`. `TestRIPETemplatesAreCurrent` (in `object`, same switch) compares the RIPE template fixtures with whois.ripe.net, so a template change there fails a test here.

`scripts/check.sh` runs 1–7 for every module under the race detector, with per-package coverage (plus gofmt, staticcheck, govulncheck and the leaf-isolation and engine-purity invariants); CI installs bgpq4 and runs it with a short `FUZZTIME` on Go 1.23 and the latest stable Go.

---

## 12. Suggested build order

1. `lexer` + `ast` + lossless round-trip + the golden corpus harness. *Shippable on its own* — already strictly better than the existing library for read/edit use.
2. `types` + `object` typed decoding for the non-policy classes (`mntner`, `person`, `role`, `route`, `route6`, the set classes' *raw* members). Covers the bulk of what people query.
3. `policy` parser for `import`/`export`/`default`. The intellectually hardest, most differentiating layer.
4. RFC 4012: `mp-*`, `afi`, `except`/`refine`, `route6`.
5. `resolve` engine + in-memory `Source` + differential tests vs `bgpq4`.
6. Live/IRRd/RDAP `Source` backends.

Stop-and-ship points after 1, 2, and 5 — each is independently useful, so the project delivers value long before it's "complete."

**Status (current).** All six milestones are shipped, and a seventh closed the gaps between
them and this document: the streaming lexer/`ast` and lossless round-trip (plus `ast.Builder`
and the opt-in `Format`), the typed `object` layer for all 22 classes with every attribute
sub-grammar of RFC 2622 §8.1 and §9 parsed, the `policy` AST with canonical `String()`,
`Flatten` for `except`/`refine` and the RFC 2622 §9 RP-attribute dictionary, the `resolve`
engine expanding every set class — including `EvalFilter` over the enumerable fragment of the
filter language — with in-memory, dump and caching `Source`s, optional concurrency and the
bgpq4 differential, the three live backends in `resolve/{irrd,whois,rdap}`, and the `auth`
package for RFC 2725. See [README.md#Status](../README.md#status) for the same matrix in
shipping form.

Three limits are deliberate and are not gaps. AS-path regexps are parsed but never evaluated
against live paths (§13). Filter evaluation covers only the terms with a finite answer in
prefixes, and names the others in a `NotEnumerableError` rather than quietly returning less.
And `auth` verifies no credential itself: cryptography arrives through a `Verifier`, the same
injection `Source` uses, so the library stays dependency-free.

---

## 13. Naming and scope guardrails

- Publish leaves as separate modules (`rpsl/types`, `rpsl/lexer`) so minimal consumers stay dependency-light.
- Keep the engine **pure**: no global state, no implicit network, context-cancellable, all limits explicit. This is what makes it safe to embed in a server doing thousands of expansions.
- Resist scope creep into BGP-table evaluation (AS-path regexp matching against live routes) — that belongs in a separate `bgp` consumer, and conflating them is how RPSL tools become unmaintainable.

---

## 14. Integration harness (`examples/bulk-ripe`)

The library's correctness story rests on three pillars: unit tests per package, the golden lossless-round-trip corpus, and the bgpq4 differential for the engine. None of those exercises the streaming parser at the scale it has to survive in production — a multi-GB RIPE split dump fed in one byte at a time, with the parser holding only the current object in memory.

`examples/bulk-ripe` is the integration harness for that scale. It streams an RPSL bulk dump (e.g. RIPE's split files from `ftp://ftp.ripe.net/ripe/dbase/split/`) through `rpsl.Parse` / `ParseWith`, validates each decoded object against a chosen profile, optionally smoke-tests the `resolve.Expander` against a sample of retained sets, and prints a throughput + diagnostic-histogram report. A `lexer/malformed-line` rule appearing in the histogram on a canonical RIPE feed is a streaming/boundary regression — the report surfaces a hint to that effect.

See [`examples/bulk-ripe/README.md`](../examples/bulk-ripe/README.md) for invocation, flags, and reference output.
