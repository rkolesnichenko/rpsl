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
  resolve/             # separate go-get module: pure expansion Expander + Source interface
    irrd/              #   socket-using Source over an IRRd query port
    whois/             #   socket-using Source over plain WHOIS (RIPE-DB)
    rdap/              #   RDAP registration client (registration metadata only)
```

Four leaves (`lexer`, `ast`, `types`, `resolve`) ship as independently `go get`-able modules so a minimal consumer of `types` never transitively pulls in the resolver. The top-level `rpsl` façade, `object`, and `policy` live in the ROOT module — they share the same release cadence as the façade. The `resolve/{irrd,whois,rdap}` subpackages are inside the `resolve` module but isolated so that `cd resolve && go list -deps .` does **not** include `net`: every socket lives only in a backend subpackage.

Imports run strictly downward: `resolve → object → policy → types → ast → lexer`, with the three `resolve/*` backends sitting at the same level as `resolve` and depending on `object` for typed values. The direction is invariant — never the reverse.

For local development the modules are wired together with a root `go.work` (`use`); inter-module `require`s are pinned at `v0.0.0` and resolve via the workspace. `go work sync` fails (it tries to fetch the siblings from GitHub) — that is expected. See [README.md#Releasing](../README.md#releasing) for the per-module tagging order when publishing.

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

The scanner is a hand-written state machine over `bufio.Scanner` lines (not regex). Folding is done in the lexer so the `Value` handed up is already the logical value, while `Raw` lets `ast` reproduce the original.

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
    name, canon string            // unexported: only ParseSetName builds one
    class       SetClass          // shared by every set component
}
// ParseSetName enforces RFC 2622 §2/§5: set components use [A-Za-z0-9_-] and end
// in a letter or digit, at least one component is a set, all set components
// share a class. So a SetName is safe to interpolate into an IRRd/whois query.
// Class(), String() (original spelling), Canonical() (identity / map key),
// Components(), IsZero(). Comparable; == is spelling-exact.

type SetClass uint8 // AsSet ("as-"), RouteSet ("rs-"), RtrSet ("rtrs-"),
                    // FilterSet ("fltr-"), PeeringSet ("prng-")

type PrefixRange struct {        // 192.0.2.0/24^+  /  ^-  /  ^24  /  ^24-28
    Prefix netip.Prefix
    Op     RangeOp              // Exact, Minus, Plus, Length(n), Range(n,m)
    Lo, Hi uint8
}
// Materialize enumerates concrete prefixes the range denotes, bounded by a cap.
func (r PrefixRange) Materialize(maxPrefixes int) ([]netip.Prefix, error)

type RangeOperator struct {      // an operator without a prefix: RS-FOO^+, AS1^24-32
    Op   RangeOp
    N, M uint8
}
// Apply composes an outer operator over a range (RFC 2622 §5.2): ^n-m over
// ^k-l becomes ^max(n,k)-m if m >= max(n,k), otherwise the prefix is deleted.
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

type AutNum struct {
    Common
    AS       types.ASN
    AsName   string
    MemberOf []types.SetName
    Imports  []policy.Import  // parsed import: AND mp-import:, in document order
    Exports  []policy.Export  // parsed export: AND mp-export:
    Defaults []policy.Default // parsed default: AND mp-default:
    raw      *ast.Object
}

type AsSet struct {
    Common
    Name      types.SetName
    Members   []SetMember // ASNs and nested set names (raw, unexpanded)
    MpMembers []SetMember // RFC 4012 mp-members
    MbrsByRef []string    // mntner names enabling indirect membership
    raw       *ast.Object
}

type RouteSet struct {
    Common
    Name      types.SetName
    Members   []SetMember // prefix-ranges, set names, or AS numbers (with ^op)
    MpMembers []SetMember // RFC 4012 mp-members (may carry IPv6)
    MbrsByRef []string
    raw       *ast.Object
}

type Route struct {             // Route6 has the same shape
    Common
    Prefix   netip.Prefix
    Origin   types.ASN
    MemberOf []types.SetName    // indirect route-set membership claims
    Holes    []netip.Prefix
    // … pingable, inject, components, aggr-bndry, aggr-mtd, export-comps
    raw      *ast.Object
}
```

Decoding into a typed object is fallible *per attribute*: `DecodeAutNum` returns the `AutNum` it could build plus a `[]Diagnostic` for the lines it couldn't, rather than failing whole-object. This is the resilience principle made concrete.

Every attribute a validation profile (`object/profiles.go`) lists for a class is surfaced on that class's struct; `TestDecoderSurfacesEveryProfiledAttribute` enforces the agreement by reflection, so a profile entry without a decoder — data silently dropped on `Decode` — fails the build.

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
peer-clause = ("from" | "to") peering ["action" action {";" action} [";"]]
peering     = as-expr [router-expr] ["at" router-expr] | prng-name | "<" regexp ">"
as-expr     = as-and {"OR" as-and}
as-and      = as-prim {("AND" | "EXCEPT") as-prim}       (* EXCEPT binds like AND *)
as-prim     = ASN | as-set | set-template | "(" as-expr ")"
filter      = f-and {["OR"] f-and}                       (* "x y" is "x OR y" *)
f-and       = f-not {"AND" f-not}
f-not       = "NOT" f-not | f-prim
f-prim      = "(" filter ")" | "{" prefix-ranges "}" [op] | "<" regexp ">" | "ANY"
            | ("PeerAS" | ASN | set-name | set-template) [op] | rp-attr-method "(" … ")"
default     = [afi-list] "to" peering ["action" …] ["networks" filter] [";"] EOF
```

`set-template` is a set name with `PeerAS` components (`AS1:AS-CUSTOMERS:PeerAS`),
an IRR convention common in RIPE data. An mp-* value with no afi clause applies to
every family (RFC 4012 §2.5); a legacy import:/export:/default: to ipv4.unicast.

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
type ASExpr interface{ isASExpr() }             // ASNum, ASSetRef, ASSetTemplate, ASExprBinary{AND|OR|EXCEPT}

type Filter interface{ isFilter() }             // sealed; Op = range operator on the term
type FilterAny struct{}
type FilterPeerAS struct{ Op types.RangeOperator }
type FilterPrefixList struct{ Ranges []types.PrefixRange } // outer {…}^op composed in
type FilterASExpr struct{ AS ASExpr; Op types.RangeOperator }
type FilterSetRef struct{ Name types.SetName; Op types.RangeOperator }
type FilterSetTemplate struct{ Template SetNameTemplate; Op types.RangeOperator }
type FilterPathRE struct{ Raw string; Regexp *ASPathRE } // structured; see below
type FilterCommunity struct{ Raw string }
type FilterAnd struct{ L, R Filter }
type FilterOr struct{ L, R Filter }
type FilterNot struct{ Inner Filter }
```

AS-path regexps parse into their own sealed tree (`ASPathExpr`): anchors `^`/`$` as
atoms anywhere, `.`, ASNs, as-sets, templates, `PeerAS`, `[...]`/`[^...]` classes
with `AS1 - AS10` ranges, `* + ? {m,n}` and the same-AS `~* ~+ ~{m,n}` forms,
concatenation and `|`. An unknown byte is an error, never skipped.

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
    Src         Source
    MaxDepth    int       // cap on shortest nesting distance from the top (default 32)
    MaxPrefixes int       // cap on output prefixes, or ranges (default 1<<20)
    MaxVisited  int       // cap on distinct sets fetched per call (default 1<<17)
    AFI         types.AFI // constrain to v4 or v6 (Unspecified / Any = both)
}

// ExpandAS returns the ASNs of every as-set reachable from n, plus indirect aut-num members.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error)

// ExpandPrefixRanges returns the prefix ranges of a route-set or as-set (routes
// of member ASes), with member range operators composed — bgpq4's le/ge form.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error)

// ExpandPrefixes is ExpandPrefixRanges, materialized under MaxPrefixes.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
```

(A bare AS is not a SetName; its prefixes come straight from `Source.OriginatedRoutes`.)

Engine mechanics that matter:

- **Two phases.** *Discovery* walks the set graph breadth-first from the named set, fetching every reachable set once — so a set's depth is its shortest nesting distance and the result never depends on member order — together with its indirect members and, for prefix expansions, each member AS's routes (once per AS per call). *Evaluation* builds the result from that graph with no further I/O. Caching *across* calls belongs to the `Source`, because freshness policy varies.
- **Cycle detection.** as-sets reference each other, sometimes cyclically (`AS-A` includes `AS-B` includes `AS-A`). A revisit is skipped, not an error (matches `bgpq4` behavior). With range operators, evaluation walks each set once per distinct operator stack; a set re-entered under the *same* stack is skipped exactly, but one re-entered under a *different* stack (`RS-A` lists `RS-B^+`, `RS-B` lists `RS-A`) would need a fixpoint, so it returns `ErrCyclicOperator` rather than an undersized result.
- **Range operators on members.** `RS-FOO^+` applies to each range of RS-FOO and `AS1^24` to each route AS1 originates, composing along the path with `types.RangeOperator.Apply` (RFC 2622 §5.2).
- **Fan-out guards (three of them).** Real as-sets (e.g. some tier-1 customer cones) expand to *hundreds of thousands* of prefixes. `MaxPrefixes` bounds distinct output, `MaxVisited` (default `1<<17` = 131,072) bounds the sets fetched, and `MaxDepth` (default 32) bounds the shortest nesting distance. Each returns `ErrSetTooLarge{Name, Limit, Count}` naming the cap — the caller decides whether to chunk or reject; none truncates a result silently.
- **Missing and unexpandable sets.** A missing top-level set is an error wrapping `ErrNotFound`; missing nested sets expand to nothing, as in bgpq4, and are listed by the result's `Missing()`. `AS-ANY`/`RS-ANY` denote the whole IRR and return `ErrAnySet`.
- **Indirect membership.** Per RFC 2622 §5.1-5.2, an as-set's indirect members are aut-nums and a route-set's are routes; each claim must pass `ClaimAllowed` (member-of + mbrs-by-ref mntner check), which the engine re-applies to whatever the `Source` returns.
- **AFI constraint.** A v4 expansion must drop `route6`-only members and `mp-members` IPv6 entries, and vice versa. The `afi` dictionary from RFC 4012 makes this explicit; `any` means both.
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

const DefaultMaxObjectBytes = 64 << 20

type ParseOptions struct {
    // MaxObjectBytes caps one object's source and, separately, the blank/comment
    // lines before it; over-long lines are discarded as they stream. 0 means
    // DefaultMaxObjectBytes, negative means unlimited. Breaches are diagnosed
    // ("rpsl/object-too-large", "rpsl/trivia-too-large") and parsing resumes.
    MaxObjectBytes int64
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
3. **Differential expansion tests vs. `bgpq4`.** For a fixed offline IRR snapshot, expand a basket of as-sets/route-sets and compare against checked-in golden expansions (hand-checked; `bgpq4` cannot read an offline snapshot, so each golden file records the equivalent `bgpq4 -j` command). An opt-in live diff against `bgpq4` itself runs when `RPSL_BGPQ4_SERVER`/`RPSL_BGPQ4_SET` are set. Any divergence is a bug in one of them — and finding `bgpq4` bugs would itself be a credibility win.
4. **Fuzzing** (`go test -fuzz`) of every parser that takes untrusted text: lexer, attribute lists, set names, range operators, the stream, and the policy parser (import, filter, peering, AS-path regexp). RPSL text from the internet is adversarial by nature; the parser must never panic, only diagnose, and the stream fuzzer also checks that no byte is lost.
5. **Fan-out / cycle property tests** with synthetic set graphs (generated cyclic and deep nestings) against a brute-force oracle, to verify results, limits and termination.
6. **Real-data regression** (opt-in, `RPSL_REALDATA`). Streams the RIPE split dumps (`scripts/fetch-ripe-dumps.sh`) and checks that the stream is lossless, raises no stream-level diagnostics, and keeps each error family under 0.1 % of objects (of policy values for `policy/*`); then expands the largest real as-sets and route-sets twice, in opposite input orders, and requires identical results.
7. **Live smoke test** (opt-in, `RPSL_LIVE=1`). Queries RADB, RIPE whois and RIPE RDAP read-only and asserts only stable facts (AS3333 originates 193.0.0.0/21). It is what caught IRRd closing the connection after one command without `!!`.

`scripts/check.sh` runs 1–5 for every module (plus gofmt, staticcheck, govulncheck and the leaf-isolation and engine-purity invariants); CI runs it with a short `FUZZTIME` on Go 1.23 and the latest stable Go.

---

## 12. Suggested build order

1. `lexer` + `ast` + lossless round-trip + the golden corpus harness. *Shippable on its own* — already strictly better than the existing library for read/edit use.
2. `types` + `object` typed decoding for the non-policy classes (`mntner`, `person`, `role`, `route`, `route6`, the set classes' *raw* members). Covers the bulk of what people query.
3. `policy` parser for `import`/`export`/`default`. The intellectually hardest, most differentiating layer.
4. RFC 4012: `mp-*`, `afi`, `except`/`refine`, `route6`.
5. `resolve` engine + in-memory `Source` + differential tests vs `bgpq4`.
6. Live/IRRd/RDAP `Source` backends.

Stop-and-ship points after 1, 2, and 5 — each is independently useful, so the project delivers value long before it's "complete."

**Status (current).** All six milestones are shipped: the streaming lexer/`ast` and lossless round-trip, the typed `object` layer (including RFC 4012 `mp-*`, `route6`, `afi`-scoped policies, `except`/`refine`), the `resolve` engine with in-memory `Source` and the bgpq4 differential, plus the three live backends in `resolve/{irrd,whois,rdap}`. See [README.md#Status](../README.md#status) for the same matrix in shipping form.

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
