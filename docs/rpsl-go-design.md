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
  auth/                # RFC 2725 authorisation model (+ RIPE's mnt-irt: consent); cryptography injected
  resolve/             # separate go-get module: pure expansion Expander + Source interface
    irrd/              #   socket-using Source over an IRRd query port
    whois/             #   socket-using Source over plain WHOIS (RIPE-DB)
    rdap/              #   RDAP registration client (registration metadata only)
    rpki/              #   RPKI-aware expansion as IRRd 4 does it (no sockets)
    nrtm4/             #   socket-using NRTMv4 mirror client: a Source kept current
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

type SetRef struct {             // a set reference, optionally scoped to one
    source string                 // registry (draft-ietf-grow-rpsl-registry-
    name   SetName                // scoped-members: "RIPE::AS-FOO")
}
// Ref returns the unscoped reference to name; NewSetRef scopes name to source
// (validated by ParseSourceName, "" giving the unscoped reference); ParseSetRef
// parses "AS-FOO" or "RIPE::AS-FOO" (whitespace around "::" is an error). It is
// opaque and canonical, as SetName is: the source is upper-cased, so every
// spelling of a reference is == and one map key. Source(), Name(), IsScoped(),
// IsZero() and String() read it; an unscoped ref leaves the choice of registry
// to the Source's precedence.
func Ref(name SetName) SetRef
func NewSetRef(source string, name SetName) (SetRef, error)
func ParseSetRef(s string) (SetRef, error)

// ParseSourceName validates and canonicalizes an IRR source name — a source:
// value, or a reference's registry: ASCII letters, digits, '-' and '_',
// upper-cased, so it is safe in an IRRd "!s" or a whois "-s" query. Case
// folding is done in place: no offset found in the upper-cased copy is ever
// used to slice the original (the v0.19.0 "ɐ" panic).
func ParseSourceName(s string) (string, error)

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
    Changed []Changed // address and date, as parsed; Raw keeps the line
    Source  string
}

// Registry holds what RIPE's templates add across classes (org:, abuse-c:,
// mnt-lower:, mnt-routes:, created:, …); embedded beside Common, so every
// attribute either profile lists has a typed home.
type Registry struct {
    Org           []string
    SponsoringOrg string
    AbuseC        types.NICHandle
    MntLower, MntDomains, MntIrt, MntRef []string
    MntRoutes             []policy.MntRoutes // a maintainer and the space it may authorise
    Created, LastModified Timestamp          // RFC 3339, as RIPE sets them
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
    Name       types.SetName
    Members    []SetMember // ASNs and nested set names (raw, unexpanded)
    MpMembers  []SetMember // mp-members: some IRRs accept it on as-sets; RFC 4012 and RIPE do not
    SrcMembers []SetMember // src-members: (draft-ietf-grow-rpsl-registry-scoped-members), opt-in profile
    MbrsByRef  []string    // mntner names enabling indirect membership
    raw        *ast.Object
}

type RouteSet struct {
    Common
    Registry
    Name       types.SetName
    Members    []SetMember // prefix-ranges, set names, or AS numbers (with ^op)
    MpMembers  []SetMember // RFC 4012 mp-members (may carry IPv6)
    SrcMembers []SetMember // src-members:, as for AsSet
    MbrsByRef  []string
    raw        *ast.Object
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

`AsSet` and `RouteSet` implement `Set` (`NamedSet` plus `SetMembers() []SetMember`,
`members:` and `mp-members:` as written, and `SetSrcMembers() []SetMember`,
`src-members:` as written — named `SetSrcMembers`, not `SrcMembers`, so the
method does not clash with the field). `object.DirectMembers(s Set)` is the one
place draft-ietf-grow-rpsl-registry-scoped-members §2.3 steps 1-2 live: every
`src-members:` member, then each `members:`/`mp-members:` member whose key —
its set name, ASN, or prefix range, registry and operator stripped — no
`src-members:` member already has. It reads one object and does no I/O; the
engine's discovery calls it instead of `SetMembers` for these two classes.
`WithSrcMembers(p Profile) Profile` returns p with `src-members:` (optional,
multi-valued) also admitted on as-set and route-set; the RIPE, IRRd and ARIN
profiles stay as their fixtures pin them until a registry deploys the
attribute.

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

`Flatten(e, af)` resolves EXCEPT and REFINE into the (peering, actions, filter)
terms a policy denotes for one address family (`Import.Terms(af)` also asks
whether the policy applies to af at all). An EXCEPT or REFINE with an afi clause
takes effect only for the families it covers; for the others the left-hand
policy stands as it is. Each level of an EXCEPT chain doubles the filters, so a
value of a few hundred bytes could denote gigabytes of terms: every term
Flatten builds is charged its filter size, and past `MaxFlattenNodes` (1<<20)
it returns `ErrFlattenTooLarge`.

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
    // GetSet fetches the set ref names. An unscoped ref is resolved by the
    // Source's precedence; a scoped ref (draft-ietf-grow-rpsl-registry-scoped-
    // members) only in that registry — any registry the Source holds, even
    // one its default list leaves out — and a registry it does not know is
    // ErrNotFound. For a scoped ref the returned set's source must be the
    // ref's.
    GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error)

    // OriginatedRoutes returns the prefixes a given AS originates,
    // from route/route6 objects. Needed because an as-set or route-set
    // member that is a bare ASN expands to that AS's routes. Never scoped:
    // a member AS's routes come from the default precedence, since a scope
    // does not cascade (§8.2).
    OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

    // MembersByRef supports the mbrs-by-ref / member-of indirect mechanism:
    // objects from the set's own source, maintained by one of its mbrs-by-ref
    // mntners, that claim member-of this set (filtered with ClaimAllowed).
    MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error)
}

// PolicySource is a Source that also serves the objects routing policy names
// outside sets: aut-nums, whose import/export/default policies a policy
// evaluator reads, and inet-rtrs, which router expressions and peerings name.
// source scopes a lookup as a SetRef does. Shaped for a peval/RtConfig-style
// evaluator, the next milestone; it has no consumer yet.
type PolicySource interface {
    Source
    AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error)
    InetRtr(ctx context.Context, name, source string) (object.InetRtr, error)
}
```

Backends shipped: an in-memory `Source` (for tests and for loading an IRRd snapshot/`.db` dump), a caching `Source`, a WHOIS `Source`, and a `Source` over an IRRd query port. RDAP serves registration data, not IRR sets, so `resolve/rdap` is a client, not a `Source`. The engine never opens a socket itself. `MemSource`, `irrd.Source`, `whois.Source`, `Cache` and `rpki.Filter` also implement `PolicySource`; a wrapper (`Cache`, `rpki.Filter`) whose inner `Source` does not returns `ErrNoPolicy`, and so does a `MemSource` built from a `Corpus` without `KeepPolicy` (§8.9), which holds only the aut-nums and inet-rtrs that claim membership of a set — a partial answer it will not pass off as a whole one.

`irrd.Source` resolves a scoped lookup — `GetSet` of `RIPE::AS-FOO`, or `AutNum`/`InetRtr` with a source — on connections of a sub-source that select only that registry (`!s` is per connection). Data can name any registry, so the Source learns the server's registries once, with IRRd's `!j-*` (every source it has, with its serial range: `RIPE:N:0-66028019`), on a connection that selects none, and keeps the list until `Close`: a registry not on it is `ErrNotFound` without a query, a sub-source or a connection, and there are only ever as many sub-sources as the server has registries. A server that refuses `!j`, or whose connection breaks on it twice in a row (a server that does not know the command may hang up), is asked for each registry instead; a refused registry's sub-source is dropped, and up to 1,024 refused names are remembered. `!j-*` lists a server's real sources, not the source aliases IRRd 4.4 may also accept in `!s` (`source_aliases`, each standing for a set of sources), so a scoped lookup of an alias is `ErrNotFound`: data names registries by their own names (an object's `source:`), and a caller should scope by them too. The list is a snapshot: a source configured on the server after it was learned is unknown until `Close`.

The engine does not take a `Source`'s answer on trust: a set whose name is not the one asked for is an error, one whose class is not its name's (`route-set: AS-EVIL`) is invalid data, treated as missing, and — for a scoped `GetSet` — one whose source is not the ref's registry fails the same way, since a `Source` that ignores scoping cannot quietly answer by precedence. Expanded under its name's rules a mismatched set would let an as-set pull in prefixes, or claims, its class does not allow. Every indirect claim is re-checked with `ClaimAllowed`.

### 8.2 Dual membership

A set's members come from **two** places and the engine must union them:

1. **Direct** — the `members:` / `mp-members:` attribute lists ASNs, prefix-ranges, and nested set names.
2. **Indirect** — other objects assert `member-of:` *this* set. Per RFC 2622 this is only honored when the set carries `mbrs-by-ref:` and the asserting object is maintained by one of the listed mntners (or `mbrs-by-ref: ANY`). Skipping the mntner check is a common correctness bug; the engine enforces it via `Source.MembersByRef` and re-checks every claim with `ClaimAllowed`.

   The claim must also come from the set's own `source:`. Maintainer names are unique only within one registry, so without this rule anyone who registers a same-named mntner in a permissive IRR (RADB) could add members to a RIPE set once several IRRs are loaded together. IRRd applies the same rule (its mbrs-by-ref index is keyed by source and set), so `RIPE-NONAUTH` does not claim into `RIPE`. An absent source matches only an absent source.

**Registry-scoped members.** draft-ietf-grow-rpsl-registry-scoped-members-00
lets an as-set or route-set name each nested set together with the registry it
lives in (`src-members: RIPE::RS-SECOND`), and a resolver must fetch it from
that registry only. Its §2.3 resolution is two steps: include every
`src-members:` member (a scoped set matched on registry and primary key, a
registry unknown to the resolver matching no set), then include each
`members:`/`mp-members:` member whose primary key is not already in
`src-members:`. The scope selects only where the referenced object is fetched:
its own nested references resolve from its own `src-members:`, or by the
default source selection — the restriction does not cascade. A scoped miss
never falls back to precedence, and a name listed under two registries in
`src-members:` (a conflict the draft forbids) falls back to `members:` for
that name, as if `src-members:` had not named it.

### 8.3 Traversal, cycles, and limits

```go
type Expander struct {
    Src          Source
    MaxDepth     int       // cap on shortest nesting distance from the top (default 32)
    MaxPrefixes  int       // cap on output prefixes, or ranges (default 1<<20)
    MaxVisited   int       // cap on distinct sets fetched per call (default 1<<17)
    MaxConjuncts int       // cap on conjuncts NormalizeFilter builds (default 1<<12)
    AFI          types.AFI // constrain to v4 or v6 (Unspecified / Any = both)
    Exclude      Exclusion // sets and AS numbers left out (bgpq4's EXCEPT)
    Peer         types.ASN // binds PeerAS and set templates for EvalFilter/NormalizeFilter; 0 = unbound
}

// ExpandAS returns the ASNs of every as-set reachable from ref, plus indirect
// aut-num members. An unscoped caller writes types.Ref(n); a scoped ref is
// §2.3.2's query parameter and does not cascade.
func (e *Expander) ExpandAS(ctx context.Context, ref types.SetRef) (ASNSet, error)

// ExpandPrefixRanges returns the prefix ranges of a route-set or as-set (routes
// of member ASes), with member range operators composed — bgpq4's le/ge form.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, ref types.SetRef) (RangeSet, error)

// ExpandPrefixes is ExpandPrefixRanges, materialized under MaxPrefixes.
func (e *Expander) ExpandPrefixes(ctx context.Context, ref types.SetRef) (PrefixSet, error)
```

(A bare AS is not a SetName or a SetRef; its prefixes come straight from `Source.OriginatedRoutes`. `ExpandRouters`, `ExpandPeerings` and `ExpandFilterSet` take a `types.SetRef` the same way; `EvalFilter` is unchanged, since a set reference inside a filter has no registry syntax and becomes an unscoped ref.)

Engine mechanics that matter:

- **Two phases.** *Discovery* walks the set graph breadth-first from the named set, fetching every reachable set once — so a set's depth is its shortest nesting distance and the result never depends on member order — together with its indirect members and, for prefix expansions, each member AS's routes (once per AS per call). *Evaluation* builds the result from that graph with no further I/O. Caching *across* calls belongs to the `Source`, because freshness policy varies.
- **Class rules.** Discovery and evaluation follow only the nestings RFC 2622 §5.1-5.2 allows: an as-set lists as-sets; a route-set lists route-sets and as-sets. A route-set listed inside an as-set is invalid data and is not followed — otherwise any nested as-set could inject prefixes that no route object backs. `ExpandAS` takes an as-set and the prefix expansions an as-set or route-set; any other class returns `ErrSetClass`.
- **Cycle detection.** as-sets reference each other, sometimes cyclically (`AS-A` includes `AS-B` includes `AS-A`). The discovery graph is keyed by `types.SetRef`, not by name, so one name reached both scoped and unscoped — or under two registries — is two nodes, fetched and counted against `MaxVisited` separately, even where precedence would pick the same copy anyway. A revisit of the same ref is skipped, not an error (matches `bgpq4` behavior). With range operators, evaluation states are (ref, operator stack) pairs, and a stack is identified by what it does — for each family, the lower bound it maps each inner lower bound to (or deletion) and the upper bound the outermost operator sets — so `^+^+` and `^+` are one state. The states are finite (registries are finite too): every reachable one is walked once, and cycles through operators (`RS-A` lists `RS-B^+`, `RS-B` lists `RS-A`) terminate at the RFC's least fixpoint rather than being refused. `MaxVisited` bounds the states walked.
- **Range operators on members.** `RS-FOO^+` applies to each range of RS-FOO and `AS1^24` to each route AS1 originates, composing along the path with `types.RangeOperator.Apply` (RFC 2622 §5.2).
- **Fan-out guards (three of them).** Real as-sets (e.g. some tier-1 customer cones) expand to *hundreds of thousands* of prefixes. `MaxPrefixes` bounds distinct output, `MaxVisited` (default `1<<17` = 131,072) bounds the sets fetched, and `MaxDepth` (default 32) bounds the shortest nesting distance. Each returns a `*SetTooLargeError{Name, Limit, Max, Count}` (`Name` a `types.SetRef`) naming the cap — the caller decides whether to chunk or reject; none truncates a result silently.
- **Missing and unexpandable sets.** A missing top-level set is an error wrapping `ErrNotFound`; missing nested sets expand to nothing, as in bgpq4, and are listed by the result's `Missing()`, which returns `[]types.SetRef`. A registry a scoped reference names that the `Source` does not know is missing the same way — never a fallback to another registry. An existing set with no members is empty, not missing, in every backend: IRRd answers `!i` alike for both, so the irrd `Source` checks with `!m`. `AS-ANY`/`RS-ANY` denote the whole IRR (in any registry) and return `AnySetError`, which keeps a `types.SetName`.
- **Indirect membership.** Per RFC 2622 §5.1-5.2, an as-set's indirect members are aut-nums and a route-set's are routes; each claim must pass `ClaimAllowed` (member-of + mbrs-by-ref mntner check), which the engine re-applies to whatever the `Source` returns.
- **AFI constraint.** A v4 expansion must drop `route6`-only members and `mp-members` IPv6 entries, and vice versa. The `afi` dictionary from RFC 4012 makes this explicit; `any` means both. A *SAFI* has no role here: no RPSL set member carries one and there is no multicast route class, so `Expander.AFI` is an `AFI`, and the sub-family matters only where RFC 4012 puts it — in `policy.Import`/`Export`/`Default.AppliesTo`.
- **The other set classes.** `ExpandRouters` walks an `rtr-set` to routers (`types.RouterID`), `ExpandPeerings` a `peering-set` to the peerings it denotes with nested references replaced, and `ExpandFilterSet`/`EvalFilter` a `filter-set`'s expression to prefix ranges. Discovery is the same breadth-first traversal for all of them; only what counts as a nested name, and which indirect claims are honored, differs by class.
- **Filters are only partly enumerable.** `EvalFilter` evaluates `ANY`, prefix lists, route-set/as-set/filter-set references, AS numbers and AS expressions, `OR`, and `AND` (the intersection of two range sets, via `types.PrefixRange.Intersect`, testing each range only against the ranges at its prefix's ancestors and descendants). `NOT`, `PeerAS`, community tests, AS-path regexps and per-peer templates have no finite prefix denotation, and return a `*NotEnumerableError` naming the term instead of a quietly smaller answer. Within one call each set is fetched and expanded once, `MaxVisited` bounds the call as a whole, and a cycle of filter-sets is solved by iteration to the least fixpoint, as a cycle of route-sets is.
  `Expander.Peer` binds `PeerAS` and a set template (`AS1:AS-CUST:PeerAS`) to one AS, in a filter, an AS expression or an AS-path regexp, for both `EvalFilter` and `NormalizeFilter`; zero leaves them unbound, so `EvalFilter` still refuses a `PeerAS` term with `*NotEnumerableError`. `NormalizeFilter` goes further: it evaluates a filter into disjunctive normal form rather than refusing what `EvalFilter` cannot. What can be enumerated (prefix lists, set and AS references, a bound `PeerAS` or template) folds into prefix ranges through the same evaluation as `EvalFilter`; AS-path regexps and community tests stay symbolic and are never evaluated (§13), kept as `PathMatch`/`CommunityMatch` on the `Conjunct` that carries them, each optionally `Negated`. NOT is pushed to the leaves by De Morgan, so an enumerable NOT becomes a `Conjunct.NotPrefixes` and a symbolic one sets `Negated`; only an OR mixing symbolic literals multiplies conjuncts, and `MaxConjuncts` (default 4,096) bounds that growth the same way the other three limits bound theirs, returning `*SetTooLargeError` — it caps both the conjuncts of any disjunction and the tests (`Paths` and `Communities`) of any conjunct. A filter-set holding a symbolic term is inlined once per polarity however often the filter names it, a test repeated in a conjunct is kept once, and every normalization step is charged against `MaxVisited`, so a filter-set named four times at each of ten levels is one conjunct of one test, not 4^10 copies. Whenever `EvalFilter(f)` succeeds, `NormalizeFilter(f)` has at most one conjunct (none when the answer is empty) with no `NotPrefixes`, `Paths` or `Communities`, and the same `Prefixes` `EvalFilter` returned — the two never disagree on what they can both decide. `Expander.Exclude` applies to `NormalizeFilter` only where it narrows the answer — positive prefix literals — never under a NOT, where a literal is evaluated with `Exclude` cleared so an excluded AS or set cannot drop out of a deny side and become accepted, and never inside an AS-path regexp, in either polarity: a set can reject even inside a positive regexp (`<[^AS-A]>`), so `PathMatch.Sets` is always the full expansion.
- **Exclusion.** `Expander.Exclude` names sets and AS numbers an expansion leaves out, as bgpq4's `EXCEPT` does: an excluded set is never followed, fetched or reported missing — discovery skips it, so it costs nothing against `MaxVisited` — and an excluded AS contributes nothing, as a member, an indirect aut-num member or a reference inside a filter-set. The set an Expand call names is expanded as asked, and so are the terms of a filter passed to `EvalFilter`; `NormalizeFilter` applies it to positive prefix literals only (above), and `resolve/peval` to clause filters only, never to peering or router matching (§8.10). It applies inside route-sets as well, where bgpq4's stoplist does not reach (bgpq4 has the server expand route-sets).
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

Framing is also what makes pipelining safe. With `irrd.Source.Pipeline` set, concurrent queries share a persistent connection: each writes its command under the connection's lock, in the order it is queued, and one reader hands the answers out in that order — IRRd answers commands in the order it reads them. Only a transport or framing error breaks the stream (the queries waiting on it are retried once on a fresh connection); a `D` or `F` answer belongs to its query alone, and a caller that gives up only stops waiting, its answer still read. This is how bgpq4 queries an IRRd, and what makes a set of tens of thousands of members a matter of seconds rather than of a round trip per query. `rpslq` (`resolve/cmd/rpslq`) is the engine behind bgpq4's command line: every vendor and kind of list bgpq4 writes, its aggregation (a port of bgpq4's own radix tree, `resolve/internal/filtergen`), and `EXCEPT` as `Expander.Exclude`. `TestRpslqMatchesBgpq4` and its siblings hold its output to the bgpq4 binary's byte for byte, and its refusals to bgpq4's.

A registry caps how fast it answers any one client — RADB at about 1,200 queries a second, however they are sent — so an as-set of 25,000 ASes costs the engine's expansion some twenty seconds of route queries. IRRd 4's `!a` expands an as-set on the server in one query, and `irrd.Source.ASSetPrefixes` sends it; its answer is the server's, under the server's rules, which is why it is not part of `resolve.Source` and why `rpslq` uses it only when asked (`--server-expand`).

---

### 8.6 Authorisation (`auth`)

Who may change an object is the other half of what keeps an IRR honest: a set
expands only to what its members' maintainers registered, and a registry
accepts a route only from someone the address space delegated to. RFC 2725
gives the model, and the registries depart from it. The RIPE Database asks,
on creation, the parent of every hierarchical object — the covering address
space (`mnt-routes:`, then `mnt-lower:` for strictly less specific space, then
`mnt-by:`), the as-block of an aut-num, the object a set's hierarchical name
names — and the consent of any irt or `mnt-ref:` holder a new reference names,
but not the origin AS of a route. IRRd asks only the `mnt-by:` of a route's
address space and of a set's aut-num, and both versions' maintainers on a
change. Each is a `Rules` value — `auth.RIPE`, `auth.IRRd` — whose `Authorise`
takes an update and a credential and returns a `Decision` with its reasons.

The lookups Authorise needs are injected as a `Database` — the object stored
under a key, the objects covering an address range, the as-blocks holding an
AS — as `resolve.Source` injects the engine's, with `MemDatabase` for tests
and dumps; the cryptography is injected as a `Verifier`. `RouteCreation` stays
as RFC 2725 §9.9's route check, the one that also asks the origin AS.

### 8.7 RPKI-aware expansion (`resolve/rpki`)

IRRd 4 is RPKI-aware by default (`irrd/rpki`): it imports the VRPs a
relying-party validator exports, validates every route and route6 object with
RFC 6811 origin validation, and **suppresses** the invalid ones — they vanish
from query answers, database exports and NRTM, so an as-set's expansion over
RADB never contains them. It also serves each ROA as a **pseudo route object**
of the source `RPKI` (prefix, origin, `max-length:`), and RADB lists `RPKI`
among its default sources, so bgpq4 against RADB gets those routes too
(AS13335: 258 of 4,615 `!g` prefixes exist only as ROAs). A registry's own dump
(RIPE, APNIC, ARIN, AFRINIC, LACNIC, and the mirrors RADB passes on unfiltered),
whois.ripe.net, or an older IRRd shows neither effect. Only RADB's and NTT's
exports come filtered.

The rule, as IRRd's `validate_route` states it: a route is **valid** when some
VRP covering its prefix (the same prefix or less specific, same family) names
its origin, which is not AS0, with a `maxLength` of at least its length;
**invalid** when VRPs cover it and none matches; **not_found** when none covers
it. An AS0 VRP covers but never matches (RFC 6483 §4).

`resolve/rpki` reproduces both effects over any `Source`, without sockets:

- `VRPs` indexes the payloads (exact prefix → grants, with a bitmask of the
  lengths present, so `Validate` looks up only lengths that have VRPs).
  `ReadJSON` reads the export rpki-client, Routinator and IRRd's
  `rpki.roa_source` use, strictly as IRRd does — one bad record fails the read,
  keys are exact — and `ApplySLURM` applies an RFC 8416 file as IRRd's
  importer does (filters drop VRPs, never assertions; assertions get the TA
  `SLURM file`).
- `Filter` wraps a `Source`: `OriginatedRoutes` drops the prefixes invalid for
  the AS asked about, `MembersByRef` the invalid route claimants. Sets and
  their listed members pass through — IRRd suppresses route objects, not the
  prefixes a route-set names. A route's state depends only on its prefix and
  origin, so filtering prefixes equals IRRd's per-object suppression when no
  source is `rpki_excluded` (IRRd's default); per-source exclusion is not
  modelled, since `OriginatedRoutes` does not say which registry a prefix
  came from.
- `WriteRPSL` writes the pseudo objects byte for byte as IRRd renders them, as
  a dump for `DumpLoader`: the registry `RPKI` then takes part in source
  precedence, `SourceOf` and rpslq's `-S` and `SOURCE::` like any other.

Two limits are deliberate. Over an IRRd that is not RPKI-aware, `irrd.Source`
receives a route-set's indirect route members folded into `!i` as plain
prefixes, which `Filter` cannot tell from listed ones (an RPKI-aware IRRd
suppresses them itself). And `Filter` hides the pseudo route of an AS0 VRP,
which IRRd marks valid; it matters only to a set that lists AS0. Freshness is
the caller's: the VRPs are a snapshot passed in, as a `Source`'s cache policy
is its own.

rpslq's `--rpki` (and `--slurm`) wraps every backend in `Filter` and, with
`--dump`, loads the pseudo objects; against a live server it can only leave out
more than the server's own VRPs did. `--server-expand` refuses it: `!a` answers
prefixes without origins.

### 8.8 Mirroring over NRTMv4 (`resolve/nrtm4`)

A dump is a day old the moment it is written, and most of what separates an
expansion over dumps from one over RADB is that day (AS-DECIX: a few hundred
of 827,000 prefixes over four days, a few dozen over one). NRTMv4
(draft-ietf-grow-nrtm-v4, implemented by IRRd 4 and the RIPE Database) keeps a
mirror current: a signed Update Notification File lists a Snapshot File and a
day of Delta Files, one a minute, fetched over HTTPS.

`nrtm4.Client` mirrors one database. `Sync` polls once — loading the snapshot
the first time, after a new session, when the deltas no longer reach back to
the version held, or after three Syncs in a row failed on a delta — and
applies the deltas after it; `Run` polls every minute or more, with backoff.
Every file is verified before any of it is used:

- the notification file is a JWS; it must be ES256 and verify with the
  current key, or with the key a valid file announced in `next_signing_key`,
  after which the old key is never used again (§9.6). Nothing else — `none`, a
  MAC, `crit` — is accepted. The standard library does the cryptography;
- each snapshot and delta is hashed (SHA-256, as served) against the
  notification file, and its header checked against the session and version
  it should have. A URL must stay on the notification file's scheme and host —
  so must every redirect, which is not signed, with the caller's `http.Client`
  too — and a file is capped after decompression;
- a hash the server gave for a file in one notification file may not change in
  a later one of the same session ("rewriting history"); a URL may;
- deltas must lead one version at a time from the version held: a delta is
  parsed and validated whole before any of it is applied, and after a refused
  one nothing newer is. A snapshot streams into a store that replaces the
  mirror only when its hash and every record check out;
- an object whose `source:` is not the database's, or that has no primary
  key, is left out with a `nrtm4/discarded` diagnostic, and the file goes on
  (§9.2). A delete names class and primary key, matched in canonical form
  (`2001:DB8::/32AS1` is `2001:db8::/32AS1`).

The client skips the classes the engine has no use for unparsed, holds the
rest in a `resolve.Corpus` (§8.9), and publishes each version it reaches as a
new immutable `MemSource`: an expansion takes one `Source()` and sees one
version whole while the mirror moves on. Mirroring RIPE from scratch — the
403 MB snapshot and a day of deltas — takes about 80 seconds and peaks under
1 GB. `CopyTo` merges a mirror's version into a caller's `Corpus`, to combine
mirrors — RIPE and RIPE-NONAUTH — or a mirror with dumps and RPKI pseudo
routes under one precedence.

A signature proves who wrote a notification file, not when, so an old but
validly signed file could be replayed to roll the mirror back. A new session
whose file is older than the one the mirror came from is always refused; a
file older than `Client.MaxAge` is refused when that is set, as IRRd refuses
one over 24 hours old. By default it is not: a stale file is reported
(`Status.Stale`) and used, as the draft allows — the one choice that differs
from IRRd. The state lives in memory: a restart loads the snapshot again,
`Status.CurrentKey` is the one thing to persist, so a key rotated while the
program was down still verifies, and `MaxAge` is what keeps a restart from
accepting a replayed old file.

### 8.9 What a loaded IRR costs (`Corpus`)

A decoded object is expensive: its lossless text, one 152-byte attribute per
line (RIPE adds seven lines of `remarks:` to every object it dumps or
mirrors), a position table per attribute, and a typed struct — 4.7 KB for a
RIPE route, 18.6 KB for an aut-num with its policies parsed. Holding every
object a registry's dumps or mirror hold cost 3.7 GB for RIPE, of which the
`MemSource` the engine expands against needed 380 MB: it keeps a route as a
prefix in a map by origin, and only sets and membership claimants whole.

`resolve.Corpus` keeps objects in that form from the start. Sets, and the
objects that claim membership of one (`member-of:`), are kept whole — `GetSet`
and `MembersByRef` return them; every other route and route6 is kept as its
prefix, origin and source, a comparable map key of about 94 bytes; aut-nums
and inet-rtrs that claim nothing, and every other class, are not kept. An
object is identified by class, canonical primary key and source, so a later
one replaces an earlier one — an NRTM update, or a route gaining or losing
`member-of:` and moving between the two forms — and `Delete` takes an NRTM
delete's class and key. A source name is interned: a substring of an
object's text would keep the text alive.

`DumpLoader` and `nrtm4.Client` hold a `Corpus`; `Corpus.Source` builds
through the same code as `NewMemSource`, and a property test over the random
IRRs holds every answer — each set, each AS's routes in each family, each
set's claimants, every expansion — to `NewMemSource` over the same objects,
as an opt-in test does for the largest real sets of RIPE and ARIN. RIPE's
dumps now load into 460 MB of heap instead of 3.7 GB. The one change in
meaning: two objects with one identity in one source — which a registry
cannot have, its primary keys being unique — are one object, the later.

`Corpus.KeepPolicy`, set before the first `Put`, adds aut-nums and inet-rtrs to
what a `Corpus` keeps, for `PolicySource`. They are kept as text, source
interned, under the same primary key `Delete` and NRTM replacement already use
— never decoded in memory. Measured on RIPE's 39,918 aut-nums: 95 MB as text
against 707 MB decoded (18.2 KB per `object.AutNum`, more than the whole
`Corpus` without them). A `MemSource` built from a `Corpus` decodes a
text-kept entry on every `AutNum`/`InetRtr` call — `rpsl.ParseObject` then
`object.Decode`, its diagnostics dropped since the loader already reported
them — so the `MemSource` stays immutable and safe to share; wrap it in
`Cache` for repeated lookups. An aut-num that claims `member-of:` is already
kept decoded (it answers `MembersByRef` directly) and needs no re-decoding.
Without `KeepPolicy` a `MemSource` built from the `Corpus` answers `AutNum` and
`InetRtr` with `ErrNoPolicy`: the claimants it holds are not the registry's
aut-nums, and serving them alone would be a partial answer. `NewMemSource`
serves every aut-num and inet-rtr it is given.

### 8.10 Policy evaluation (`resolve/peval`)

`resolve/peval` is the consumer §8's engine was always missing: what
IRRToolSet's `RtConfig` and `peval` compute, on this engine. A `Session` is
one BGP session seen from `Local` — `Local`/`Peer` AS numbers, optional
`LocalRtr`/`PeerRtr` addresses, and the `types.AddrFamily` that selects which
mp-* terms apply and trims prefixes to one family. An `Evaluator` reads
`Local`'s aut-num through a `resolve.PolicySource` and evaluates one of its
policy attributes — `Import`, `Export`, `ImportVia`, `ExportVia`, `Default` —
for that session; `Filter` runs the same normalization `rpslconf -e` exposes,
for a bare filter. All I/O goes through `Src`; an `Evaluator` holds no
per-call state, so one value serves concurrent calls, and wrapping `Src` in
`resolve.Cache` shares lookups across them.

A `Policy` is its `Clause`s in specification order (RFC 2622 §6.1): each
attribute's terms, in document order, `Flatten`ed for the session's address
family, filtered to the ones whose peering matches, and normalized (§8.3)
with `PeerAS` bound to the session's peer. A route takes the first clause it
matches; one matching none is refused (import) or not announced (export) —
the same rule a router's route-map applies.

**`Undecided` never guesses.** A term whose peering names a router the
session does not give (`LocalRtr`/`PeerRtr` unset but the peering has an
`at`/router clause), a peering regexp, or a protocol other than BGP4,
contributes no `Clause`; it is reported in `Policy.Undecided` with a `Why`
string instead. Approximating a router the caller did not name — matching
regardless, or refusing the whole policy — would be a silent wrong answer
either way, so the evaluator reports the uncertainty and moves on. An AS
mismatch, by contrast, is always decidable: it is simply no match, whatever
the routers say.

**Matching.** An `ASNum` peering is an equality test against `Session.Peer`;
an `ASSetRef`/`ASSetTemplate` expands the set (once per call, memoized) and
tests membership; `AS-ANY` always matches; AS expressions combine with
AND/OR/EXCEPT as booleans. A router expression is matched the same way
against whichever of `LocalRtr`/`PeerRtr` the peering's side names: a
`RouterName` is resolved via `Src.InetRtr` and compared against its
`ifaddr:`/`interface:` addresses (not found: no match, listed in
`MissingRouters()`), and an `rtr-set` is expanded and each member checked the
same way. A `PeeringSetRef` matches if any of its (already-replaced) nested
peerings does. `Expander.Exclude` plays no part in matching: as-sets,
peering-sets and rtr-sets are expanded for it with `Exclude` cleared, since an
excluded set on the right of an EXCEPT (`AS-PEERS EXCEPT AS-BAD`) would
otherwise widen the peering. It narrows the clause filters' prefix literals
only, as `NormalizeFilter` applies it. `import-via:`/`export-via:` match the *via* peering — the
route-server session itself — against the session, and carry the peering
beyond it in `Clause.Remote`; `PeerAS` binds to `Remote`'s AS only when it
names exactly one AS number, otherwise a filter using it is `Undecided`
("PeerAS beyond a via peering names no single AS").

**`Flatten`'s approximation carries through.** `peval` resolves EXCEPT and
REFINE with `policy.Flatten`, which is exact except for one documented
simplification: REFINE's peering intersection (RFC 2622 §6.6) is approximated
by comparing peerings' rendered text, or treating `AS-ANY` as meeting
anything, rather than expanding both sides through a registry — `Flatten`
has no `Source` to expand with (§1, principle 4: the resolver is an
interface, not a hardcoded transport, and `policy` sits below `resolve` in
the import order). `peval` inherits that approximation as written; nothing
in this package widens or narrows it.

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

// Validate checks an object against a class/attribute profile (RIPE, IRRd, ARIN, RFCStrict).
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

- **RIPE deviations.** RIPE's RPSL diverged from RFC 2622 over 25 years (extra attributes, dropped features, `auth:` formats, `abuse-c:`). The class/attribute dictionary is data-driven (a loadable table), with four built-in profiles. The RIPE profile is RIPE's own templates (`whois -t <class>`, kept in `object/testdata/ripe-templates` and checked by `TestRIPEProfileMatchesTemplates`, and against whois.ripe.net by the live test). The IRRd profile is IRRd 4's class tables — what RADB and the IRRs it mirrors accept — read from IRRd's `rpsl_objects.py` (kept in `object/testdata/irrd` at a release tag, checked by `TestIRRdProfileMatchesSource`, and against IRRd's latest release by a live test); it differs from RIPE's where the registries do (`mnt-by:` optional on aut-num, `rev-srv:`, `geoidx:`, `changed:` still allowed). The ARIN profile is ARIN's IRR as it serves its objects: ARIN's five classes (route, route6, aut-num, as-set, route-set), each IRRd's table, plus the `created:` and `last-modified:` ARIN generates. ARIN documents its templates only in prose and its validator is closed, so the tables are IRRd's, derived from them in code (`TestARINProfileIsIRRdPlusGenerated`); ARIN's legacy objects, migrated in 2020, keep `changed:` and `notify:`, which IRRd's tables allow. The RFC-strict profile follows the tables of RFC 2622, 2725, 2726 and 4012.
- **`changed:` / legacy attributes** that RFC strict mode rejects but every historical dump contains.
- **Empty and `+`-only continuation lines** inside `remarks:`/`descr:` (see §3) — the classic round-trip breaker.
- **Lists continued across lines without commas** (`members: AS1`, then a line `AS2`; hundreds of RADB sets). RFC 2622 separates list items with commas only, but IRRd joins a value's lines with commas, so to IRRd — and to bgpq4 — those are separate members. `ast.Attribute.List` splits at line breaks too, with a Warning (`object/list-line-break`); reading the value as one invalid member silently shrinks the set.
- **`mbrs-by-ref: ANY`** — indirect membership open to any maintainer; easy to either over- or under-apply.
- **Mixed-case set names and ASNs** (`as-FOO`, `As65001`) — canonicalize for comparison, preserve for output.
- **`as-set` members that are `route-set`-shaped** and other class-confusion in messy registries — validate member class against context, emit a warning, don't crash.
- **32-bit ASNs in dot notation** (`AS1.10`) still seen in older objects.
- **Zero-padded IPv4 octets** (`064.006.160.000/19`, in ARIN's IRR). Go's `netip` rejects them, since C would read a leading zero as octal; RPSL addresses are dotted decimal and IRRd reads them so. `types.ParseAddr`/`ParsePrefix` accept them as decimal everywhere an RPSL value holds an address, with a Warning (`object/<class>-leading-zeros`, `policy/leading-zeros`).
- **Abbreviated IPv4 prefixes** (`191.243.44/22`, in RADB route-sets). IRRd reads them with the missing octets zero (Python's IPy does), so `types.ParsePrefix` does too, with a Warning (`object/<class>-abbreviated-prefix`, `policy/abbreviated-prefix`). Only prefixes: a short bare address is ambiguous (`inet_aton` reads `10.1` as `10.0.0.1`, IPy as `10.1.0.0`), so it stays an error.
- **Route-set members without a length** (`206.197.238.0`, in ARIN's and RADB's route-sets). IRRd stores such a member as the host prefix (`!i` answers `206.197.238.0/32`) and bgpq4 reads it so too, so `object.ParseSetMember` does, with a Warning (`object/<class>-members-no-length`). Only set members: `types.ParsePrefix` still requires a length, and so does a policy prefix list (RFC 2622 §5.4 asks for an address-prefix, and no reference tool reads policies).
- **AS-path regexps with nested braces** `{m,n}` repetition vs. the `{...}` prefix-list braces — the lexer must disambiguate by context (inside `<...>` it's a regexp).
- **Same-named sets in several registries.** Ambiguity among same-named sets in `members:` with no scope is undefined, as it always was; `src-members:` (draft-ietf-grow-rpsl-registry-scoped-members) resolves it where written, naming the registry each nested set comes from. Neither bgpq4 nor IRRd implements the draft, so on data carrying `src-members:` the engine's answer differs from theirs by design — pinned as a divergence in `resolve/testdata/bgpq4/divergences.md`, since no registry deploys the attribute yet.

---

## 11. Testing strategy

The correctness bar is "matches the tools operators already trust," so testing is differential and corpus-driven, and the suite is judged by whether it catches bugs: each bug the reviews found was put back in, one at a time, and a test had to fail.

1. **Golden round-trip corpus.** A directory of real objects from RIPE/RADB/ARIN; assert `Parse → String` is byte-identical. This guards the lossless property and catches lexer regressions.
2. **Policy tests from the RFCs.** Table tests for the grammar's forms, and every routing-policy example in RFC 2622, 2650 and 4012 kept verbatim in `policy/testdata/rfc-examples.txt`: each must parse clean, except the one the parser rejects on purpose (RFC 2622's `NOT` in a peering).
3. **A model of the engine.** Random IRRs — as-sets and route-sets in two sources, range operators on every kind of member, indirect members honored and rejected, cycles, missing and invalid members, `AS-ANY` — are expanded by the engine and by a brute-force oracle that evaluates RFC 2622 straight from the generator's model, never from parsed text. They must agree on AS numbers, prefixes of each family, `Missing()`, and on `MaxDepth`/`MaxPrefixes` holding exactly at the true depth and size. The same IRRs are served by `resolve/internal/irrtest`, an in-process server that answers the IRRd and whois protocols as IRRd does, so `irrd.Source`, `whois.Source` and `MemSource` are held to the same oracle. With random ROAs added, the oracle also applies RFC 6811 from the model: `rpki.Filter` over `MemSource` (with and without `WriteRPSL`'s pseudo objects), the backends against `irrtest` in IRRd's RPKI-aware mode (its own port of IRRd's validator and pseudo-object rendering), and `Filter` over a server that is not RPKI-aware must all agree with it. The NRTMv4 client is held to `resolve/internal/nrtmtest`, an independent server that follows the draft: random histories of changes, snapshots, expiring deltas and new sessions, with clients joining late, after each of which the mirror must equal the server's database object for object and in every expansion; and each way a server can misbehave — a corrupt or rewritten file, a key it was never given, a gap in the deltas, an older notification file — must leave the mirror where it was. **The filter model** (`TestModelNormalizeFilter`) checks `NormalizeFilter` the same way, route by route: the model decides whether a random filter (NOT/AND/OR, prefix lists, AS numbers, route-sets, as-sets and filter-sets, range operators, regexps with sets, classes and `~*`, communities, `PeerAS`, set templates such as `AS1:AS-CUST:PeerAS`) accepts a sampled route, matching its regexps with its own Go translation, and `routemodel.Match` (`resolve/internal/routemodel`, a brute-force RFC matcher) must find that `NormalizeFilter`'s normal form, and its text read back, accept exactly the same routes. Its filters name no set that reaches `AS-ANY`, and it runs over `MemSource` only. Whenever `EvalFilter` succeeds it must equal the normal form's one pure conjunct (or none), `MaxConjuncts` (`TestModelMaxConjuncts`) holds at exactly the true count, and with a random `Exclude` (`TestModelNormalizeExclude`) every route the normal form accepts is one the model accepts without it. The model's translation and `routemodel` are the only code that matches an AS-path regexp against a concrete path, and both are test-only. **The policy model** (`TestModelPolicy`, `TestModelPolicyBackends`) does the same for `resolve/peval`: random policies of one of four kinds, drawn per aut-num — `import:`, `export:`, `import-via:` or `default:`, each with its mp- form (EXCEPT/REFINE, lists, attributes with and without afi clauses, peering-sets, AS expressions, router addresses, inet-rtr names, rtr-sets, protocols, set templates) — are evaluated by `peval.Evaluator`'s `Import`, `Export`, `ImportVia` or `Default` and by an oracle that applies RFC 2622 §6 per route directly from the generator's model — first term whose peering and filter match, its actions — without `Flatten`, marking a term Undecided exactly when a needed router is not given. For `import-via:` a term covers the session when its via peering (a route server) does, and its filter binds `PeerAS` to the remote peering's AS when that is one AS number, the term being Undecided when its filter names the peer and the remote peering does not; for `default:` the oracle gives the attributes that cover the session, their actions, and route by route what each `networks` filter accepts. Checked over `MemSource`, `Corpus` with `KeepPolicy`, and `irrd`/`whois` against `irrtest`, and with a random `Exclude` (`TestModelPolicyExclude`, over `MemSource`) the clauses that cover a session are unchanged and what peval accepts — for a default, what its `networks` filter accepts — is a subset of the model's. `export-via:` is covered by table tests in `resolve/peval`, not by the model.
4. **Differential expansion vs. `bgpq4`.** A real `bgpq4` binary queries `irrtest` serving the same objects the engine expands (bgpq4 recurses through as-sets itself with `-L`; route-sets it asks the server to resolve with `!i…,1`, which `irrtest` implements as IRRd does). Random IRRs must expand identically, AS numbers and both families' prefixes; the golden expansions of the snapshot in `resolve/testdata` are bgpq4's own output, re-checked whenever bgpq4 is installed (CI installs it). Where the two knowingly differ — bgpq4 drops the single-length `^n` form (a bgpq4 bug), neither IRRd nor bgpq4 applies range operators on set and AS members, bgpq4 follows route-sets listed in as-sets — the difference is pinned in `resolve/testdata/bgpq4/divergences.md` and a test, so a change on either side fails. `rpslq` is held to the binary the same way, over every vendor, kind of list and shape (`-A`, `-R`, `-r`, `-s`, `-W`, `-w`, …) and `EXCEPT`, with its own divergences pinned alongside. An opt-in run (`RPSL_REALDATA`) does the same for the largest and a random sample of real RIPE sets. `rpslq --dump --rpki` is held to bgpq4 against an RPKI-aware `irrtest` holding the same objects and ROAs, with bgpq4 recursing itself and letting the server expand, with the pseudo source selected and not. An older opt-in diff against bgpq4 on a live IRR runs when `RPSL_BGPQ4_SERVER`/`RPSL_BGPQ4_SET` are set. **`TestPevalMatchesIRRToolSet`** does the same for `resolve/peval`'s underlying `NormalizeFilter`, against IRRToolSet 5.1.3's `peval` when it is on `PATH` (the Homebrew bottle works: the test gives `peval` its server through `IRR_HOST`/`IRR_PORT`/`IRR_SOURCES`, since the arm64 build ignores its command-line options) — but only on the filters IRRToolSet gets right: prefix lists, bare AS numbers, AND, OR and NOT over prefix lists, all IPv4. IRRToolSet's own bugs (substituting `0.0.0.0/0` for an unresolvable set member, dropping NOT over an AS-derived term, enumerating IPv6 ranges without end, and others) are pinned, each with the input that shows it, in `resolve/testdata/rtconfig/divergences.md`, numbered D1–D10 from the design spec's spike; the filter model (item 3) is the oracle for everything outside that narrow overlap.
5. **Fuzzing** (`go test -fuzz`) of every parser that takes untrusted text — lexer, attribute lists, set names, set references (`FuzzParseSetRef`: what it accepts, `String()` parses back to an equal ref, and its source matches `[A-Z0-9_-]+`), range operators, prefix ranges, the stream, decoding, editing, src-members items (`FuzzParseSrcMember`: an accepted member's `Ref()` round-trips), the policy parser (import, filter, peering, AS-path regexp, and `FuzzParseMPFilter` for the mp-filter/afi-prefix form), what the network backends read from a server (the IRRd frame reader, member list and `!j-*` registry list — `FuzzParseRegistries`: only canonical names of listed lines, never a "Database unknown" one — the whois response scanner), the NRTMv4 notification file and delta reader (what is accepted holds the §6.3 rules), the VRP export and SLURM readers (what they accept is well-formed and its pseudo objects load back one per VRP; a SLURM file only drops VRPs it may and adds those it asserts), `FuzzNormalizeFilter` (no panic, `MaxConjuncts` holds, and `String()` parses back to a filter the route model says matches the same sampled routes), and rpslq's port of bgpq4's aggregation (any prefix set, aggregated and refined, without a panic — bgpq4 aborts on an "unreachable point" — and aggregation losing and adding nothing) — for properties, not only for panics:
   - every token's span and segments point at its bytes, and its kind follows the line rules the stream shares;
   - the stream is lossless, splits objects where the lexer sees them end, yields each object exactly as `ParseObject` reads its text (positions shifted), resumes after a break, and under caps drops only whole, diagnosed objects;
   - `Append`/`Set` produce text that parses back to exactly the edit, other attributes' bytes untouched;
   - `Decode` and `Validate` keep diagnostics inside the object, and a clean object decodes the same after changes RPSL gives no meaning to (`+` lines, name case, trailing spaces, CRLF);
   - policy diagnostics stay in the value and under the cap, the AST under the nesting cap, and keyword case or extra whitespace change nothing.
6. **Engine property tests** with synthetic set graphs (cyclic and deep nestings, operator cycles) against brute-force oracles, to verify results, limits and termination, and an oracle for `RangeOperator.Apply` against the per-prefix meaning of RFC 2622 §2.
7. **Contracts.** Every attribute a validation profile lists lands in its own field of the typed struct (`TestEveryAttributeLandsInItsOwnField`), an attribute decodes to the same type in every class that has it (`TestAttributeTypesAgreeAcrossClasses`), and every diagnostic rule the library emits is in `docs/diagnostics.md` with its severity, and every rule listed there is emitted (`TestDiagnosticRulesAreDocumented`).
8. **Real-data regression** (opt-in, `RPSL_REALDATA`). Streams the public dumps of sixteen registries (`scripts/fetch-irr-dumps.sh`: every split class of RIPE and APNIC; ARIN, AFRINIC, LACNIC and RADB; and the ten IRRs RADB mirrors, such as NTTCOM, ALTDB and JPIRR; about 13.3 million objects) and checks that the stream is lossless, raises no stream-level diagnostics, decodes every route and route6 to a valid prefix, and puts Errors of any one family on at most 0.1 % of objects (at least 3 tolerated). RIPE's dumps are also validated against the RIPE profile, RADB's and its mirrors' against the IRRd profile, and ARIN's against the ARIN profile — each against the software that registry runs; the other registries run their own. What a registry's dump does to its data (RIPE removes some `auth:` lines, ARIN ends with a line reading `EOF`) is listed per registry with its reason, and a problem in a registry's own data too frequent for the error limit (person names where a NIC handle belongs, in RADB and its mirrors) is declared the same way, counted by cause rather than tolerated in bulk, and a registry whose data misuses RPSL more often than the limit allows (TC's aut-nums) raises that one family's limit, with its reason. For RIPE and APNIC it then expands the largest real as-sets and route-sets twice, in opposite input orders, and requires identical results.
9. **Live smoke test** (opt-in, `RPSL_LIVE=1`). Queries RADB (over both the IRRd protocol and whois), RIPE whois and RIPE RDAP read-only and asserts only stable facts (AS3333 originates 193.0.0.0/21; a made-up set is not found). It caught IRRd closing the connection after one command without `!!`, and IRRd's whois parser needing every flag before `-i`. `TestRIPETemplatesAreCurrent` (in `object`, same switch) compares the RIPE template fixtures with whois.ripe.net, so a template change there fails a test here. The RPKI checks run on the same switches: `TestRealDataRPKI` validates every registry's routes with the VRPs NTT exports for IRRd — RADB's and NTT's exports, filtered by their RPKI-aware IRRds, must be nearly clean (at most 1 %, for ROAs issued since) — and `TestLiveRPKIAgreesWithRADB` samples BELL's unfiltered routes and requires RADB to hide those `Validate` finds invalid and serve the valid ones; `TestLivePseudoObjectIsCurrent` holds `WriteRPSL` to RADB's rendering. `TestLiveRIPE` (in `resolve/nrtm4`, same switch) verifies the RIPE Database's NRTMv4 notification file with the key RIPE publishes and parses its newest delta; `RPSL_LIVE_NRTM=1` mirrors the whole RIPE Database.

10. **Benchmarks** of every hot path — the lexer, the stream, decoding and validation, the policy parser, the expansion engine — on inputs generated in code, and (opt-in, `RPSL_REALDATA`) on the RIPE dumps. `check.sh` runs each once so none breaks unnoticed; `scripts/bench.sh` compares two refs on one machine with `benchstat`. Nothing times them in CI, where shared runners make timing meaningless.

`scripts/check.sh` runs 1–7 for every module under the race detector, and each benchmark of 10 once, with per-package coverage (plus gofmt, staticcheck, govulncheck and the leaf-isolation and engine-purity invariants); CI installs bgpq4 and runs it with a short `FUZZTIME` on Go 1.23 and the latest stable Go.

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
package for RFC 2725 and RIPE's `mnt-irt:` consent rule, and RPKI-aware expansion as IRRd 4 does it (`resolve/rpki`, §8.7), and NRTMv4 mirroring (`resolve/nrtm4`, §8.8), and policy evaluation (`resolve/peval`, §8.10) and `rpslconf -e`. See [README.md#Status](../README.md#status) for the same matrix in
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
- The only code anywhere in the module that matches an AS-path regexp against a concrete path is test code: `resolve/internal/routemodel`, a test oracle over synthetic paths, and the filter model's own Go translation of its regexps (`resolve/filter_model_test.go`); nothing exported does this, and `resolve/peval` keeps regexps symbolic (§8.10).

---

## 14. Integration harness (`examples/bulk-ripe`)

The library's correctness story rests on three pillars: unit tests per package, the golden lossless-round-trip corpus, and the bgpq4 differential for the engine. None of those exercises the streaming parser at the scale it has to survive in production — a multi-GB RIPE split dump fed in one byte at a time, with the parser holding only the current object in memory.

`examples/bulk-ripe` is the integration harness for that scale. It streams an RPSL bulk dump (e.g. RIPE's split files from `ftp://ftp.ripe.net/ripe/dbase/split/`) through `rpsl.Parse` / `ParseWith`, validates each decoded object against a chosen profile, optionally smoke-tests the `resolve.Expander` against a sample of retained sets, and prints a throughput + diagnostic-histogram report. A `lexer/malformed-line` rule appearing in the histogram on a canonical RIPE feed is a streaming/boundary regression — the report surfaces a hint to that effect.

See [`examples/bulk-ripe/README.md`](../examples/bulk-ripe/README.md) for invocation, flags, and reference output.
