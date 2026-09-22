// Package policy parses the RPSL routing-policy grammar (RFC 2622 §6) found in
// the import:, export:, and default: attributes into a typed AST. Parsing is
// resilient and total: every value is either consumed completely or yields a
// diagnostic (nothing is dropped silently), and hostile input never panics.
// The AST is modeled as sealed interfaces (Go's stand-in for sum types);
// exhaustive type switches cover every variant.
//
// Scope is RFC 2622 §5-6 — protocol/into prefixes, from/to peerings with
// AS-expressions and router expressions, actions, filters with implicit OR and
// range operators, AS-path regexps, structured except/refine policies — plus
// RFC 4012 (RPSLng): afi scoping and mp-import/mp-export/mp-default.
package policy

import (
	"net/netip"

	"github.com/rkolesnichenko/rpsl/types"
)

// Import is a parsed import: or mp-import: value. Protocol/IntoProtocol hold the
// optional "protocol X"/"into Y" prefixes ("" when absent). MP marks an
// mp-import: (ParseMPImport). AFIs holds the RFC 4012 "afi <afi-list>" clause as
// written; when it is empty the policy applies to ipv4.unicast for a legacy
// import: and to every family for an mp-import: (RFC 4012 §2.5).
type Import struct {
	Protocol     string
	IntoProtocol string
	MP           bool
	AFIs         []types.AddrFamily
	Expr         Expr
}

// Export is a parsed export: or mp-export: value. Its peerings use "to" and its
// filter uses "announce", but the structure mirrors Import.
type Export struct {
	Protocol     string
	IntoProtocol string
	MP           bool
	AFIs         []types.AddrFamily
	Expr         Expr
}

// Default is a parsed default: value: a single peering with optional action and
// optional "networks" filter (nil when the value denotes an unscoped default).
type Default struct {
	MP       bool
	AFIs     []types.AddrFamily
	Peering  Peering
	Actions  []Action
	Networks Filter
}

// Expr is the sealed routing-policy expression node: a Factor, a brace-enclosed
// ExprList, or an Except/Refine composition (RFC 2622 §6.6 / RFC 4012 §2.5).
// Except and Refine are right-associative ("performed right to left"):
// "A except B refine C" is Except{A, Refine{B, C}}.
type Expr interface{ isExpr() }

// Factor is "(from|to) <peering> [action <actions>] ... accept|announce <filter>".
// Peers holds one entry per peering clause, in document order.
type Factor struct {
	Peers  []PeerAction
	Filter Filter
}

// ExprList is a brace-enclosed list of expressions: "{" e1 ";" e2 … "}".
type ExprList struct{ Exprs []Expr }

// Except is "<Left> EXCEPT <Right>": refinement that overrides the base policy
// for the routes the right-hand expression matches.
type Except struct {
	Left, Right Expr
	AFIs        []types.AddrFamily
}

// Refine is "<Left> REFINE <Right>": the cartesian refinement of two policies.
type Refine struct {
	Left, Right Expr
	AFIs        []types.AddrFamily
}

func (Factor) isExpr()   {}
func (ExprList) isExpr() {}
func (Except) isExpr()   {}
func (Refine) isExpr()   {}

// PeerAction pairs one peering specification with its optional action list.
type PeerAction struct {
	Peering Peering
	Actions []Action
}

// Peering is the sealed peering-specification node (RFC 2622 §6.2).
type Peering interface{ isPeering() }

// PeeringAS is an AS expression with optional router expressions: Router is the
// peer-side expression and AtRouter the local one after "at"; nil if absent.
type PeeringAS struct {
	AS       ASExpr
	Router   RouterExpr
	AtRouter RouterExpr
}

// RouterExpr is the sealed router-expression node (RFC 2622 §5.6, RFC 4012):
// router addresses, inet-rtr names and rtr-sets under AND, OR and EXCEPT.
type RouterExpr interface{ isRouterExpr() }

// RouterAddr is a router's IPv4 or IPv6 address.
type RouterAddr struct{ Addr netip.Addr }

// RouterName is an inet-rtr name, a DNS name such as "rtr1.example.net".
type RouterName struct{ Name string }

// RouterSetRef is a reference to an rtr-set (rtrs-…).
type RouterSetRef struct{ Name types.SetName }

// RouterExprBinary combines two router expressions with AND, OR, or EXCEPT.
type RouterExprBinary struct {
	Op   RouterOp
	L, R RouterExpr
}

func (RouterAddr) isRouterExpr()       {}
func (RouterName) isRouterExpr()       {}
func (RouterSetRef) isRouterExpr()     {}
func (RouterExprBinary) isRouterExpr() {}

// RouterOp is a boolean operator over router expressions. As for AS
// expressions, EXCEPT binds like AND and OR is lowest (RFC 2622 §5.6).
type RouterOp uint8

// The router-expression operators.
const (
	RouterAnd RouterOp = iota
	RouterOr
	RouterExcept
)

// PeeringSetRef is a reference to a peering-set (prng-…).
type PeeringSetRef struct{ Name types.SetName }

// PeeringRegexp is an AS-path regexp used in peering position. Raw preserves the
// original body for round-trip; Regexp is the parsed sub-AST (nil if it could
// not be parsed).
type PeeringRegexp struct {
	Raw    string
	Regexp *ASPathRE
}

func (PeeringAS) isPeering()     {}
func (PeeringSetRef) isPeering() {}
func (PeeringRegexp) isPeering() {}

// ASExpr is the sealed AS-expression node, shared by peerings and AS filters.
type ASExpr interface{ isASExpr() }

// ASNum is a bare autonomous system number.
type ASNum struct{ AS types.ASN }

// ASSetRef is a reference to an as-set (as-…) or hierarchical set name.
type ASSetRef struct{ Name types.SetName }

// ASExprBinary combines two AS expressions with AND, OR, or EXCEPT.
type ASExprBinary struct {
	Op   ASOp
	L, R ASExpr
}

// ASSetTemplate references a per-peer as-set ("AS1:AS-CUSTOMERS:PeerAS").
type ASSetTemplate struct{ Template SetNameTemplate }

func (ASNum) isASExpr()         {}
func (ASSetRef) isASExpr()      {}
func (ASSetTemplate) isASExpr() {}
func (ASExprBinary) isASExpr()  {}

// ASOp is a boolean operator over AS expressions. EXCEPT binds like AND; OR is
// lowest (RFC 2622 §5.6).
type ASOp uint8

// The AS-expression operators.
const (
	ASAnd ASOp = iota
	ASOr
	ASExcept
)

// Action is one routing-policy action (RFC 2622 §7): an rp-attribute
// assignment ("pref = 100"), append ("community .= {1:2}") or method call
// ("community.append(1:2)", "aspath.prepend(AS1)"). Attr is the rp-attribute
// and Method the method, both lower-cased; Value is the right-hand side of an
// assignment or append, Args a method call's comma-separated arguments, and
// Raw the action as written.
type Action struct {
	Attr   string
	Method string
	Op     ActionOp
	Args   []string
	Value  string
	Raw    string
}

// ActionOp distinguishes the three action forms.
type ActionOp uint8

const (
	ActionAssign ActionOp = iota // attr = value
	ActionAppend                 // attr .= value
	ActionMethod                 // attr.method(args)
)

// Filter is the sealed policy-filter node (RFC 2622 §5.4). Boolean precedence is
// NOT > AND > OR; parentheses override; juxtaposition ("x y") is OR. Op on a
// term is its range operator ("AS-FOO^+"); the zero Op means none.
type Filter interface{ isFilter() }

// FilterAny matches everything (the ANY keyword).
type FilterAny struct{}

// FilterPeerAS matches the routes of the peer AS (the PeerAS keyword).
type FilterPeerAS struct{ Op types.RangeOperator }

// FilterPrefixList is an explicit brace-enclosed prefix(-range) list. An outer
// operator ("{...}^+") is composed into each range at parse time (RFC 2622
// §5.2); ranges it deletes are dropped.
type FilterPrefixList struct{ Ranges []types.PrefixRange }

// FilterASExpr filters by an AS, an as-set, or a per-peer as-set template,
// resolved by the expansion engine in a later layer.
type FilterASExpr struct {
	AS ASExpr
	Op types.RangeOperator
}

// FilterSetRef references a route-set or filter-set by name.
type FilterSetRef struct {
	Name types.SetName
	Op   types.RangeOperator
}

// FilterSetTemplate references a per-peer route-set or filter-set
// ("AS1:RS-FOO:PeerAS").
type FilterSetTemplate struct {
	Template SetNameTemplate
	Op       types.RangeOperator
}

// FilterPathRE is an AS-path regexp (<...>). Raw preserves the original body for
// round-trip; Regexp is the parsed sub-AST (nil if it could not be parsed). The
// regexp is structured, not evaluated against live paths (design §9).
type FilterPathRE struct {
	Raw    string
	Regexp *ASPathRE
}

// FilterCommunity is a community test (RFC 2622 §7): community(…) and
// community.contains(…) match routes carrying all of Values (Op
// CommunityContains); community == {…} matches routes carrying exactly them
// (CommunityEquals). Raw is the term as written.
type FilterCommunity struct {
	Op     CommunityOp
	Values []string
	Raw    string
}

// CommunityOp is the comparison a FilterCommunity makes.
type CommunityOp uint8

// The community comparisons.
const (
	CommunityContains CommunityOp = iota // community(…), community.contains(…)
	CommunityEquals                      // community == {…}
)

// FilterAnd matches what all of its two or more Terms match. A chain
// "a AND b AND c" is one node, so a long filter is a wide node rather than a
// deep tree; parentheses keep their own node.
type FilterAnd struct{ Terms []Filter }

// FilterOr matches what any of its two or more Terms matches: "a OR b OR c",
// and the implicit OR "a b c", are one node.
type FilterOr struct{ Terms []Filter }

// FilterNot matches what Inner does not.
type FilterNot struct{ Inner Filter }

func (FilterAny) isFilter()         {}
func (FilterPeerAS) isFilter()      {}
func (FilterPrefixList) isFilter()  {}
func (FilterASExpr) isFilter()      {}
func (FilterSetRef) isFilter()      {}
func (FilterSetTemplate) isFilter() {}
func (FilterPathRE) isFilter()      {}
func (FilterCommunity) isFilter()   {}
func (FilterAnd) isFilter()         {}
func (FilterOr) isFilter()          {}
func (FilterNot) isFilter()         {}
