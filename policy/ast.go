// Package policy parses the RPSL routing-policy grammar (RFC 2622 §6) found in
// the import:, export:, and default: attributes into a typed AST. Parsing is
// resilient: a malformed factor yields a diagnostic and recovery at the next
// peering separator, never a panic. The AST is modeled as sealed interfaces
// (Go's stand-in for sum types); exhaustive type switches cover every variant.
//
// Scope is RFC 2622 §6: protocol/into prefixes, from/to peering [action]
// clauses, and accept/announce/networks filters. RFC 4012 extensions
// (mp-import/mp-export, afi scoping, except/refine) are deferred; the sealed
// Expr interface is designed so those variants slot in without breaking callers.
package policy

import "github.com/rkolesnichenko/rpsl/types"

// Import is a parsed import: or mp-import: value. Protocol/IntoProtocol hold the
// optional "protocol X"/"into Y" prefixes ("" when absent). AFIs holds the RFC
// 4012 "afi <afi-list>" scope; empty means unscoped (legacy import:).
type Import struct {
	Protocol     string
	IntoProtocol string
	AFIs         []types.AddrFamily
	Expr         Expr
}

// Export is a parsed export: or mp-export: value. Its peerings use "to" and its
// filter uses "announce", but the structure mirrors Import.
type Export struct {
	Protocol     string
	IntoProtocol string
	AFIs         []types.AddrFamily
	Expr         Expr
}

// Default is a parsed default: value: a single peering with optional action and
// optional "networks" filter (nil when the value denotes an unscoped default).
type Default struct {
	Peering Peering
	Actions []Action
	Networks Filter
}

// Expr is the sealed routing-policy expression node: a Factor, a brace-enclosed
// ExprList, or an Except/Refine composition (RFC 2622 §6.5 / RFC 4012 §2.5.1).
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
type Except struct{ Left, Right Expr }

// Refine is "<Left> REFINE <Right>": the cartesian refinement of two policies.
type Refine struct{ Left, Right Expr }

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

// PeeringAS is an AS expression with optional router specifications. The router
// expressions are kept raw for now (router parsing is out of scope for M3).
type PeeringAS struct {
	AS       ASExpr
	Router   string
	AtRouter string
}

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

func (ASNum) isASExpr()        {}
func (ASSetRef) isASExpr()     {}
func (ASExprBinary) isASExpr() {}

// ASOp is a boolean operator over AS expressions.
type ASOp uint8

const (
	ASAnd ASOp = iota
	ASOr
	ASExcept
)

// Action is one routing-policy action: an rp-attribute assignment, append, or
// method call. For Assign/Append, Value is the right-hand side; for Method,
// Value is the raw "method(args)" text (method internals are not interpreted).
type Action struct {
	Attr  string
	Op    ActionOp
	Value string
}

// ActionOp distinguishes the three action forms.
type ActionOp uint8

const (
	ActionAssign ActionOp = iota // attr = value
	ActionAppend                 // attr .= value
	ActionMethod                 // attr.method(args)
)

// Filter is the sealed policy-filter node (RFC 2622 §5.4). Boolean precedence is
// NOT > AND > OR; parentheses override.
type Filter interface{ isFilter() }

// FilterAny matches everything (the ANY keyword).
type FilterAny struct{}

// FilterPeerAS matches the routes of the peer AS (the PeerAS keyword).
type FilterPeerAS struct{}

// FilterPrefixList is an explicit brace-enclosed prefix(-range) list.
type FilterPrefixList struct{ Ranges []types.PrefixRange }

// FilterASExpr filters by an AS expression (a bare AS or an as-set), resolved by
// the expansion engine in a later layer.
type FilterASExpr struct{ AS ASExpr }

// FilterSetRef references a route-set or filter-set by name.
type FilterSetRef struct{ Name types.SetName }

// FilterPathRE is an AS-path regexp (<...>). Raw preserves the original body for
// round-trip; Regexp is the parsed sub-AST (nil if it could not be parsed). The
// regexp is structured, not evaluated against live paths (design §9).
type FilterPathRE struct {
	Raw    string
	Regexp *ASPathRE
}

// FilterCommunity is a community(...) method call, kept raw for now.
type FilterCommunity struct{ Raw string }

// FilterAnd, FilterOr, FilterNot form the boolean tree over filter leaves.
type FilterAnd struct{ L, R Filter }
type FilterOr struct{ L, R Filter }
type FilterNot struct{ Inner Filter }

func (FilterAny) isFilter()        {}
func (FilterPeerAS) isFilter()     {}
func (FilterPrefixList) isFilter() {}
func (FilterASExpr) isFilter()     {}
func (FilterSetRef) isFilter()     {}
func (FilterPathRE) isFilter()     {}
func (FilterCommunity) isFilter()  {}
func (FilterAnd) isFilter()        {}
func (FilterOr) isFilter()         {}
func (FilterNot) isFilter()        {}
