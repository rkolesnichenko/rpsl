// Package peval evaluates an aut-num's routing policy for one BGP session:
// the ordered clauses — a filter in normal form and the actions to apply —
// that a route-map implements, as IRRToolSet's RtConfig computes them before
// printing. It is pure: all I/O goes through a resolve.PolicySource, and AS-path
// regexps and community tests are kept symbolic, never evaluated (design §13).
//
// A term whose peering names a router the session does not give, a peering
// regexp, or a protocol other than BGP4 is never guessed at: it is reported in
// Undecided and contributes no clause.
package peval

import (
	"context"
	"errors"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Session is one BGP session, seen from Local. The routers are optional: a
// zero address is one not given.
type Session struct {
	Local, Peer       types.ASN
	LocalRtr, PeerRtr netip.Addr
	AF                types.AddrFamily // which mp-* terms apply (policy.Import.Terms); AF.AFI trims prefixes
}

// Evaluator evaluates aut-num policies. All I/O goes through Src. Expander is a
// template — its limits, Exclude and Concurrency — whose Src, AFI and Peer
// each call sets; an Evaluator holds no per-call state, so one value may serve
// concurrent calls. Wrap Src in resolve.Cache to share lookups across calls.
type Evaluator struct {
	Src      resolve.PolicySource
	Expander resolve.Expander
	Source   string // the registry to read Local's aut-num from; "" is the Source's precedence
}

// Policy is what Local does with the routes of a session. A route takes the
// first clause it matches — the RFC 2622 §6.1 specification-order rule — and a
// route matching none is refused (an import) or not announced (an export).
type Policy struct {
	Clauses   []Clause
	Undecided []Undecided
	missing   []types.SetRef
	rtrs      []string
}

// Missing lists the sets the policy named that Src does not have, sorted.
func (p Policy) Missing() []types.SetRef { return p.missing }

// MissingRouters lists the inet-rtr names the policy named that Src does not
// have, lower-cased and sorted.
func (p Policy) MissingRouters() []string { return p.rtrs }

// Clause is one flattened term that applies to the session.
type Clause struct {
	Index   int                  // the attribute's position in AutNum.Imports (Exports, ImportVia, ExportVia)
	Term    policy.Term          // the term, as written
	Actions []policy.Action      // what a route it accepts is given
	Filter  resolve.NormalFilter // PeerAS bound (see Import)
	Remote  policy.Peering       // import-via: and export-via: only: the peering beyond the via one
}

// Defaults is what Local's default: and mp-default: attributes say for a session.
type Defaults struct {
	Clauses   []DefaultClause
	Undecided []Undecided
	missing   []types.SetRef
	rtrs      []string
}

// Missing lists the sets the defaults named that Src does not have, sorted.
func (d Defaults) Missing() []types.SetRef { return d.missing }

// MissingRouters lists the inet-rtr names that Src does not have, sorted.
func (d Defaults) MissingRouters() []string { return d.rtrs }

// DefaultClause is one default: that applies to the session.
type DefaultClause struct {
	Index    int // the attribute's position in AutNum.Defaults
	Peering  policy.Peering
	Actions  []policy.Action
	Networks *resolve.NormalFilter // nil: the default names no networks
}

// Undecided is a term the session might match that could not be decided.
type Undecided struct {
	Index int         // the attribute's position, as Clause.Index
	Term  policy.Term // zero for an attribute skipped whole (a protocol)
	Why   string      // "peer router not given", "local router not given", "peering regexp", "protocol OSPF", …
}

var errNoSource = errors.New("peval: Evaluator.Src is nil")

// newCall starts one evaluation for s.
func (v *Evaluator) newCall(ctx context.Context, s Session) *call {
	e := v.Expander
	e.Src, e.AFI, e.Peer = v.Src, s.AF.AFI, s.Peer
	return &call{
		ctx: ctx, src: v.Src, e: e, s: s,
		asns:    map[types.SetName]asMembers{},
		prngs:   map[types.SetName]*resolve.PeeringSet{},
		rtrSets: map[types.SetName]*resolve.RouterSet{},
		rtrs:    map[string][]netip.Addr{},
		missing: map[types.SetRef]bool{},
		noRtr:   map[string]bool{},
	}
}
