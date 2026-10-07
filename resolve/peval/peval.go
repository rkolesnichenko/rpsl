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
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
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
//
// Expander.Exclude narrows only the clause filters, and there only their
// prefix literals (see resolve.Expander.NormalizeFilter). It never decides
// which terms cover a session: the as-sets, peering-sets and rtr-sets of
// peerings and router expressions are expanded with Exclude cleared, since an
// excluded set on the right of an EXCEPT would otherwise widen the peering.
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
	Why   string      // one of the Why constants below
}

// The reasons a term is Undecided, Undecided.Why. They are stable, for a
// consumer to compare, and docs/rpslconf.md explains each. WhyProtocol and
// WhyInto begin a reason: a space and the protocol's name follow ("protocol
// OSPF", "into RIP").
const (
	WhyPeerRouter     = "peer router not given"                          // the peering names the peer's router; Session.PeerRtr is unset
	WhyLocalRouter    = "local router not given"                         // the peering names a local router ("at …"); Session.LocalRtr is unset
	WhyPeeringRegexp  = "peering regexp"                                 // a peering written as an AS-path regexp names no set of sessions
	WhyUnknownPeering = "unknown peering"                                // a peering of a kind this version does not know
	WhyViaPeerAS      = "PeerAS beyond a via peering names no single AS" // import-via:/export-via: whose remote peering is not one AS
	WhyProtocol       = "protocol"                                       // a policy for another protocol (RFC 2622 §6.4)
	WhyInto           = "into"                                           // a policy into another protocol
)

// Whys returns the Undecided reasons, WhyProtocol and WhyInto as the words
// that begin theirs.
func Whys() []string {
	return []string{WhyPeerRouter, WhyLocalRouter, WhyPeeringRegexp, WhyUnknownPeering, WhyViaPeerAS, WhyProtocol, WhyInto}
}

// errNoSource is returned by every evaluation method when Evaluator.Src is nil.
var errNoSource = errors.New("peval: Evaluator.Src is nil")

// newCall starts one evaluation for s.
func (v *Evaluator) newCall(ctx context.Context, s Session) *call {
	e := v.Expander
	e.Src, e.AFI, e.Peer = v.Src, s.AF.AFI, s.Peer
	m := e
	m.Exclude = resolve.Exclusion{}
	return &call{
		ctx: ctx, src: v.Src, e: e, m: m, s: s,
		asns:    map[types.SetName]asMembers{},
		prngs:   map[types.SetName]*resolve.Peerings{},
		rtrSets: map[types.SetName]*resolve.Routers{},
		rtrs:    map[string][]netip.Addr{},
		missing: map[types.SetRef]bool{},
		noRtr:   map[string]bool{},
	}
}

// begin checks a call's arguments and reads Local's aut-num.
func (v *Evaluator) begin(ctx context.Context, s Session) (*object.AutNum, *call, error) {
	if v.Src == nil {
		return nil, nil, errNoSource
	}
	if s.Local == 0 || s.Peer == 0 {
		return nil, nil, errors.New("peval: Session.Local and Session.Peer must be set")
	}
	if s.AF == (types.AddrFamily{}) {
		return nil, nil, errors.New("peval: Session.AF must be set")
	}
	an, err := v.Src.AutNum(ctx, s.Local, v.Source)
	if err == nil && an == nil { // the PolicySource contract: nil is not found
		err = fmt.Errorf("resolve: aut-num %s: %w", s.Local, resolve.ErrNotFound)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("peval: %w", err)
	}
	return an, v.newCall(ctx, s), nil
}

// attr is one import or export attribute, as evaluation needs it.
type attr struct {
	proto, into string
	applies     func(types.AddrFamily) bool
	terms       func(types.AddrFamily) ([]policy.Term, error)
}

func imports(is []policy.Import) []attr {
	out := make([]attr, len(is))
	for i, x := range is {
		out[i] = attr{x.Protocol, x.IntoProtocol, x.AppliesTo, x.Terms}
	}
	return out
}

func exports(es []policy.Export) []attr {
	out := make([]attr, len(es))
	for i, x := range es {
		out[i] = attr{x.Protocol, x.IntoProtocol, x.AppliesTo, x.Terms}
	}
	return out
}

// Import evaluates Local's import: and mp-import: attributes for the session:
// every flattened term (policy.Import.Terms) whose peering covers the session,
// in specification order, its filter normalized with PeerAS bound to s.Peer.
// An error — a limit, a context, a filter that cannot be normalized — is
// returned whole, with no partial Policy.
func (v *Evaluator) Import(ctx context.Context, s Session) (Policy, error) {
	an, c, err := v.begin(ctx, s)
	if err != nil {
		return Policy{}, err
	}
	return c.policy(imports(an.Imports), false)
}

// Export evaluates Local's export: and mp-export: attributes, as Import does.
func (v *Evaluator) Export(ctx context.Context, s Session) (Policy, error) {
	an, c, err := v.begin(ctx, s)
	if err != nil {
		return Policy{}, err
	}
	return c.policy(exports(an.Exports), false)
}

// ImportVia evaluates Local's import-via: attributes: the session is with the
// via peering (a route server), and Clause.Remote is the peering beyond it.
// PeerAS is bound to Remote's AS when that is a single AS number; a term
// whose filter names the peer when it is not is Undecided.
func (v *Evaluator) ImportVia(ctx context.Context, s Session) (Policy, error) {
	an, c, err := v.begin(ctx, s)
	if err != nil {
		return Policy{}, err
	}
	return c.policy(imports(an.ImportVia), true)
}

// ExportVia evaluates Local's export-via: attributes, as ImportVia does.
func (v *Evaluator) ExportVia(ctx context.Context, s Session) (Policy, error) {
	an, c, err := v.begin(ctx, s)
	if err != nil {
		return Policy{}, err
	}
	return c.policy(exports(an.ExportVia), true)
}

// Default evaluates Local's default: and mp-default: attributes for the session.
func (v *Evaluator) Default(ctx context.Context, s Session) (Defaults, error) {
	an, c, err := v.begin(ctx, s)
	if err != nil {
		return Defaults{}, err
	}
	var d Defaults
	for i, x := range an.Defaults {
		if !x.AppliesTo(s.AF) {
			continue
		}
		t := policy.Term{Peering: x.Peering, Actions: x.Actions, Filter: x.Networks}
		vd, why, err := c.peering(x.Peering)
		if err != nil {
			return Defaults{}, err
		}
		switch vd {
		case noMatch:
			continue
		case undecided:
			d.Undecided = append(d.Undecided, Undecided{Index: i, Term: t, Why: why})
			continue
		}
		dc := DefaultClause{Index: i, Peering: x.Peering, Actions: x.Actions}
		if x.Networks != nil {
			nf, err := c.filter(x.Networks, s.Peer)
			if err != nil {
				return Defaults{}, fmt.Errorf("peval: default %d: %w", i, err)
			}
			dc.Networks = &nf
		}
		d.Clauses = append(d.Clauses, dc)
	}
	d.missing, d.rtrs = c.missingLists()
	return d, nil
}

// Filter is peval: f normalized with PeerAS bound to peer (0 leaves it
// unbound) and prefixes trimmed to afi.
func (v *Evaluator) Filter(ctx context.Context, f policy.Filter, afi types.AFI, peer types.ASN) (resolve.NormalFilter, error) {
	if v.Src == nil {
		return resolve.NormalFilter{}, errNoSource
	}
	e := v.Expander
	e.Src, e.AFI, e.Peer = v.Src, afi, peer
	return e.NormalizeFilter(ctx, f)
}

// policy evaluates import or export attributes; via marks the -via forms,
// whose terms are matched on their via peering.
func (c *call) policy(attrs []attr, via bool) (Policy, error) {
	var p Policy
	for i, a := range attrs {
		if !a.applies(c.s.AF) {
			continue
		}
		if !isBGP(a.proto) || !isBGP(a.into) {
			why := WhyProtocol + " " + a.proto
			if isBGP(a.proto) {
				why = WhyInto + " " + a.into
			}
			p.Undecided = append(p.Undecided, Undecided{Index: i, Why: why})
			continue
		}
		terms, err := a.terms(c.s.AF)
		if err != nil {
			return Policy{}, fmt.Errorf("peval: %w", err)
		}
		for _, t := range terms {
			pe := t.Peering
			if via {
				pe = t.Via
			}
			vd, why, err := c.peering(pe)
			if err != nil {
				return Policy{}, err
			}
			switch vd {
			case noMatch:
				continue
			case undecided:
				p.Undecided = append(p.Undecided, Undecided{Index: i, Term: t, Why: why})
				continue
			}
			cl := Clause{Index: i, Term: t, Actions: t.Actions}
			peer := c.s.Peer
			if via {
				cl.Remote, peer = t.Peering, singleAS(t.Peering)
			}
			nf, err := c.filter(t.Filter, peer)
			if via && errors.Is(err, resolve.ErrUnboundPeer) {
				p.Undecided = append(p.Undecided, Undecided{Index: i, Term: t, Why: WhyViaPeerAS})
				continue
			}
			if err != nil {
				return Policy{}, fmt.Errorf("peval: %s: %w", t, err)
			}
			cl.Filter = nf
			p.Clauses = append(p.Clauses, cl)
		}
	}
	p.missing, p.rtrs = c.missingLists()
	return p, nil
}

// isBGP reports whether a protocol or into clause leaves the policy one for a
// BGP session: absent, or BGP4 (RFC 2622 §6.1's default).
func isBGP(p string) bool { return p == "" || strings.EqualFold(p, "BGP4") }

// singleAS is the AS number a peering names when it is exactly one, else 0.
func singleAS(p policy.Peering) types.ASN {
	if pa, ok := p.(policy.PeeringAS); ok && pa.Router == nil && pa.AtRouter == nil {
		if n, ok := pa.AS.(policy.ASNum); ok {
			return n.AS
		}
	}
	return 0
}
