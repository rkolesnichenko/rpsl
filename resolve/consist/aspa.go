package consist

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// The ASPA rules Lint reports when Checker.ASPAs is set (docs/diagnostics.md).
// They compare registry data only — normalized filters' structure, peerings,
// set members and ASPA provider lists — and never evaluate an AS path.
const (
	// The aut-num imports a full table from a peer its ASPA does not list:
	// ASPA verification elsewhere would treat its routes through that peer
	// as leaks.
	RuleASPAMissingProvider = "lint/aspa-missing-provider"
	// The aut-num's ASPA lists a provider none of its peerings names.
	RuleASPAStaleProvider = "lint/aspa-stale-provider"
	// The aut-num announces an as-set whose direct member AS has an ASPA not
	// naming it. The issue's Peers holds that member, not a session peer.
	RuleASPACustomerSet = "lint/aspa-customer-set"
)

// fullTable reports whether a normalized import filter takes a full table:
// some conjunct accepts the family's whole space (ANY) less any negated
// prefixes, with only negated AS-path and community tests — a positive test
// selects a peer's or a customer's routes, not a provider's table — and
// accepts something.
func fullTable(f resolve.NormalFilter) bool {
	for _, cj := range f.Conjuncts {
		if cj.AnyPrefix() && onlyNegated(cj) && !cj.Space().IsEmpty() {
			return true
		}
	}
	return false
}

func onlyNegated(cj resolve.Conjunct) bool {
	for _, p := range cj.Paths {
		if !p.Negated {
			return false
		}
	}
	for _, c := range cj.Communities {
		if !c.Negated {
			return false
		}
	}
	return true
}

// namesPeer reports whether peering p names peer specifically, so that a
// full table taken through it makes peer a provider: peer is in what p
// denotes for a session toward peer, and nothing on p's positive side can
// match a peer through AS-ANY. That rules out AS-ANY written anywhere but
// right of an EXCEPT (ruling R3: AS2 OR AS-ANY names no peer), and AS-ANY
// reached through an as-set's expansion or a peering-set (ruling R7). A
// set template is instantiated for peer (ruling R9); one whose set is
// missing names nobody. Each set is expanded once per Lint call: d holds
// Peers' expansions.
func (d *denoter) namesPeer(p policy.Peering, peer types.ASN) (bool, error) {
	s, anyPos, err := d.peering(p, peer)
	return err == nil && !anyPos && !s.any && s.members[peer], err
}

// peering returns what p denotes toward peer and whether AS-ANY is reached
// on its positive side (inside OR or AND, left of EXCEPT, or in any of a
// peering-set's peerings).
func (d *denoter) peering(p policy.Peering, peer types.ASN) (asSet, bool, error) {
	switch x := p.(type) {
	case policy.PeeringAS:
		return d.asExpr(x.AS, peer)
	case policy.PeeringSetRef:
		ps, err := d.expandPeerings(x.Name)
		if err != nil || ps.any {
			return asSet{any: ps.any}, ps.any, err
		}
		var out asSet
		anyPos := false
		for _, q := range ps.peerings {
			s, a, err := d.peering(q, peer)
			if err != nil {
				return asSet{}, false, err
			}
			out, anyPos = combine(policy.ASOr, out, s), anyPos || a
		}
		return out, anyPos, nil
	}
	return asSet{}, false, nil
}

func (d *denoter) asExpr(e policy.ASExpr, peer types.ASN) (asSet, bool, error) {
	switch x := e.(type) {
	case policy.ASNum:
		return asSet{members: map[types.ASN]bool{x.AS: true}}, false, nil
	case policy.ASSetRef:
		s, err := d.expandAS(x.Name)
		return s, s.any, err
	case policy.ASSetTemplate:
		s, err := d.expandAS(x.Template.Instantiate(peer))
		return s, s.any, err
	case policy.ASExprBinary:
		l, la, err := d.asExpr(x.L, peer)
		if err != nil {
			return asSet{}, false, err
		}
		r, ra, err := d.asExpr(x.R, peer)
		if err != nil {
			return asSet{}, false, err
		}
		anyPos := la || ra
		if x.Op == policy.ASExcept {
			anyPos = la
		}
		return combine(x.Op, l, r), anyPos, nil
	}
	return asSet{}, false, nil
}

// fullImport is an import clause taking a full table from peer in af.
type fullImport struct {
	peer  types.ASN
	index int
	af    types.AddrFamily
}

// noteFullTables records p's clauses that take a full table from peer, a
// real peer (l.real), through a peering that names it. A limit met
// expanding a set template's set for peer is a lint/limit issue, and the
// clause is not recorded.
func (l *linter) noteFullTables(p peval.Policy, peer types.ASN, af types.AddrFamily) error {
	if !l.real[peer] {
		return nil
	}
	for _, cl := range p.Clauses {
		if !fullTable(cl.Filter) {
			continue
		}
		names, err := l.den.namesPeer(cl.Term.Peering, peer)
		if ok, err := l.failed(err, peer, af); ok || err != nil {
			if err != nil {
				return err
			}
			continue
		}
		if names {
			l.fulls = append(l.fulls, fullImport{peer, cl.Index, af})
		}
	}
	return nil
}

// missingProviders reports each recorded full-table import from a peer as's
// ASPA does not list (lint/aspa-missing-provider). An AS without an ASPA has
// none to compare.
func (l *linter) missingProviders(as types.ASN, aspas *rpki.ASPAs) {
	ps, ok := aspas.Providers(as)
	if !ok {
		return
	}
	for _, f := range l.fulls {
		if slices.Contains(ps, f.peer) {
			continue
		}
		msg := fmt.Sprintf("imports a full table from %s, but %s's ASPA does not list it as a provider", f.peer, as)
		if len(ps) == 0 {
			msg = fmt.Sprintf("imports a full table from %s, but %s's ASPA declares no transit providers (AS0)", f.peer, as)
		}
		af := f.af
		l.add(RuleASPAMissingProvider, "import", f.index, msg, f.peer, &af)
	}
}

// staleProviders reports each provider as's ASPA lists that none of its
// peerings names, directly or through a set (lint/aspa-stale-provider) —
// unless a peering could name any AS (AS-ANY, a regexp, a set template:
// pl.Skipped other than "AS0"), or a set some peering reaches, at any depth,
// is missing from the Source (missing; ruling R8), which could name it.
func (l *linter) staleProviders(as types.ASN, pl PeerList, missing bool, aspas *rpki.ASPAs) {
	ps, ok := aspas.Providers(as)
	if !ok || len(ps) == 0 || missing {
		return
	}
	for _, s := range pl.Skipped {
		if s != "AS0" {
			return
		}
	}
	for _, p := range ps {
		if slices.Contains(pl.Forward, p) || slices.Contains(pl.ViaSets, p) {
			continue
		}
		l.add(RuleASPAStaleProvider, "", -1, fmt.Sprintf("%s's ASPA lists %s as a provider, but no peering of %s names it", as, p, as), p, nil)
	}
}

// positiveASSets appends the as-sets a filter names positively: not under
// NOT, not inside an AS-path regexp, not a set template; under an AS
// expression's EXCEPT only its left side.
func positiveASSets(out []types.SetName, f policy.Filter) []types.SetName {
	switch x := f.(type) {
	case policy.FilterSetRef:
		if x.Name.Class() == types.ClassAsSet {
			return addSet(out, x.Name)
		}
	case policy.FilterASExpr:
		return positiveASExprSets(out, x.AS)
	case policy.FilterAnd:
		for _, t := range x.Terms {
			out = positiveASSets(out, t)
		}
	case policy.FilterOr:
		for _, t := range x.Terms {
			out = positiveASSets(out, t)
		}
	}
	return out
}

func positiveASExprSets(out []types.SetName, e policy.ASExpr) []types.SetName {
	switch x := e.(type) {
	case policy.ASSetRef:
		return addSet(out, x.Name)
	case policy.ASExprBinary:
		out = positiveASExprSets(out, x.L)
		if x.Op != policy.ASExcept {
			out = positiveASExprSets(out, x.R)
		}
	}
	return out
}

// directASNs returns the AS numbers a set's direct members hold, ascending:
// the ASNs object.DirectMembers lists, and the aut-nums claiming membership
// that resolve.ClaimAllowed admits. Nested sets are not followed. A set the
// source does not have, or whose class is not its name's, has none (nil,
// nil): lint/missing-set reports it. Any other Source failure is err.
func directASNs(ctx context.Context, src resolve.Source, n types.SetName) (asns []types.ASN, err error) {
	set, err := src.GetSet(ctx, types.Ref(n))
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case set == nil || set.Class() != n.Class().String():
		return nil, nil
	}
	if s, isSet := set.(object.Set); isSet {
		for _, m := range object.DirectMembers(s) {
			if m.Kind == object.MemberAS && !slices.Contains(asns, m.AS) {
				asns = append(asns, m.AS)
			}
		}
	}
	claimants, err := src.MembersByRef(ctx, set)
	if err != nil {
		return nil, err
	}
	for _, o := range claimants {
		if !resolve.ClaimAllowed(o, set) {
			continue
		}
		var a types.ASN
		switch an := o.(type) {
		case object.AutNum:
			a = an.AS
		case *object.AutNum:
			a = an.AS
		default:
			continue
		}
		if !slices.Contains(asns, a) {
			asns = append(asns, a)
		}
	}
	slices.Sort(asns)
	return asns, nil
}

// customerSets reports, for each as-set as's export filters announce, each
// direct member AS whose ASPA does not name as, or is an AS0 one
// (lint/aspa-customer-set). Each set is fetched once per call.
func (l *linter) customerSets(ctx context.Context, src resolve.Source, as types.ASN, aspas *rpki.ASPAs) error {
	members := map[types.SetName][]types.ASN{}
	for i, ex := range exportExprs(l.an) {
		var names []types.SetName
		eachFactor(ex, func(x policy.Factor) {
			names = positiveASSets(names, x.Filter)
		})
		for _, n := range names {
			ms, seen := members[n]
			if !seen {
				var err error
				if ms, err = directASNs(ctx, src, n); err != nil {
					return err
				}
				members[n] = ms
			}
			for _, m := range ms {
				ps, ok := aspas.Providers(m)
				if m == as || !ok || slices.Contains(ps, as) {
					continue
				}
				msg := fmt.Sprintf("announces %s, whose member %s has an ASPA that does not list %s as a provider", n, m, as)
				if len(ps) == 0 {
					msg = fmt.Sprintf("announces %s, whose member %s declares no transit providers (AS0)", n, m)
				}
				l.add(RuleASPACustomerSet, "export", i, msg, m, nil)
			}
		}
	}
	return nil
}
