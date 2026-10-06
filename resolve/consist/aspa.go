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

// namesPeer reports whether a peering names its peer specifically: an AS
// number, an as-set other than AS-ANY or a peering-set — not AS-ANY, which
// names no AS, nor an expression mentioning it (AS2 OR AS-ANY). Under EXCEPT only the left side names the peer.
func namesPeer(p policy.Peering) bool {
	switch x := p.(type) {
	case policy.PeeringAS:
		return !mentionsAny(x.AS) && asExprNames(x.AS)
	case policy.PeeringSetRef:
		return true
	}
	return false
}

// mentionsAny reports whether AS-ANY occurs on the positive side of e, at any
// depth: inside OR or AND, or the left side of EXCEPT. Such a peering can
// match a peer through AS-ANY alone, so it does not name the peer.
func mentionsAny(e policy.ASExpr) bool {
	switch x := e.(type) {
	case policy.ASSetRef:
		return anySets[x.Name.String()]
	case policy.ASExprBinary:
		if x.Op == policy.ASExcept {
			return mentionsAny(x.L)
		}
		return mentionsAny(x.L) || mentionsAny(x.R)
	}
	return false
}

func asExprNames(e policy.ASExpr) bool {
	switch x := e.(type) {
	case policy.ASNum:
		return true
	case policy.ASSetRef:
		return !anySets[x.Name.String()]
	case policy.ASSetTemplate:
		return true
	case policy.ASExprBinary:
		if x.Op == policy.ASExcept {
			return asExprNames(x.L)
		}
		return asExprNames(x.L) || asExprNames(x.R)
	}
	return false
}

// fullImport is an import clause taking a full table from peer in af.
type fullImport struct {
	peer  types.ASN
	index int
	af    types.AddrFamily
}

// noteFullTables records p's clauses that take a full table from peer, a
// real peer (l.real), through a peering that names it.
func (l *linter) noteFullTables(p peval.Policy, peer types.ASN, af types.AddrFamily) {
	if !l.real[peer] {
		return
	}
	for _, cl := range p.Clauses {
		if namesPeer(cl.Term.Peering) && fullTable(cl.Filter) {
			l.fulls = append(l.fulls, fullImport{peer, cl.Index, af})
		}
	}
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
// pl.Skipped other than "AS0").
func (l *linter) staleProviders(as types.ASN, pl PeerList, aspas *rpki.ASPAs) {
	ps, ok := aspas.Providers(as)
	if !ok || len(ps) == 0 {
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
// source does not have, or whose class is not its name's, has none (ok
// false): lint/missing-set reports it.
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
