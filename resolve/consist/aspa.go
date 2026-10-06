package consist

import (
	"fmt"
	"slices"

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
