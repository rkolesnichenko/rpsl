package consist

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// PeerList is what Peers found.
type PeerList struct {
	Forward []types.ASN // named directly by as's peerings (on either side of OR, AND, EXCEPT); ascending
	ViaSets []types.ASN // reached only by expanding an as-set or a peering-set its peerings name; ascending, none in Forward
	Reverse []types.ASN // aut-nums whose peerings name as (resolve.PolicyIndex only); ascending
	Skipped []string    // peerings that name no list of ASes: AS-ANY, set templates, regexps, as written; and "AS0"; sorted
	NoIndex bool        // the Source keeps no reverse index, so Reverse is empty
}

// Peers lists the AS numbers as's import, export and default peerings name:
// Forward, the AS numbers a peering names directly — an AS number anywhere
// in its AS expression; ViaSets, those it reaches only through an as-set or
// a peering-set (every AS a peering-set's peerings name included), expanded
// under the Evaluator's Expander limits (a set the Source lacks names
// nobody: Lint reports it); and Reverse, the aut-nums naming as directly,
// when the Source is a resolve.PolicyIndex that keeps an index. A set an
// exchange's members share can name tens of thousands of ASes, which is why
// ViaSets is kept apart: Lint and rpslcheck run sessions toward it only when
// asked (Checker.SetPeers). The -via attributes are not read. AS0 is
// reserved (RFC 7607) and never a session's peer: a peering that names it,
// directly or through a set, adds "AS0" to Skipped instead, and no list
// holds it; nor does any hold as itself. It returns an error wrapping
// resolve.ErrNotFound when as's aut-num is not in the Source, and a limit's
// error when an expansion hits one.
func (c *Checker) Peers(ctx context.Context, as types.ASN) (PeerList, error) {
	pl, _, err := c.peers(ctx, as)
	return pl, err
}

// asSet is what an AS expression denotes, as far as it can be listed: the
// AS numbers in members, or every AS (any: AS-ANY). members is never
// modified once built: one expansion's map is shared by every peering that
// names the set.
type asSet struct {
	members map[types.ASN]bool
	any     bool
}

// combine is l op r, for the AS-expression operators.
func combine(op policy.ASOp, l, r asSet) asSet {
	switch op {
	case policy.ASOr:
		if l.any || r.any {
			return asSet{any: true}
		}
		if len(l.members) == 0 {
			return r
		}
		if len(r.members) == 0 {
			return l
		}
		out := maps.Clone(l.members)
		maps.Copy(out, r.members)
		return asSet{members: out}
	case policy.ASAnd:
		switch {
		case l.any:
			return r
		case r.any:
			return l
		}
		out := map[types.ASN]bool{}
		for a := range l.members {
			if r.members[a] {
				out[a] = true
			}
		}
		return asSet{members: out}
	}
	// EXCEPT. AS-ANY less a list is still every AS but those: not listable,
	// and covered by the AS-ANY session anyway.
	switch {
	case r.any:
		return asSet{}
	case l.any:
		return l
	}
	out := map[types.ASN]bool{}
	for a := range l.members {
		if !r.members[a] {
			out[a] = true
		}
	}
	return asSet{members: out}
}

// peers is Peers, plus what each set peering — one whose AS expression
// names an as-set, or a peering-set — denotes, in document order, for
// Lint's representative sessions. A set peering that denotes every AS
// (AS-ANY) is left out: the AS-ANY session covers it.
func (c *Checker) peers(ctx context.Context, as types.ASN) (PeerList, []asSet, error) {
	ev := c.eval()
	an, err := ev.Src.AutNum(ctx, as, ev.Source)
	if err != nil {
		return PeerList{}, nil, fmt.Errorf("consist: %w", err)
	}
	e := ev.Expander
	e.Src = ev.Src
	fwd, via := map[types.ASN]bool{}, map[types.ASN]bool{}
	skipped := map[string]bool{}
	// Each set is expanded once per call, however many peerings name it.
	expanded := map[types.SetName]asSet{}
	expandAS := func(n types.SetName) (asSet, error) {
		if s, ok := expanded[n]; ok {
			return s, nil
		}
		set, err := e.ExpandAS(ctx, types.Ref(n))
		var anyErr *resolve.AnySetError
		var s asSet
		switch {
		case errors.As(err, &anyErr):
			skipped[n.String()] = true
			s.any = true
		case errors.Is(err, resolve.ErrNotFound):
		case err != nil:
			return asSet{}, err
		default:
			s.members = map[types.ASN]bool{}
			for _, a := range set.List() {
				s.members[a] = true
				via[a] = true
			}
		}
		expanded[n] = s
		return s, nil
	}
	// isSet records whether the peering being walked names a set.
	var isSet bool
	// asExpr records the AS numbers x names in names (directly) and via
	// (through sets), and returns what x denotes.
	var asExpr func(x policy.ASExpr, names map[types.ASN]bool) (asSet, error)
	asExpr = func(x policy.ASExpr, names map[types.ASN]bool) (asSet, error) {
		switch y := x.(type) {
		case policy.ASNum:
			names[y.AS] = true
			return asSet{members: map[types.ASN]bool{y.AS: true}}, nil
		case policy.ASSetRef:
			isSet = true
			return expandAS(y.Name)
		case policy.ASSetTemplate:
			skipped[y.Template.String()] = true
		case policy.ASExprBinary:
			l, err := asExpr(y.L, names)
			if err != nil {
				return asSet{}, err
			}
			r, err := asExpr(y.R, names)
			if err != nil {
				return asSet{}, err
			}
			return combine(y.Op, l, r), nil
		}
		return asSet{}, nil
	}
	// peering records what p names, directly in names, and returns what it
	// denotes.
	var peering func(p policy.Peering, names map[types.ASN]bool) (asSet, error)
	peering = func(p policy.Peering, names map[types.ASN]bool) (asSet, error) {
		switch x := p.(type) {
		case policy.PeeringAS:
			return asExpr(x.AS, names)
		case policy.PeeringSetRef:
			isSet = true
			ps, err := e.ExpandPeerings(ctx, types.Ref(x.Name))
			var anyErr *resolve.AnySetError
			switch {
			case errors.As(err, &anyErr):
				skipped[x.Name.String()] = true
				return asSet{any: true}, nil
			case errors.Is(err, resolve.ErrNotFound):
				return asSet{}, nil
			case err != nil:
				return asSet{}, err
			}
			// What a peering-set's peerings name, directly or not, is named
			// through the set.
			var out asSet
			for _, q := range ps.List() {
				d, err := peering(q, via)
				if err != nil {
					return asSet{}, err
				}
				out = combine(policy.ASOr, out, d)
			}
			return out, nil
		case policy.PeeringRegexp:
			skipped["<"+x.Raw+">"] = true
		}
		return asSet{}, nil
	}
	var groups []asSet
	for _, p := range policyPeerings(an) {
		isSet = false
		d, err := peering(p, fwd)
		if err != nil {
			return PeerList{}, nil, fmt.Errorf("consist: peers of %s: %w", as, err)
		}
		if isSet && !d.any {
			groups = append(groups, d)
		}
	}
	if fwd[0] || via[0] {
		skipped["AS0"] = true
	}
	for _, m := range []map[types.ASN]bool{fwd, via} {
		delete(m, as)
		delete(m, 0)
	}
	for a := range fwd {
		delete(via, a)
	}
	pl := PeerList{Forward: slices.Sorted(maps.Keys(fwd)), ViaSets: slices.Sorted(maps.Keys(via)), Skipped: slices.Sorted(maps.Keys(skipped))}
	pi, ok := ev.Src.(resolve.PolicyIndex)
	if !ok {
		pl.NoIndex = true
		return pl, groups, nil
	}
	rev, err := pi.NamedBy(as)
	switch {
	case errors.Is(err, resolve.ErrNoIndex):
		pl.NoIndex = true
	case err != nil:
		return PeerList{}, nil, err
	default:
		// Cloned: PolicyIndex does not promise a slice of the caller's own.
		pl.Reverse = slices.DeleteFunc(slices.Clone(rev), func(a types.ASN) bool { return a == as || a == 0 })
	}
	return pl, groups, nil
}

// policyPeerings returns every peering of an's import, export and default
// attributes, in document order.
func policyPeerings(an object.AutNum) []policy.Peering {
	var out []policy.Peering
	for _, ex := range append(importExprs(an), exportExprs(an)...) {
		out = append(out, exprPeerings(ex)...)
	}
	for _, d := range an.Defaults {
		out = append(out, d.Peering)
	}
	return out
}

func importExprs(an object.AutNum) []policy.Expr {
	out := make([]policy.Expr, len(an.Imports))
	for i, x := range an.Imports {
		out[i] = x.Expr
	}
	return out
}

func exportExprs(an object.AutNum) []policy.Expr {
	out := make([]policy.Expr, len(an.Exports))
	for i, x := range an.Exports {
		out[i] = x.Expr
	}
	return out
}

// exprPeerings returns the peerings of one policy expression, in order.
func exprPeerings(e policy.Expr) []policy.Peering {
	var out []policy.Peering
	var walk func(policy.Expr)
	walk = func(e policy.Expr) {
		switch x := e.(type) {
		case policy.Factor:
			for _, pa := range x.Peers {
				out = append(out, pa.Peering)
			}
		case policy.ExprList:
			for _, s := range x.Exprs {
				walk(s)
			}
		case policy.Except:
			walk(x.Left)
			walk(x.Right)
		case policy.Refine:
			walk(x.Left)
			walk(x.Right)
		}
	}
	walk(e)
	return out
}
