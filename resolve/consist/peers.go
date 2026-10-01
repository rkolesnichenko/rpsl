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
	Forward []types.ASN // named by as's peerings, as-sets and peering-sets expanded; ascending
	Reverse []types.ASN // aut-nums whose peerings name as (resolve.PolicyIndex only); ascending
	Skipped []string    // peerings that name no list of ASes: AS-ANY, set templates, regexps, as written; and "AS0"; sorted
	NoIndex bool        // the Source keeps no reverse index, so Reverse is empty
}

// Peers lists the AS numbers as's import, export and default peerings name:
// Forward, with as-sets and peering-sets expanded under the Evaluator's
// Expander limits (a set the Source lacks names nobody: Lint reports it);
// and Reverse, the aut-nums naming as directly, when the Source is a
// resolve.PolicyIndex that keeps an index. The -via attributes are not
// read. AS0 is reserved (RFC 7607) and never a session's peer: a peering
// that names it, directly or through a set, adds "AS0" to Skipped instead,
// and neither list holds it. It returns an error wrapping resolve.ErrNotFound when as's aut-num
// is not in the Source, and a limit's error when an expansion hits one.
func (c *Checker) Peers(ctx context.Context, as types.ASN) (PeerList, error) {
	ev := c.eval()
	an, err := ev.Src.AutNum(ctx, as, ev.Source)
	if err != nil {
		return PeerList{}, fmt.Errorf("consist: %w", err)
	}
	e := ev.Expander
	e.Src = ev.Src
	fwd := map[types.ASN]bool{}
	skipped := map[string]bool{}
	var asExpr func(policy.ASExpr) error
	asExpr = func(x policy.ASExpr) error {
		switch y := x.(type) {
		case policy.ASNum:
			fwd[y.AS] = true
		case policy.ASSetRef:
			set, err := e.ExpandAS(ctx, types.Ref(y.Name))
			var anyErr *resolve.AnySetError
			switch {
			case errors.As(err, &anyErr):
				skipped[y.Name.String()] = true
			case errors.Is(err, resolve.ErrNotFound):
			case err != nil:
				return err
			default:
				for _, a := range set.List() {
					fwd[a] = true
				}
			}
		case policy.ASSetTemplate:
			skipped[y.Template.String()] = true
		case policy.ASExprBinary:
			if err := asExpr(y.L); err != nil {
				return err
			}
			return asExpr(y.R)
		}
		return nil
	}
	var peering func(policy.Peering) error
	peering = func(p policy.Peering) error {
		switch x := p.(type) {
		case policy.PeeringAS:
			return asExpr(x.AS)
		case policy.PeeringSetRef:
			ps, err := e.ExpandPeerings(ctx, types.Ref(x.Name))
			var anyErr *resolve.AnySetError
			switch {
			case errors.As(err, &anyErr):
				skipped[x.Name.String()] = true
				return nil
			case errors.Is(err, resolve.ErrNotFound):
				return nil
			case err != nil:
				return err
			}
			for _, q := range ps.List() {
				if err := peering(q); err != nil {
					return err
				}
			}
		case policy.PeeringRegexp:
			skipped["<"+x.Raw+">"] = true
		}
		return nil
	}
	for _, p := range policyPeerings(an) {
		if err := peering(p); err != nil {
			return PeerList{}, fmt.Errorf("consist: peers of %s: %w", as, err)
		}
	}
	delete(fwd, as)
	if fwd[0] {
		delete(fwd, 0)
		skipped["AS0"] = true
	}
	pl := PeerList{Forward: slices.Sorted(maps.Keys(fwd)), Skipped: slices.Sorted(maps.Keys(skipped))}
	pi, ok := ev.Src.(resolve.PolicyIndex)
	if !ok {
		pl.NoIndex = true
		return pl, nil
	}
	rev, err := pi.NamedBy(as)
	switch {
	case errors.Is(err, resolve.ErrNoIndex):
		pl.NoIndex = true
	case err != nil:
		return PeerList{}, err
	default:
		// Cloned: PolicyIndex does not promise a slice of the caller's own.
		pl.Reverse = slices.DeleteFunc(slices.Clone(rev), func(a types.ASN) bool { return a == as || a == 0 })
	}
	return pl, nil
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
