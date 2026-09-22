package policy

import "strings"

// Flattening EXCEPT and REFINE (RFC 2622 §6.5, §6.6) into the plain
// (peering, actions, filter) triples a policy really denotes. Parsing keeps the
// nesting; Flatten computes what it means, which is what a consumer generating
// router configuration needs.
//
// The one approximation is how two peerings are matched. RFC 2622 defines
// REFINE over peerings that intersect; here two peerings intersect when they
// render alike, or when one of them is AS-ANY, which every peering meets. A
// peering-set reference is therefore compared by name, not expanded —
// expanding it needs a registry, which this layer deliberately cannot reach
// (design §1.3). resolve.Expander is where that belongs.

// Term is one flattened policy: a peering, the actions attached to it, and the
// filter in effect for it once EXCEPT and REFINE have been resolved.
type Term struct {
	Peering Peering
	Actions []Action
	Filter  Filter
}

// String renders the term as "<peering> [action …] <filter>".
func (t Term) String() string {
	var b strings.Builder
	b.WriteString(exprText(t.Peering))
	if len(t.Actions) > 0 {
		b.WriteString(" action " + actionsString(t.Actions))
	}
	b.WriteString(" | " + filterString(t.Filter, precOr))
	return b.String()
}

// Flatten resolves EXCEPT and REFINE and returns the policy's terms in
// specification order — the order the RFC 2622 §6.1 specification-order rule
// reads them in. An expression the parser could not build returns no terms.
func Flatten(e Expr) []Term {
	return flatten(e, 0)
}

// maxFlattenDepth bounds the recursion, which follows the parsed nesting. The
// parser already caps that at maxParseDepth; this is the same bound restated so
// that a hand-built AST cannot overflow the stack either.
const maxFlattenDepth = maxParseDepth

func flatten(e Expr, depth int) []Term {
	if e == nil || depth > maxFlattenDepth {
		return nil
	}
	switch x := e.(type) {
	case Factor:
		out := make([]Term, 0, len(x.Peers))
		for _, p := range x.Peers {
			out = append(out, Term{Peering: p.Peering, Actions: p.Actions, Filter: x.Filter})
		}
		return out
	case ExprList:
		var out []Term
		for _, sub := range x.Exprs {
			out = append(out, flatten(sub, depth+1)...)
		}
		return out
	case Refine:
		return refineTerms(flatten(x.Left, depth+1), flatten(x.Right, depth+1))
	case Except:
		return exceptTerms(flatten(x.Left, depth+1), flatten(x.Right, depth+1))
	}
	return nil
}

// refineTerms is the cartesian refinement of RFC 2622 §6.5: one term per pair
// of left and right terms whose peerings intersect, carrying the more specific
// peering, both actions in order, and the conjunction of both filters.
func refineTerms(left, right []Term) []Term {
	var out []Term
	for _, l := range left {
		for _, r := range right {
			pe, ok := intersectPeerings(l.Peering, r.Peering)
			if !ok {
				continue
			}
			out = append(out, Term{
				Peering: pe,
				Actions: concatActions(l.Actions, r.Actions),
				Filter:  andFilters(l.Filter, r.Filter),
			})
		}
	}
	return out
}

// exceptTerms is the exception of RFC 2622 §6.6: each right-hand term overrides
// the left for what it covers, so it keeps its own peering and actions and
// takes the conjunction of both filters; the left-hand terms keep what the
// right did not take.
func exceptTerms(left, right []Term) []Term {
	if len(right) == 0 {
		return left
	}
	out := make([]Term, 0, len(right)*len(left)+len(left))
	for _, l := range left {
		for _, r := range right {
			out = append(out, Term{
				Peering: r.Peering,
				Actions: r.Actions,
				Filter:  andFilters(l.Filter, r.Filter),
			})
		}
	}
	covered := make([]Filter, 0, len(right))
	for _, r := range right {
		if r.Filter != nil {
			covered = append(covered, r.Filter)
		}
	}
	rest := orFilters(covered)
	for _, l := range left {
		f := l.Filter
		if rest != nil {
			f = andFilters(f, FilterNot{Inner: rest})
		}
		out = append(out, Term{Peering: l.Peering, Actions: l.Actions, Filter: f})
	}
	return out
}

// intersectPeerings reports whether two peerings denote a common peer and
// returns the more specific of the two. See the file comment for the rule.
func intersectPeerings(a, b Peering) (Peering, bool) {
	switch {
	case a == nil:
		return b, b != nil
	case b == nil:
		return a, true
	case isAnyPeering(a):
		return b, true
	case isAnyPeering(b):
		return a, true
	case exprText(a) == exprText(b):
		return a, true
	}
	return nil, false
}

// isAnyPeering reports whether the peering is AS-ANY, which meets every peering.
func isAnyPeering(p Peering) bool {
	as, ok := p.(PeeringAS)
	if !ok || as.Router != nil || as.AtRouter != nil {
		return false
	}
	ref, ok := as.AS.(ASSetRef)
	return ok && strings.EqualFold(ref.Name.String(), "AS-ANY")
}

// concatActions joins two action lists, left first, without sharing backing
// arrays with either input.
func concatActions(l, r []Action) []Action {
	if len(l) == 0 {
		return r
	}
	if len(r) == 0 {
		return l
	}
	out := make([]Action, 0, len(l)+len(r))
	return append(append(out, l...), r...)
}

// andFilters returns the conjunction of two filters, keeping AND chains flat as
// the parser builds them; a nil operand is "no constraint".
func andFilters(a, b Filter) Filter {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	terms := make([]Filter, 0, 2)
	for _, f := range []Filter{a, b} {
		if and, ok := f.(FilterAnd); ok {
			terms = append(terms, and.Terms...)
			continue
		}
		terms = append(terms, f)
	}
	return FilterAnd{Terms: terms}
}

// orFilters returns the disjunction of the filters, flat, or nil for none.
func orFilters(fs []Filter) Filter {
	switch len(fs) {
	case 0:
		return nil
	case 1:
		return fs[0]
	}
	terms := make([]Filter, 0, len(fs))
	for _, f := range fs {
		if or, ok := f.(FilterOr); ok {
			terms = append(terms, or.Terms...)
			continue
		}
		terms = append(terms, f)
	}
	return FilterOr{Terms: terms}
}
