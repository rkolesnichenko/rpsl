package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

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
// filter in effect for it once EXCEPT and REFINE have been resolved. Via is
// the peering the routes pass through, for a term of an import-via: or
// export-via: policy, and nil otherwise.
type Term struct {
	Via     Peering
	Peering Peering
	Actions []Action
	Filter  Filter
}

// String renders the term as "<peering> [via <peering>] [action …] | <filter>".
func (t Term) String() string {
	var b strings.Builder
	b.WriteString(exprText(t.Peering))
	if t.Via != nil {
		b.WriteString(" via " + exprText(t.Via))
	}
	if len(t.Actions) > 0 {
		b.WriteString(" action " + actionsString(t.Actions))
	}
	b.WriteString(" | " + filterString(t.Filter, precOr))
	return b.String()
}

// ErrFlattenTooLarge is returned by Flatten when the terms it would build
// exceed MaxFlattenNodes filter nodes, or the expression is nested deeper than
// the parser allows. Each level of an EXCEPT chain doubles the size of the
// filters, so a value of a few hundred bytes could otherwise denote gigabytes.
var ErrFlattenTooLarge = errors.New("policy: flattened policy too large")

// MaxFlattenNodes caps the work of one Flatten: the filter nodes of every term
// it builds, counting a filter shared by several terms once per term, since
// every consumer walking the terms pays for it that often.
const MaxFlattenNodes = 1 << 20

// Flatten resolves EXCEPT and REFINE for address family af and returns the
// policy's terms in specification order — the order the RFC 2622 §6.1
// specification-order rule reads them in.
//
// An EXCEPT or REFINE with an afi clause of its own (RFC 4012 §2.5) takes
// effect only for the families that clause covers; for any other family the
// left-hand policy stands as it is. One without an afi clause takes effect for
// every family. Whether the policy as a whole is in effect for af is the
// enclosing value's question: Import.Terms and Export.Terms ask it.
//
// A policy that flattens to more than MaxFlattenNodes filter nodes returns an
// error wrapping ErrFlattenTooLarge rather than exhausting memory.
func Flatten(e Expr, af types.AddrFamily) ([]Term, error) {
	f := flattener{af: af}
	ts := f.flatten(e, 0)
	if f.err != nil || len(ts) == 0 {
		return nil, f.err
	}
	out := make([]Term, len(ts))
	for i, t := range ts {
		out[i] = t.Term
	}
	return out, nil
}

// Terms flattens the import for address family af: nil when the import is not
// in effect for af (AppliesTo), and otherwise Flatten of its expression.
func (i Import) Terms(af types.AddrFamily) ([]Term, error) {
	if !i.AppliesTo(af) {
		return nil, nil
	}
	return Flatten(i.Expr, af)
}

// Terms flattens the export for address family af, as Import.Terms does.
func (e Export) Terms(af types.AddrFamily) ([]Term, error) {
	if !e.AppliesTo(af) {
		return nil, nil
	}
	return Flatten(e.Expr, af)
}

// maxFlattenDepth bounds the recursion, which follows the parsed nesting. The
// parser already caps that at maxParseDepth; this is the same bound restated so
// that a hand-built AST cannot overflow the stack either.
const maxFlattenDepth = maxParseDepth

// flattener carries one Flatten's family and its budget.
type flattener struct {
	af    types.AddrFamily
	spent int // filter nodes of every term built so far
	err   error
}

// wterm is a term with the size of its filter, which is known when the term is
// built and would cost exponential time to measure afterwards.
type wterm struct {
	Term
	w int
}

// charge accounts for a new term of w filter nodes, and reports whether the
// budget still holds.
func (f *flattener) charge(w int) bool {
	if f.err != nil {
		return false
	}
	if f.spent += w + 1; f.spent > MaxFlattenNodes {
		f.err = fmt.Errorf("%w: more than %d filter nodes", ErrFlattenTooLarge, MaxFlattenNodes)
		return false
	}
	return true
}

// covers reports whether an EXCEPT or REFINE scoped to afis takes effect for
// the family being flattened; with no afi clause it always does.
func (f *flattener) covers(afis []types.AddrFamily) bool {
	if len(afis) == 0 {
		return true
	}
	for _, a := range afis {
		if a.Covers(f.af) {
			return true
		}
	}
	return false
}

func (f *flattener) flatten(e Expr, depth int) []wterm {
	if e == nil || f.err != nil {
		return nil
	}
	if depth > maxFlattenDepth {
		f.err = fmt.Errorf("%w: nested deeper than %d", ErrFlattenTooLarge, maxFlattenDepth)
		return nil
	}
	switch x := e.(type) {
	case Factor:
		w := filterSize(x.Filter, 0)
		out := make([]wterm, 0, len(x.Peers))
		for _, p := range x.Peers {
			if !f.charge(w) {
				return nil
			}
			out = append(out, wterm{Term{Via: p.Via, Peering: p.Peering, Actions: p.Actions, Filter: x.Filter}, w})
		}
		return out
	case ExprList:
		var out []wterm
		for _, sub := range x.Exprs {
			out = append(out, f.flatten(sub, depth+1)...)
		}
		return out
	case Refine:
		left := f.flatten(x.Left, depth+1)
		if !f.covers(x.AFIs) {
			return left
		}
		return f.refineTerms(left, f.flatten(x.Right, depth+1))
	case Except:
		left := f.flatten(x.Left, depth+1)
		if !f.covers(x.AFIs) {
			return left
		}
		return f.exceptTerms(left, f.flatten(x.Right, depth+1))
	}
	return nil
}

// filterSize counts the nodes of a parsed filter, whose depth the parser caps.
func filterSize(fl Filter, depth int) int {
	if depth > maxFlattenDepth {
		return 1
	}
	switch x := fl.(type) {
	case nil:
		return 0
	case FilterAnd:
		n := 1
		for _, t := range x.Terms {
			n += filterSize(t, depth+1)
		}
		return n
	case FilterOr:
		n := 1
		for _, t := range x.Terms {
			n += filterSize(t, depth+1)
		}
		return n
	case FilterNot:
		return 1 + filterSize(x.Inner, depth+1)
	}
	return 1
}

// refineTerms is the cartesian refinement of RFC 2622 §6.5: one term per pair
// of left and right terms whose peerings — and via peerings, in a via policy —
// intersect, carrying the more specific of each, both actions in order, and
// the conjunction of both filters.
func (f *flattener) refineTerms(left, right []wterm) []wterm {
	var out []wterm
	for _, l := range left {
		for _, r := range right {
			pe, ok := intersectPeerings(l.Peering, r.Peering)
			if !ok {
				continue
			}
			via, ok := intersectVias(l.Via, r.Via)
			if !ok {
				continue
			}
			w := l.w + r.w + 1
			if !f.charge(w) {
				return nil
			}
			out = append(out, wterm{Term{
				Via:     via,
				Peering: pe,
				Actions: concatActions(l.Actions, r.Actions),
				Filter:  andFilters(l.Filter, r.Filter),
			}, w})
		}
	}
	return out
}

// exceptTerms is the exception of RFC 2622 §6.6: each right-hand term overrides
// the left for what it covers, so it keeps its own peering and actions and
// takes the conjunction of both filters; the left-hand terms keep what the
// right did not take.
func (f *flattener) exceptTerms(left, right []wterm) []wterm {
	if len(right) == 0 {
		return left
	}
	out := make([]wterm, 0, len(right)*len(left)+len(left))
	for _, l := range left {
		for _, r := range right {
			w := l.w + r.w + 1
			if !f.charge(w) {
				return nil
			}
			out = append(out, wterm{Term{
				Via:     r.Via,
				Peering: r.Peering,
				Actions: r.Actions,
				Filter:  andFilters(l.Filter, r.Filter),
			}, w})
		}
	}
	covered := make([]Filter, 0, len(right))
	restW := 2 // the NOT and the OR
	for _, r := range right {
		if r.Filter != nil {
			covered = append(covered, r.Filter)
			restW += r.w
		}
	}
	rest := orFilters(covered)
	for _, l := range left {
		fl, w := l.Filter, l.w
		if rest != nil {
			fl, w = andFilters(fl, FilterNot{Inner: rest}), w+restW+1
		}
		if !f.charge(w) {
			return nil
		}
		out = append(out, wterm{Term{Via: l.Via, Peering: l.Peering, Actions: l.Actions, Filter: fl}, w})
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

// intersectVias is intersectPeerings for via peerings, which are absent from
// every policy but import-via: and export-via:; two absent ones meet.
func intersectVias(a, b Peering) (Peering, bool) {
	if a == nil && b == nil {
		return nil, true
	}
	return intersectPeerings(a, b)
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
