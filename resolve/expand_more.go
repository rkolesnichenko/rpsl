package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// Expanding the set classes that hold something other than ASNs and prefixes:
// the routers of an rtr-set, the peerings of a peering-set, and the prefixes a
// filter-set's expression denotes.
//
// The first two are ordinary traversals, the same breadth-first discovery the
// as-set and route-set expansions use. The third is different in kind: a filter
// is an expression, not a member list, so evaluating it means computing over
// prefix ranges — and only part of the filter language has a finite answer in
// prefixes at all. See EvalFilter.

// ExpandRouters returns the routers denoted by an rtr-set: the router members
// of every rtr-set reachable from it, plus the inet-rtr objects that claim
// membership through mbrs-by-ref. A set of another class returns an error
// wrapping ErrSetClass; a missing top-level set one wrapping ErrNotFound.
// Missing nested sets expand to nothing and are listed by RouterSet.Missing.
func (e *Expander) ExpandRouters(ctx context.Context, n types.SetName) (RouterSet, error) {
	if n.Class() != types.ClassRtrSet {
		return RouterSet{}, fmt.Errorf("resolve: ExpandRouters %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return RouterSet{}, err
	}
	out := newRouterSet()
	for _, nd := range g.nodes {
		rs, ok := nd.set.(object.RouterSet)
		if !ok {
			continue
		}
		for _, m := range rs.SetRouters() {
			if m.Kind == object.RtrMemberRouter {
				out.add(m.Router)
			}
		}
		// An inet-rtr that claims membership joins under its own name.
		for _, o := range nd.claims {
			ir, ok := o.(object.InetRtr)
			if !ok {
				continue
			}
			if r, err := types.ParseRouterID(ir.Name); err == nil {
				out.add(r)
			}
		}
	}
	out.missing = g.missing
	return *out, nil
}

// ExpandPeerings returns the peerings denoted by a peering-set: the peering:
// and mp-peering: specifications of every peering-set reachable from it, with
// nested peering-set references followed and replaced by what they denote.
// A set of another class returns an error wrapping ErrSetClass.
func (e *Expander) ExpandPeerings(ctx context.Context, n types.SetName) (PeeringSet, error) {
	if n.Class() != types.ClassPeeringSet {
		return PeeringSet{}, fmt.Errorf("resolve: ExpandPeerings %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return PeeringSet{}, err
	}
	out := newPeeringSet()
	// Walk in the graph's discovery order so the result does not depend on map
	// iteration: the top set first, then the rest by canonical name.
	for _, nd := range g.ordered() {
		pg, ok := nd.set.(object.PeeringGroup)
		if !ok {
			continue
		}
		for _, p := range pg.SetPeerings() {
			if _, isRef := p.(policy.PeeringSetRef); isRef {
				continue // followed by discovery; its contents are already here
			}
			out.add(p)
		}
	}
	out.missing = g.missing
	return *out, nil
}

// ExpandFilterSet evaluates a filter-set's filter into the prefix ranges it
// denotes, choosing filter: or mp-filter: by the expander's AFI. A set of
// another class returns an error wrapping ErrSetClass; see EvalFilter for what
// a filter can and cannot denote.
func (e *Expander) ExpandFilterSet(ctx context.Context, n types.SetName) (RangeSet, error) {
	if n.Class() != types.ClassFilterSet {
		return RangeSet{}, fmt.Errorf("resolve: ExpandFilterSet %s: %w", n, ErrSetClass)
	}
	ev := newFilterEval(e, ctx)
	set, err := e.Src.GetSet(ctx, n)
	if err == nil && set == nil {
		err = ErrNotFound
	}
	if err != nil {
		return RangeSet{}, fmt.Errorf("expand %s: %w", n, err)
	}
	fg, ok := setValue(set).(object.FilterGroup)
	if !ok {
		return RangeSet{}, fmt.Errorf("resolve: ExpandFilterSet %s: %w", n, ErrSetClass)
	}
	ev.seen[n.String()] = true
	got, err := ev.eval(ev.pick(fg), 0)
	if err != nil {
		return RangeSet{}, err
	}
	return ev.result(got), nil
}

// NotEnumerableError reports a filter term that denotes no finite set of
// prefixes, so it cannot be expanded without a routing table: a negation, a
// community test, an AS-path regexp, or anything that depends on which peer the
// policy is being evaluated for.
type NotEnumerableError struct {
	Term string // the offending term, as RPSL
	Why  string
}

func (e *NotEnumerableError) Error() string {
	return "resolve: cannot enumerate the prefixes of " + e.Term + ": " + e.Why
}

// EvalFilter evaluates a policy filter into the prefix ranges it denotes,
// resolving set and AS references through the Source.
//
// Only the part of the filter language that has a finite answer in prefixes is
// evaluated: ANY, prefix lists, route-set, as-set and filter-set references, AS
// numbers and AS expressions, OR, and AND (as the intersection of what the two
// sides denote). A term that denotes no such set — NOT, PeerAS, a community
// test, an AS-path regexp, a per-peer set template — returns a
// *NotEnumerableError naming it, rather than a quietly smaller answer.
func (e *Expander) EvalFilter(ctx context.Context, f policy.Filter) (RangeSet, error) {
	ev := newFilterEval(e, ctx)
	got, err := ev.eval(f, 0)
	if err != nil {
		return RangeSet{}, err
	}
	return ev.result(got), nil
}

// rangeSetOf is the working representation of a filter's value: the ranges it
// denotes, deduplicated.
type rangeSetOf map[types.PrefixRange]struct{}

// filterEval evaluates one filter, tracking the filter-sets already entered so
// that a cycle terminates, and the sets that were not found.
type filterEval struct {
	e       *Expander
	ctx     context.Context
	seen    map[string]bool
	missing []types.SetName
	visits  int
}

func newFilterEval(e *Expander, ctx context.Context) *filterEval {
	return &filterEval{e: e, ctx: ctx, seen: map[string]bool{}}
}

// pick chooses a filter-set's filter: or mp-filter: by the expander's AFI. A
// v6 expansion prefers mp-filter:, which is where RFC 4012 puts IPv6; either
// falls back to the other when the set carries only one.
func (ev *filterEval) pick(fg object.FilterGroup) policy.Filter {
	v4, v6 := fg.SetFilter(), fg.SetMpFilter()
	if ev.e.AFI == types.AFIv6 && v6 != nil {
		return v6
	}
	if v4 != nil {
		return v4
	}
	return v6
}

// result turns the working set into a RangeSet, carrying the missing sets.
func (ev *filterEval) result(got rangeSetOf) RangeSet {
	out := newRangeSet()
	for r := range got {
		out.add(r)
	}
	out.missing = sortedNames(ev.missing)
	return *out
}

// note records a set the filter named but the Source does not have.
func (ev *filterEval) note(n types.SetName) {
	for _, m := range ev.missing {
		if m == n {
			return
		}
	}
	ev.missing = append(ev.missing, n)
}

// cap enforces MaxPrefixes on a working set as it grows.
func (ev *filterEval) cap(got rangeSetOf, n types.SetName) error {
	if len(got) > ev.e.maxPrefixes() {
		return &SetTooLargeError{Name: n, Limit: LimitPrefixes, Max: ev.e.maxPrefixes(), Count: len(got)}
	}
	return nil
}

// eval evaluates one filter node.
func (ev *filterEval) eval(f policy.Filter, depth int) (rangeSetOf, error) {
	if err := ev.ctx.Err(); err != nil {
		return nil, err
	}
	if depth > ev.e.maxDepth() {
		return nil, &SetTooLargeError{Limit: LimitDepth, Max: ev.e.maxDepth(), Count: depth}
	}
	if ev.visits++; ev.visits > ev.e.maxVisited() {
		return nil, &SetTooLargeError{Limit: LimitVisited, Max: ev.e.maxVisited(), Count: ev.visits}
	}
	switch x := f.(type) {
	case nil:
		return rangeSetOf{}, nil
	case policy.FilterAny:
		return ev.everything(), nil
	case policy.FilterPrefixList:
		out := rangeSetOf{}
		for _, r := range x.Ranges {
			ev.put(out, r)
		}
		return out, nil
	case policy.FilterOr:
		out := rangeSetOf{}
		for _, t := range x.Terms {
			got, err := ev.eval(t, depth+1)
			if err != nil {
				return nil, err
			}
			for r := range got {
				out[r] = struct{}{}
			}
			if err := ev.cap(out, types.SetName{}); err != nil {
				return nil, err
			}
		}
		return out, nil
	case policy.FilterAnd:
		var out rangeSetOf
		for _, t := range x.Terms {
			got, err := ev.eval(t, depth+1)
			if err != nil {
				return nil, err
			}
			if out == nil {
				out = got
				continue
			}
			out = intersectRanges(out, got)
			if err := ev.cap(out, types.SetName{}); err != nil {
				return nil, err
			}
		}
		if out == nil {
			return rangeSetOf{}, nil
		}
		return out, nil
	case policy.FilterSetRef:
		return ev.setRef(x.Name, x.Op, depth)
	case policy.FilterASExpr:
		as, err := ev.asns(x.AS, depth)
		if err != nil {
			return nil, err
		}
		return ev.routesOf(as, x.Op)
	case policy.FilterNot:
		return nil, &NotEnumerableError{Term: filterText(x), Why: "a negation has no finite set of prefixes"}
	case policy.FilterPeerAS:
		return nil, &NotEnumerableError{Term: "PeerAS", Why: "it depends on which peer the policy is for"}
	case policy.FilterSetTemplate:
		return nil, &NotEnumerableError{Term: x.Template.String(), Why: "it depends on which peer the policy is for"}
	case policy.FilterCommunity:
		return nil, &NotEnumerableError{Term: filterText(x), Why: "a community test needs a routing table"}
	case policy.FilterPathRE:
		return nil, &NotEnumerableError{Term: filterText(x), Why: "an AS-path regexp needs a routing table"}
	}
	return nil, &NotEnumerableError{Term: filterText(f), Why: "unknown filter term"}
}

// setRef evaluates a reference to a route-set, as-set or filter-set, composing
// the term's range operator into what it denotes.
func (ev *filterEval) setRef(n types.SetName, op types.RangeOperator, depth int) (rangeSetOf, error) {
	if isAnySet(n) {
		return nil, &AnySetError{Name: n}
	}
	switch n.Class() {
	case types.ClassRouteSet, types.ClassAsSet:
		rs, err := ev.e.ExpandPrefixRanges(ev.ctx, n)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			ev.note(n)
			return rangeSetOf{}, nil
		}
		for _, m := range rs.Missing() {
			ev.note(m)
		}
		out := rangeSetOf{}
		for _, r := range rs.List() {
			ev.putOp(out, r, op)
		}
		return out, ev.cap(out, n)
	case types.ClassFilterSet:
		if ev.seen[n.String()] {
			return rangeSetOf{}, nil // a cycle contributes nothing more
		}
		ev.seen[n.String()] = true
		set, err := ev.e.Src.GetSet(ev.ctx, n)
		if err == nil && set == nil {
			err = ErrNotFound
		}
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			ev.note(n)
			return rangeSetOf{}, nil
		}
		fg, ok := setValue(set).(object.FilterGroup)
		if !ok {
			ev.note(n)
			return rangeSetOf{}, nil
		}
		got, err := ev.eval(ev.pick(fg), depth+1)
		if err != nil {
			return nil, err
		}
		if op.IsZero() {
			return got, nil
		}
		out := rangeSetOf{}
		for r := range got {
			ev.putOp(out, r, op)
		}
		return out, nil
	}
	return nil, &NotEnumerableError{
		Term: n.String(),
		Why:  "a " + n.Class().String() + " denotes no prefixes",
	}
}

// asns resolves an AS expression to the AS numbers it denotes. AND, OR and
// EXCEPT are the intersection, union and difference of the two sides, which is
// what RFC 2622 §5.6 means by them.
func (ev *filterEval) asns(e policy.ASExpr, depth int) (map[types.ASN]bool, error) {
	if depth > ev.e.maxDepth() {
		return nil, &SetTooLargeError{Limit: LimitDepth, Max: ev.e.maxDepth(), Count: depth}
	}
	switch x := e.(type) {
	case nil:
		return map[types.ASN]bool{}, nil
	case policy.ASNum:
		return map[types.ASN]bool{x.AS: true}, nil
	case policy.ASSetRef:
		if isAnySet(x.Name) {
			return nil, &AnySetError{Name: x.Name}
		}
		set, err := ev.e.ExpandAS(ev.ctx, x.Name)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			ev.note(x.Name)
			return map[types.ASN]bool{}, nil
		}
		for _, m := range set.Missing() {
			ev.note(m)
		}
		out := make(map[types.ASN]bool, set.Len())
		for _, a := range set.List() {
			out[a] = true
		}
		return out, nil
	case policy.ASExprBinary:
		l, err := ev.asns(x.L, depth+1)
		if err != nil {
			return nil, err
		}
		r, err := ev.asns(x.R, depth+1)
		if err != nil {
			return nil, err
		}
		out := map[types.ASN]bool{}
		switch x.Op {
		case policy.ASOr:
			for a := range l {
				out[a] = true
			}
			for a := range r {
				out[a] = true
			}
		case policy.ASAnd:
			for a := range l {
				if r[a] {
					out[a] = true
				}
			}
		case policy.ASExcept:
			for a := range l {
				if !r[a] {
					out[a] = true
				}
			}
		}
		return out, nil
	case policy.ASSetTemplate:
		return nil, &NotEnumerableError{Term: x.Template.String(), Why: "it depends on which peer the policy is for"}
	}
	return nil, &NotEnumerableError{Term: "AS expression", Why: "unknown AS expression"}
}

// routesOf returns the routes the given ASes originate, as exact ranges with
// the term's operator composed in.
func (ev *filterEval) routesOf(as map[types.ASN]bool, op types.RangeOperator) (rangeSetOf, error) {
	out := rangeSetOf{}
	for a := range as {
		routes, err := ev.e.Src.OriginatedRoutes(ev.ctx, a, ev.e.AFI)
		if err != nil {
			return nil, err
		}
		for _, p := range routes {
			p = p.Masked()
			r, ok := types.NewPrefixRange(p, p.Bits(), p.Bits())
			if !ok {
				continue
			}
			ev.putOp(out, r, op)
		}
		if err := ev.cap(out, types.SetName{}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// everything is the value of ANY: every prefix of the families in scope, held
// as the two full ranges rather than enumerated.
func (ev *filterEval) everything() rangeSetOf {
	out := rangeSetOf{}
	for _, p := range []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	} {
		if r, ok := types.NewPrefixRange(p, 0, p.Addr().BitLen()); ok {
			ev.put(out, r)
		}
	}
	return out
}

// put adds a range, if the expander's address family allows it.
func (ev *filterEval) put(out rangeSetOf, r types.PrefixRange) {
	if r.IsEmpty() || !ev.e.afiAllows(r.Prefix()) {
		return
	}
	out[r] = struct{}{}
}

// putOp adds a range with an operator composed into it (RFC 2622 §5.2).
func (ev *filterEval) putOp(out rangeSetOf, r types.PrefixRange, op types.RangeOperator) {
	if !op.IsZero() {
		c, ok := op.Apply(r)
		if !ok {
			return // the operator deletes the range
		}
		r = c
	}
	ev.put(out, r)
}

// intersectRanges returns the ranges denoting exactly what both sets denote.
func intersectRanges(a, b rangeSetOf) rangeSetOf {
	out := rangeSetOf{}
	for x := range a {
		for y := range b {
			if c, ok := x.Intersect(y); ok {
				out[c] = struct{}{}
			}
		}
	}
	return out
}

// filterText renders a filter term for a diagnostic.
func filterText(f policy.Filter) string {
	if s, ok := f.(interface{ String() string }); ok {
		return s.String()
	}
	return "filter"
}
