package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

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
// Missing nested sets expand to nothing and are listed by Routers.Missing.
// A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the
// scope does not cascade to what it lists.
func (e *Expander) ExpandRouters(ctx context.Context, ref types.SetRef) (Routers, error) {
	if ref.Name().Class() != types.ClassRtrSet {
		return Routers{}, fmt.Errorf("resolve: ExpandRouters %s: %w", ref, ErrSetClass)
	}
	g, err := e.discover(ctx, ref)
	if err != nil {
		return Routers{}, err
	}
	out := newRouterSet()
	for _, nd := range g.nodes {
		rs, ok := nd.set.(object.RouterGroup)
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
			ir, ok := o.(*object.InetRtr)
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
// A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the
// scope does not cascade to what it lists.
func (e *Expander) ExpandPeerings(ctx context.Context, ref types.SetRef) (Peerings, error) {
	if ref.Name().Class() != types.ClassPeeringSet {
		return Peerings{}, fmt.Errorf("resolve: ExpandPeerings %s: %w", ref, ErrSetClass)
	}
	g, err := e.discover(ctx, ref)
	if err != nil {
		return Peerings{}, err
	}
	out := newPeeringSet()
	// Walk in the graph's discovery order so the result does not depend on map
	// iteration: the top set first, then the rest by reference.
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
// a filter can and cannot denote. A scoped ref fetches the filter-set from that
// registry; the filter-sets and sets its filter names are unscoped, as filter
// syntax has no registry.
func (e *Expander) ExpandFilterSet(ctx context.Context, ref types.SetRef) (RangeSet, error) {
	if ref.Name().Class() != types.ClassFilterSet {
		return RangeSet{}, fmt.Errorf("resolve: ExpandFilterSet %s: %w", ref, ErrSetClass)
	}
	ev := newFilterEval(e, ctx)
	fg, err := ev.filterSet(ref)
	if err != nil {
		return RangeSet{}, fmt.Errorf("expand %s: %w", ref, err)
	}
	if fg == nil {
		return RangeSet{}, fmt.Errorf("expand %s: %w", ref, ErrNotFound)
	}
	// Only the top filter-set is evaluated through ref; every filter-set its
	// filter names is an unscoped reference, a node of its own even when it
	// names the top set again.
	got, err := ev.runWith(func() (rangeSetOf, error) { return ev.topValue(ref) })
	if err != nil {
		return RangeSet{}, err
	}
	return ev.result(got), nil
}

// NotEnumerableError reports a filter term that denotes no finite set of
// prefixes, so it cannot be expanded without a routing table: a negation, a
// community test, an AS-path regexp, or — with no Expander.Peer — anything
// that depends on which peer the policy is being evaluated for.
type NotEnumerableError struct {
	Term string // the offending term, as RPSL
	Why  string
	err  error // ErrUnboundPeer for a term that names the peer
}

func (e *NotEnumerableError) Error() string {
	return "resolve: cannot enumerate the prefixes of " + e.Term + ": " + e.Why
}

// Unwrap returns ErrUnboundPeer for a term that needs a bound peer, and nil
// otherwise.
func (e *NotEnumerableError) Unwrap() error { return e.err }

// ErrUnboundPeer is wrapped by the *NotEnumerableError of a term that names
// the peer — PeerAS, or a set template — evaluated with no Expander.Peer.
var ErrUnboundPeer = errors.New("resolve: PeerAS with no peer bound")

// unboundPeer is the error for a peer-dependent term with no peer bound.
func unboundPeer(term string) error {
	return &NotEnumerableError{Term: term, Why: "it depends on which peer the policy is for", err: ErrUnboundPeer}
}

// EvalFilter evaluates a policy filter into the prefix ranges it denotes,
// resolving set and AS references through the Source.
//
// Only the part of the filter language that has a finite answer in prefixes is
// evaluated: ANY, prefix lists, route-set, as-set and filter-set references, AS
// numbers and AS expressions, OR, and AND (as the intersection of what the two
// sides denote). A term that denotes no such set — NOT, PeerAS, a community
// test, an AS-path regexp, or — with no Expander.Peer — a per-peer set
// template — returns a *NotEnumerableError naming it, rather than a quietly
// smaller answer.
//
// Each set is fetched and expanded once per call, and MaxVisited bounds the
// call as a whole: the sets every expansion reached and the filter terms
// evaluated. A cycle of filter-sets denotes the least fixpoint, as a cycle of
// route-sets does (FLTR-A = {10.0.0.0/8} OR FLTR-A^+ is 10.0.0.0/8 and
// 10.0.0.0/8^+).
func (e *Expander) EvalFilter(ctx context.Context, f policy.Filter) (RangeSet, error) {
	ev := newFilterEval(e, ctx)
	got, err := ev.run(f)
	if err != nil {
		return RangeSet{}, err
	}
	return ev.result(got), nil
}

// rangeSetOf is the working representation of a filter's value: the ranges it
// denotes, deduplicated. A value, once built, is never modified, so one may be
// shared by memo entries and callers.
type rangeSetOf map[types.PrefixRange]struct{}

// filterEval evaluates one filter. Filter-sets are fetched and set references
// expanded once per call. Filter-sets are keyed by reference: only the top one
// ExpandFilterSet names may be scoped, and a reference met inside a filter is
// unscoped, so RIPE::FLTR-X and FLTR-X are two filter-sets. A cycle of filter-sets is solved by iteration: each
// pass evaluates a back-edge to a set with that set's value from the pass
// before (approx), starting from nothing, and passes repeat until the values
// stop growing — the least fixpoint, since every filter it evaluates is
// monotone.
type filterEval struct {
	e       *Expander
	ctx     context.Context
	missing []types.SetRef
	visits  int          // filter terms evaluated and sets reached, against MaxVisited
	cur     types.SetRef // the filter-set being evaluated, to name it in errors

	sets   map[string]object.FilterGroup // filter-sets fetched, by SetRef.String(); nil for one not found
	memo   map[string]rangeSetOf         // filter-set values of this pass, by SetRef.String()
	approx map[string]rangeSetOf         // filter-set values of the pass before
	active map[string]bool               // filter-sets on the path being evaluated
	cyclic bool                          // this pass took a back-edge
	ranges map[string]RangeSet           // route-set and as-set expansions
	asns   map[string]ASNSet             // as-set expansions in AS expressions
	ex     excluded                      // what the expansion leaves out
	anyAll bool                          // AS-ANY and RS-ANY denote every route (NormalizeFilter) rather than an AnySetError
}

func newFilterEval(e *Expander, ctx context.Context) *filterEval {
	return &filterEval{
		e: e, ctx: ctx,
		sets:   map[string]object.FilterGroup{},
		active: map[string]bool{},
		ranges: map[string]RangeSet{},
		asns:   map[string]ASNSet{},
		ex:     e.excluded(),
	}
}

// skipSet reports whether a set reference is excluded: only one met inside a
// filter-set is, since the terms of the filter passed in are the caller's.
func (ev *filterEval) skipSet(n types.SetName) bool { return !ev.cur.IsZero() && ev.ex.set(n) }

// skipAS is skipSet for an AS number.
func (ev *filterEval) skipAS(a types.ASN) bool { return !ev.cur.IsZero() && ev.ex.as(a) }

// run evaluates f to its least fixpoint (see filterEval).
func (ev *filterEval) run(f policy.Filter) (rangeSetOf, error) {
	return ev.runWith(func() (rangeSetOf, error) { return ev.eval(f, 0) })
}

// runWith repeats one evaluation pass until the least fixpoint (see
// filterEval).
func (ev *filterEval) runWith(pass func() (rangeSetOf, error)) (rangeSetOf, error) {
	for {
		ev.memo, ev.cyclic = map[string]rangeSetOf{}, false
		got, err := pass()
		if err != nil {
			return nil, err
		}
		if !ev.cyclic || sameValues(ev.memo, ev.approx) {
			return got, nil
		}
		ev.approx = ev.memo
	}
}

// sameValues reports whether two passes gave every filter-set the same value.
func sameValues(a, b map[string]rangeSetOf) bool {
	if len(a) != len(b) {
		return false
	}
	for n, x := range a {
		y, ok := b[n]
		if !ok || len(x) != len(y) {
			return false
		}
		for r := range x {
			if _, ok := y[r]; !ok {
				return false
			}
		}
	}
	return true
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
	out.missing = sortedRefs(ev.missing)
	return *out
}

// note records a set the filter named but the Source does not have.
func (ev *filterEval) note(r types.SetRef) {
	for _, m := range ev.missing {
		if m == r {
			return
		}
	}
	ev.missing = append(ev.missing, r)
}

// cap enforces MaxPrefixes on a working set as it grows; r names the set it
// belongs to, or is zero for the filter-set being evaluated.
func (ev *filterEval) cap(got rangeSetOf, r types.SetRef) error {
	if len(got) > ev.e.maxPrefixes() {
		if r.IsZero() {
			r = ev.cur
		}
		return &SetTooLargeError{Name: r, Limit: LimitPrefixes, Max: ev.e.maxPrefixes(), Count: len(got)}
	}
	return nil
}

// visit charges n visits against MaxVisited.
func (ev *filterEval) visit(n int) error {
	if ev.visits += n; ev.visits > ev.e.maxVisited() {
		return &SetTooLargeError{Name: ev.cur, Limit: LimitVisited, Max: ev.e.maxVisited(), Count: ev.visits}
	}
	return nil
}

// eval evaluates one filter node.
func (ev *filterEval) eval(f policy.Filter, depth int) (rangeSetOf, error) {
	if err := ev.ctx.Err(); err != nil {
		return nil, err
	}
	if depth > ev.e.maxDepth() {
		return nil, &SetTooLargeError{Name: ev.cur, Limit: LimitDepth, Max: ev.e.maxDepth(), Count: depth}
	}
	if err := ev.visit(1); err != nil {
		return nil, err
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
			if err := ev.cap(out, types.SetRef{}); err != nil {
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
			if out, err = ev.intersect(out, got); err != nil {
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
		if ref, ok := x.AS.(policy.ASSetRef); ok && ev.anyAll && isAnySet(ref.Name) {
			return ev.setRef(ref.Name, x.Op, depth)
		}
		as, err := ev.asExpr(x.AS, depth)
		if err != nil {
			return nil, err
		}
		return ev.routesOf(as, x.Op)
	case policy.FilterNot:
		return nil, &NotEnumerableError{Term: filterText(x), Why: "a negation has no finite set of prefixes"}
	case policy.FilterPeerAS:
		if ev.e.Peer == 0 {
			return nil, unboundPeer("PeerAS")
		}
		if ev.skipAS(ev.e.Peer) {
			return rangeSetOf{}, nil
		}
		return ev.routesOf(map[types.ASN]bool{ev.e.Peer: true}, x.Op)
	case policy.FilterSetTemplate:
		if ev.e.Peer == 0 {
			return nil, unboundPeer(x.Template.String())
		}
		return ev.setRef(x.Template.Instantiate(ev.e.Peer), x.Op, depth)
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
	if ev.skipSet(n) {
		return rangeSetOf{}, nil
	}
	if isAnySet(n) {
		if !ev.anyAll {
			return nil, &AnySetError{Name: n}
		}
		out := rangeSetOf{}
		for r := range ev.everything() {
			ev.putOp(out, r, op)
		}
		return out, nil
	}
	switch n.Class() {
	case types.ClassRouteSet, types.ClassAsSet:
		rs, err := ev.prefixRanges(n)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			ev.note(types.Ref(n))
			return rangeSetOf{}, nil
		}
		for _, m := range rs.Missing() {
			ev.note(m)
		}
		out := rangeSetOf{}
		for _, r := range rs.List() {
			ev.putOp(out, r, op)
		}
		return out, ev.cap(out, types.Ref(n))
	case types.ClassFilterSet:
		got, err := ev.filterSetValue(types.Ref(n), depth)
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

// topValue is what the filter-set ExpandFilterSet names denotes, evaluated as
// eval evaluates a reference to it, but through its own, possibly scoped, ref.
func (ev *filterEval) topValue(ref types.SetRef) (rangeSetOf, error) {
	if err := ev.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ev.visit(1); err != nil {
		return nil, err
	}
	if isAnySet(ref.Name()) {
		return nil, &AnySetError{Name: ref.Name()}
	}
	return ev.filterSetValue(ref, 0)
}

// filterSetValue is what filter-set ref denotes in this pass: the previous
// pass's value on a back-edge, this pass's value once computed, and otherwise
// the value of its filter.
func (ev *filterEval) filterSetValue(ref types.SetRef, depth int) (rangeSetOf, error) {
	key := ref.String()
	if ev.active[key] {
		ev.cyclic = true
		if v := ev.approx[key]; v != nil {
			return v, nil
		}
		return rangeSetOf{}, nil
	}
	if v, ok := ev.memo[key]; ok {
		return v, nil
	}
	fg, err := ev.filterSet(ref)
	if err != nil {
		return nil, err
	}
	if fg == nil {
		ev.note(ref)
		return rangeSetOf{}, nil
	}
	outer := ev.cur
	ev.active[key], ev.cur = true, ref
	got, err := ev.eval(ev.pick(fg), depth+1)
	delete(ev.active, key)
	ev.cur = outer
	if err != nil {
		return nil, err
	}
	ev.memo[key] = got
	return got, nil
}

// filterSet fetches a filter-set once per call: nil, with no error, when the
// Source does not have it or has something else under its name.
func (ev *filterEval) filterSet(ref types.SetRef) (object.FilterGroup, error) {
	if fg, ok := ev.sets[ref.String()]; ok {
		return fg, nil
	}
	if err := ev.visit(1); err != nil {
		return nil, err
	}
	set, err := ev.e.Src.GetSet(ev.ctx, ref)
	if err == nil {
		set, err = checkSet(ref, set)
	}
	var fg object.FilterGroup
	switch {
	case err == nil:
		fg, _ = set.(object.FilterGroup)
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	ev.sets[ref.String()] = fg
	return fg, nil
}

// prefixRanges expands a route-set or as-set once per call, charging the sets
// its expansion reached against MaxVisited.
func (ev *filterEval) prefixRanges(n types.SetName) (RangeSet, error) {
	if rs, ok := ev.ranges[n.String()]; ok {
		return rs, nil
	}
	rs, reached, err := ev.e.expandRanges(ev.ctx, types.Ref(n), ev.e.maxPrefixes())
	if err != nil {
		return RangeSet{}, err
	}
	if err := ev.visit(reached); err != nil {
		return RangeSet{}, err
	}
	ev.ranges[n.String()] = rs
	return rs, nil
}

// asSet expands an as-set once per call, charging it as prefixRanges does.
func (ev *filterEval) asSet(n types.SetName) (ASNSet, error) {
	if s, ok := ev.asns[n.String()]; ok {
		return s, nil
	}
	s, reached, err := ev.e.expandAS(ev.ctx, types.Ref(n))
	if err != nil {
		return ASNSet{}, err
	}
	if err := ev.visit(reached); err != nil {
		return ASNSet{}, err
	}
	ev.asns[n.String()] = s
	return s, nil
}

// asExpr resolves an AS expression to the AS numbers it denotes. AND, OR and
// EXCEPT are the intersection, union and difference of the two sides, which is
// what RFC 2622 §5.6 means by them.
func (ev *filterEval) asExpr(e policy.ASExpr, depth int) (map[types.ASN]bool, error) {
	if depth > ev.e.maxDepth() {
		return nil, &SetTooLargeError{Name: ev.cur, Limit: LimitDepth, Max: ev.e.maxDepth(), Count: depth}
	}
	switch x := e.(type) {
	case nil:
		return map[types.ASN]bool{}, nil
	case policy.ASNum:
		if ev.skipAS(x.AS) {
			return map[types.ASN]bool{}, nil
		}
		return map[types.ASN]bool{x.AS: true}, nil
	case policy.ASSetRef:
		if ev.skipSet(x.Name) {
			return map[types.ASN]bool{}, nil
		}
		if isAnySet(x.Name) {
			return nil, &AnySetError{Name: x.Name}
		}
		set, err := ev.asSet(x.Name)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			ev.note(types.Ref(x.Name))
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
		l, err := ev.asExpr(x.L, depth+1)
		if err != nil {
			return nil, err
		}
		r, err := ev.asExpr(x.R, depth+1)
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
		if ev.e.Peer == 0 {
			return nil, unboundPeer(x.Template.String())
		}
		return ev.asExpr(policy.ASSetRef{Name: x.Template.Instantiate(ev.e.Peer)}, depth)
	}
	return nil, &NotEnumerableError{Term: "AS expression", Why: "unknown AS expression"}
}

// routesOf returns the routes the given ASes originate, as exact ranges with
// the term's operator composed in. The ASes are asked in numeric order, so the
// error a failing Source returns does not depend on map iteration.
func (ev *filterEval) routesOf(as map[types.ASN]bool, op types.RangeOperator) (rangeSetOf, error) {
	order := make([]types.ASN, 0, len(as))
	for a := range as {
		order = append(order, a)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	out := rangeSetOf{}
	for _, a := range order {
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
		if err := ev.cap(out, types.SetRef{}); err != nil {
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

// pairs calls fn for every range x of a and y of b whose prefixes nest — y's
// prefix is x's, an ancestor of it, or a descendant — which are the only pairs
// that can meet. Each x is tested against b's ranges at its own prefix's
// ancestors, looked up by prefix, and at its descendants, found by binary
// search in b sorted by address — not against all of b. The context is
// checked as it goes.
func (ev *filterEval) pairs(a, b rangeSetOf, fn func(x, y types.PrefixRange) error) error {
	byPrefix := make(map[netip.Prefix][]types.PrefixRange, len(b))
	for y := range b {
		byPrefix[y.Prefix()] = append(byPrefix[y.Prefix()], y)
	}
	prefixes := make([]netip.Prefix, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixLess(prefixes[i], prefixes[j]) })

	tests := 0
	meet := func(x types.PrefixRange, ys []types.PrefixRange) error {
		for _, y := range ys {
			if tests++; tests%ctxCheckEvery == 0 {
				if err := ev.ctx.Err(); err != nil {
					return err
				}
			}
			if err := fn(x, y); err != nil {
				return err
			}
		}
		return nil
	}
	for x := range a {
		p := x.Prefix()
		for bits := p.Bits(); bits >= 0; bits-- { // ancestors, and p itself
			if err := meet(x, byPrefix[netip.PrefixFrom(p.Addr(), bits).Masked()]); err != nil {
				return err
			}
		}
		last := lastAddr(p)
		i := sort.Search(len(prefixes), func(i int) bool { return !prefixLess(prefixes[i], p) })
		for ; i < len(prefixes) && prefixes[i].Addr().Compare(last) <= 0; i++ {
			if q := prefixes[i]; q.Bits() > p.Bits() { // a strict descendant
				if err := meet(x, byPrefix[q]); err != nil {
					return err
				}
			}
		}
	}
	return ev.ctx.Err()
}

// intersect returns the ranges denoting exactly what both sets denote,
// enforcing MaxPrefixes as the result grows.
func (ev *filterEval) intersect(a, b rangeSetOf) (rangeSetOf, error) {
	out := rangeSetOf{}
	err := ev.pairs(a, b, func(x, y types.PrefixRange) error {
		c, ok := x.Intersect(y)
		if !ok {
			return nil
		}
		if _, dup := out[c]; dup {
			return nil
		}
		out[c] = struct{}{}
		return ev.cap(out, types.SetRef{})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// prefixLess orders prefixes by address (IPv4 before IPv6), then length.
func prefixLess(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As16()
	off := 0
	if p.Addr().Is4() {
		off = 12
	}
	for i := off*8 + p.Bits(); i < 128; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	if p.Addr().Is4() {
		return netip.AddrFrom4([4]byte(a[12:]))
	}
	return netip.AddrFrom16(a)
}

// filterText renders a filter term for a diagnostic.
func filterText(f policy.Filter) string {
	if s, ok := f.(interface{ String() string }); ok {
		return s.String()
	}
	return "filter"
}
