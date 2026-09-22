package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

const (
	defaultMaxDepth    = 32
	defaultMaxPrefixes = 1 << 20
	defaultMaxVisited  = 1 << 17 // 131 072 unique sets — well above any real graph
)

// Expander expands set references into concrete ASNs and prefixes. It is pure:
// all I/O is delegated to Src, all limits are explicit, and every traversal is
// context-cancellable. A zero Expander (except Src) uses the default limits
// MaxDepth=32, MaxPrefixes=1<<20 (1,048,576), MaxVisited=1<<17 (131,072); each
// returns SetTooLargeError, naming the Limit, when breached. An Expander holds no
// per-call state, so one value may serve concurrent expansions.
//
// Expansion runs in two phases. Discovery walks the set graph breadth-first
// from the named set, fetching every reachable set once (so a set's depth is
// its shortest nesting distance, and the result never depends on member order)
// along with its indirect members and, for prefix expansions, each member AS's
// routes. Evaluation then builds the result from that graph without further I/O,
// applying range operators along each path (RFC 2622 §5.2).
//
// IRR source precedence is the Source's concern (e.g. irrd.Source.Sources,
// NewMemSource's sourcePrecedence).
type Expander struct {
	Src         Source
	MaxDepth    int       // cap on a set's shortest nesting distance from the top (default 32)
	MaxPrefixes int       // cap on output prefixes, or ranges for ExpandPrefixRanges (default 1<<20)
	MaxVisited  int       // cap on distinct sets fetched and on evaluation visits (default 1<<17)
	AFI         types.AFI // address-family constraint; Unspecified/Any = both
}

// limit applies the rule every cap follows: zero means def, negative unlimited.
func limit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return math.MaxInt
	}
	return v
}

// ctxCheckEvery is how many prefixes ExpandPrefixes enumerates between checks
// of its context.
const ctxCheckEvery = 4096

func (e *Expander) maxDepth() int { return limit(e.MaxDepth, defaultMaxDepth) }

func (e *Expander) maxPrefixes() int { return limit(e.MaxPrefixes, defaultMaxPrefixes) }

func (e *Expander) maxVisited() int { return limit(e.MaxVisited, defaultMaxVisited) }

// afiAllows reports whether a prefix is admitted under the configured AFI.
func (e *Expander) afiAllows(p netip.Prefix) bool {
	switch e.AFI {
	case types.AFIv4:
		return p.Addr().Is4()
	case types.AFIv6:
		return p.Addr().Is6()
	default: // Unspecified / Any
		return true
	}
}

// ExpandAS returns the ASNs denoted by an as-set: the ASN members of every
// as-set reachable from it plus their indirect (mbrs-by-ref) aut-num members.
// Any other class of set returns an error wrapping ErrSetClass.
// Cycles are skipped (as in bgpq4). A missing top-level set returns an error
// wrapping ErrNotFound; missing nested sets expand to nothing and are listed by
// ASNSet.Missing. AFI only filters prefixes; ExpandAS is family-agnostic.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASNSet, error) {
	if n.Class() != types.ClassAsSet {
		return ASNSet{}, fmt.Errorf("resolve: ExpandAS %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return ASNSet{}, err
	}
	out := newASSet()
	for _, nd := range g.nodes {
		for _, m := range nd.set.SetMembers() {
			if m.Kind == object.MemberAS {
				out.add(m.AS)
			}
		}
		for _, o := range nd.claims {
			if an, ok := o.(object.AutNum); ok {
				out.add(an.AS)
			}
		}
	}
	out.missing = g.missing
	return *out, nil
}

// ExpandPrefixRanges returns the prefix ranges denoted by a route-set or as-set,
// before materialization: prefix-range members, the routes of member ASes and
// as-sets (RFC 2622 §5.2), nested route-sets, and indirect route members, with
// range operators on members ("RS-FOO^+", "AS1^24") composed along each path.
// It is what bgpq4 emits as le/ge bounds, and the only form in which sets with
// ranges like /8^+ can be used. MaxPrefixes caps the number of ranges. Cycles,
// including ones through range operators, resolve to the RFC's least fixpoint
// (RS-A = X ∪ RS-B^+, RS-B = RS-A gives X ∪ X^+). The AFI constraint applies
// throughout. A set of another class returns an error wrapping ErrSetClass.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error) {
	return e.expandRanges(ctx, n, e.maxPrefixes())
}

// expandRanges is ExpandPrefixRanges with a cap of maxRanges ranges.
func (e *Expander) expandRanges(ctx context.Context, n types.SetName, maxRanges int) (RangeSet, error) {
	if c := n.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
		return RangeSet{}, fmt.Errorf("resolve: expand prefixes of %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return RangeSet{}, err
	}
	if err := e.fetchRoutes(ctx, g); err != nil {
		return RangeSet{}, err
	}
	v := &evaluator{e: e, ctx: ctx, g: g, out: newRangeSet(), done: map[evalState]bool{}, max: maxRanges}
	if err := v.walk(n, opStack{}); err != nil {
		return RangeSet{}, err
	}
	v.out.missing = g.missing
	return *v.out, nil
}

// ExpandPrefixes returns the concrete prefixes denoted by a route-set or as-set:
// ExpandPrefixRanges, materialized. MaxPrefixes caps the number of distinct
// prefixes and is enforced while enumerating, so a single ^0-32 range cannot
// exhaust memory, and duplicates are never charged against it. The context is
// checked while enumerating, too, so even a range as large as the cap allows
// stops promptly when ctx is cancelled.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error) {
	// Ranges are not capped here: overlapping ones ("/31" and "/31^+") are
	// several ranges but no more prefixes, and only distinct prefixes count.
	// The walk that finds them is bounded by MaxVisited.
	ranges, err := e.expandRanges(ctx, n, math.MaxInt)
	if err != nil {
		return PrefixSet{}, err
	}
	out := newPrefixSet()
	enumerated := 0
	for _, r := range ranges.List() {
		for p := range r.All() {
			if enumerated++; enumerated%ctxCheckEvery == 0 && ctx.Err() != nil {
				return PrefixSet{}, ctx.Err()
			}
			out.add(p)
			if out.Len() > e.maxPrefixes() {
				return PrefixSet{}, &SetTooLargeError{Name: n, Limit: LimitPrefixes, Max: e.maxPrefixes(), Count: out.Len()}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return PrefixSet{}, err
	}
	out.missing = ranges.missing
	return *out, nil
}

// ---- discovery ----

// setGraph is the part of the IRR reachable from one top-level set.
type setGraph struct {
	top     types.SetName
	nodes   map[string]*setNode          // canonical name -> fetched set
	missing []types.SetName              // nested sets that were not found
	routes  map[types.ASN][]netip.Prefix // originated routes (prefix expansions only)
}

type setNode struct {
	set    object.Set
	claims []object.Object // indirect members that pass ClaimAllowed and the class rule
}

// discover fetches every set reachable from top breadth-first, so each set is
// fetched once and first reached at its shortest distance. It follows only the
// nested sets RFC 2622 allows (see nestable), so from an as-set only as-sets.
func (e *Expander) discover(ctx context.Context, top types.SetName) (*setGraph, error) {
	type item struct {
		name  types.SetName
		depth int
	}
	g := &setGraph{top: top, nodes: map[string]*setNode{}}
	seen := map[string]bool{top.String(): true}
	for queue := []item{{top, 0}}; len(queue) > 0; queue = queue[1:] {
		it := queue[0]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if isAnySet(it.name) {
			return nil, &AnySetError{Name: it.name}
		}
		set, err := e.Src.GetSet(ctx, it.name)
		if err == nil && set == nil {
			err = ErrNotFound // a Source that returns neither a set nor an error
		}
		if set != nil {
			set = setValue(set)
		}
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if it.depth == 0 {
				return nil, fmt.Errorf("expand %s: %w", top, ErrNotFound)
			}
			g.missing = append(g.missing, it.name)
			continue
		}
		nd := &setNode{set: set}
		g.nodes[it.name.String()] = nd
		if len(set.RefMntners()) > 0 {
			objs, err := e.Src.MembersByRef(ctx, set)
			if err != nil {
				return nil, err
			}
			for _, o := range objs {
				if o = value(o); claimClassOK(set, o) && ClaimAllowed(o, set) {
					nd.claims = append(nd.claims, o)
				}
			}
		}
		for _, m := range set.SetMembers() {
			if m.Kind != object.MemberSet || !nestable(it.name.Class(), m.Set.Class()) || seen[m.Set.String()] {
				continue
			}
			if it.depth+1 > e.maxDepth() {
				return nil, &SetTooLargeError{Name: top, Limit: LimitDepth, Max: e.maxDepth(), Count: it.depth + 1}
			}
			if len(seen) >= e.maxVisited() {
				return nil, &SetTooLargeError{Name: top, Limit: LimitVisited, Max: e.maxVisited(), Count: len(seen) + 1}
			}
			seen[m.Set.String()] = true
			queue = append(queue, item{m.Set, it.depth + 1})
		}
	}
	sort.Slice(g.missing, func(i, j int) bool { return g.missing[i].String() < g.missing[j].String() })
	return g, nil
}

// setValue is value for a Set: a pointer to an AsSet or RouteSet becomes the
// value, so type switches on the set see one form.
func setValue(set object.Set) object.Set {
	if v, ok := value(set).(object.Set); ok {
		return v
	}
	return set
}

// nestable reports whether a set of class child may be a member of a set of
// class parent (RFC 2622 §5.1-5.2): an as-set lists as-sets; a route-set lists
// route-sets and as-sets (the routes their ASes originate). Other nestings are
// invalid data and are not followed: a route-set inside an as-set would add
// prefixes that no route object backs.
func nestable(parent, child types.SetClass) bool {
	switch parent {
	case types.ClassAsSet:
		return child == types.ClassAsSet
	case types.ClassRouteSet:
		return child == types.ClassRouteSet || child == types.ClassAsSet
	}
	return false
}

// isAnySet reports whether n is AS-ANY or RS-ANY.
func isAnySet(n types.SetName) bool {
	c := n.String()
	return c == "AS-ANY" || c == "RS-ANY"
}

// claimClassOK applies RFC 2622 §5.1-5.2: an as-set's indirect members are
// aut-nums, a route-set's are routes.
func claimClassOK(set object.Set, o object.Object) bool {
	switch set.(type) {
	case object.AsSet:
		_, ok := o.(object.AutNum)
		return ok
	case object.RouteSet:
		switch o.(type) {
		case object.Route, object.Route6:
			return true
		}
	}
	return false
}

// fetchRoutes fetches, once per AS, the routes originated by every AS that is a
// member or an indirect aut-num member of a discovered set.
func (e *Expander) fetchRoutes(ctx context.Context, g *setGraph) error {
	g.routes = map[types.ASN][]netip.Prefix{}
	need := func(as types.ASN) error {
		if _, ok := g.routes[as]; ok {
			return nil
		}
		routes, err := e.Src.OriginatedRoutes(ctx, as, e.AFI)
		if err != nil {
			return err
		}
		g.routes[as] = routes
		return nil
	}
	for _, nd := range g.nodes {
		for _, m := range nd.set.SetMembers() {
			if m.Kind == object.MemberAS {
				if err := need(m.AS); err != nil {
					return err
				}
			}
		}
		for _, o := range nd.claims {
			if an, ok := o.(object.AutNum); ok {
				if err := need(an.AS); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ---- evaluation ----

// evaluator builds a RangeSet from a discovered graph. Its states are (set,
// operator stack) pairs: a set reached under the operators of the path leading
// to it. Each state is walked once, and a set met again under an equivalent
// stack is the same state, so cycles — with or without operators — terminate,
// and the result is the union over every reachable state: RFC 2622's least
// fixpoint of the set definitions.
type evaluator struct {
	e      *Expander
	ctx    context.Context
	g      *setGraph
	out    *RangeSet
	done   map[evalState]bool
	visits int
	max    int // cap on ranges
}

type evalState struct {
	set string // canonical set name
	ops opStack
}

func (v *evaluator) walk(name types.SetName, ops opStack) error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	canon := name.String()
	v.done[evalState{canon, ops}] = true
	if v.visits++; v.visits > v.e.maxVisited() {
		return &SetTooLargeError{Name: v.g.top, Limit: LimitVisited, Max: v.e.maxVisited(), Count: v.visits}
	}
	nd := v.g.nodes[canon]
	for _, m := range nd.set.SetMembers() {
		switch m.Kind {
		case object.MemberPrefixRange:
			if err := v.add(m.Range, &ops); err != nil {
				return err
			}
		case object.MemberAS:
			if err := v.addRoutes(v.g.routes[m.AS], ops.push(m.Op)); err != nil {
				return err
			}
		case object.MemberSet:
			if !nestable(name.Class(), m.Set.Class()) {
				continue // e.g. a route-set listed in an as-set, even if reachable elsewhere
			}
			if _, ok := v.g.nodes[m.Set.String()]; !ok {
				continue // missing (reported)
			}
			child := ops.push(m.Op)
			if v.done[evalState{m.Set.String(), child}] {
				continue // already walked, or on the current path: its ranges are already counted
			}
			if err := v.walk(m.Set, child); err != nil {
				return err
			}
		}
	}
	for _, o := range nd.claims {
		var err error
		switch t := o.(type) {
		case object.Route:
			err = v.addRoutes([]netip.Prefix{t.Prefix}, ops)
		case object.Route6:
			err = v.addRoutes([]netip.Prefix{t.Prefix}, ops)
		case object.AutNum:
			err = v.addRoutes(v.g.routes[t.AS], ops)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// addRoutes adds each route as an exact range under ops.
func (v *evaluator) addRoutes(routes []netip.Prefix, ops opStack) error {
	for _, p := range routes {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		exact, _ := types.NewPrefixRange(p, p.Bits(), p.Bits())
		if err := v.add(exact, &ops); err != nil {
			return err
		}
	}
	return nil
}

// add applies ops to r and records the result in canonical form if it survives
// the operators and the AFI constraint and denotes at least one prefix.
func (v *evaluator) add(r types.PrefixRange, ops *opStack) error {
	r, ok := ops.apply(r)
	if !ok || !v.e.afiAllows(r.Prefix()) {
		return nil
	}
	v.out.add(r)
	if v.out.Len() > v.max {
		return &SetTooLargeError{Name: v.g.top, Limit: LimitPrefixes, Max: v.max, Count: v.out.Len()}
	}
	return nil
}
