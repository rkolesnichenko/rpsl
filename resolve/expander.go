package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

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
// returns ErrSetTooLarge, naming the Limit, when breached. An Expander holds no
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

func (e *Expander) maxDepth() int {
	if e.MaxDepth > 0 {
		return e.MaxDepth
	}
	return defaultMaxDepth
}

func (e *Expander) maxPrefixes() int {
	if e.MaxPrefixes > 0 {
		return e.MaxPrefixes
	}
	return defaultMaxPrefixes
}

func (e *Expander) maxVisited() int {
	if e.MaxVisited > 0 {
		return e.MaxVisited
	}
	return defaultMaxVisited
}

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
// Cycles are skipped (as in bgpq4). A missing top-level set returns an error
// wrapping ErrNotFound; missing nested sets expand to nothing and are listed by
// ASSet.Missing. AFI only filters prefixes; ExpandAS is family-agnostic.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error) {
	g, err := e.discover(ctx, n, false)
	if err != nil {
		return ASSet{}, err
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
// ranges like /8^+ can be used. MaxPrefixes caps the number of ranges. Cycles
// are skipped unless re-entered under a different stack of operators, which
// returns ErrCyclicOperator. The AFI constraint applies throughout.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error) {
	g, err := e.discover(ctx, n, true)
	if err != nil {
		return RangeSet{}, err
	}
	if err := e.fetchRoutes(ctx, g); err != nil {
		return RangeSet{}, err
	}
	v := &evaluator{e: e, ctx: ctx, g: g, out: newRangeSet(), onStack: map[string]string{}, done: map[string]bool{}}
	if err := v.walk(n, nil); err != nil {
		return RangeSet{}, err
	}
	v.out.missing = g.missing
	return *v.out, nil
}

// ExpandPrefixes returns the concrete prefixes denoted by a route-set or as-set:
// ExpandPrefixRanges, materialized. MaxPrefixes caps the number of distinct
// prefixes and is enforced while enumerating, so a single ^0-32 range cannot
// exhaust memory, and duplicates are never charged against it.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error) {
	ranges, err := e.ExpandPrefixRanges(ctx, n)
	if err != nil {
		return PrefixSet{}, err
	}
	out := newPrefixSet()
	for _, r := range ranges.List() {
		if err := ctx.Err(); err != nil {
			return PrefixSet{}, err
		}
		for p := range r.All() {
			out.add(p)
			if out.Len() > e.maxPrefixes() {
				return PrefixSet{}, ErrSetTooLarge{Name: n, Limit: LimitPrefixes, Count: out.Len()}
			}
		}
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
// fetched once and first reached at its shortest distance. ExpandAS follows only
// as-set members; prefix expansions also follow route-sets.
func (e *Expander) discover(ctx context.Context, top types.SetName, prefixes bool) (*setGraph, error) {
	type item struct {
		name  types.SetName
		depth int
	}
	g := &setGraph{top: top, nodes: map[string]*setNode{}}
	seen := map[string]bool{top.Canonical(): true}
	for queue := []item{{top, 0}}; len(queue) > 0; queue = queue[1:] {
		it := queue[0]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if isAnySet(it.name) {
			return nil, ErrAnySet{Name: it.name}
		}
		set, err := e.Src.GetSet(ctx, it.name)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if it.depth == 0 {
				return nil, fmt.Errorf("resolve: %s: %w", top, ErrNotFound)
			}
			g.missing = append(g.missing, it.name)
			continue
		}
		nd := &setNode{set: set}
		g.nodes[it.name.Canonical()] = nd
		if refs := set.RefMntners(); len(refs) > 0 {
			objs, err := e.Src.MembersByRef(ctx, it.name, refs)
			if err != nil {
				return nil, err
			}
			for _, o := range objs {
				if claimClassOK(set, o) && ClaimAllowed(o, it.name, refs) {
					nd.claims = append(nd.claims, o)
				}
			}
		}
		for _, m := range set.SetMembers() {
			if m.Kind != object.MemberSet || !follows(m.Set, prefixes) || seen[m.Set.Canonical()] {
				continue
			}
			if it.depth+1 > e.maxDepth() {
				return nil, ErrSetTooLarge{Name: top, Limit: LimitDepth, Count: it.depth + 1}
			}
			if len(seen) >= e.maxVisited() {
				return nil, ErrSetTooLarge{Name: top, Limit: LimitVisited, Count: len(seen) + 1}
			}
			seen[m.Set.Canonical()] = true
			queue = append(queue, item{m.Set, it.depth + 1})
		}
	}
	sort.Slice(g.missing, func(i, j int) bool { return g.missing[i].Canonical() < g.missing[j].Canonical() })
	return g, nil
}

// follows reports whether discovery traverses a nested set of this class.
func follows(n types.SetName, prefixes bool) bool {
	return n.Class() == types.AsSet || (prefixes && n.Class() == types.RouteSet)
}

// isAnySet reports whether n is AS-ANY or RS-ANY.
func isAnySet(n types.SetName) bool {
	c := n.Canonical()
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

// evaluator builds a RangeSet from a discovered graph. Each set is walked once
// per distinct stack of range operators leading to it (ops, outermost first).
type evaluator struct {
	e       *Expander
	ctx     context.Context
	g       *setGraph
	out     *RangeSet
	onStack map[string]string // canonical set on the current path -> its opsKey
	done    map[string]bool   // canonical set + "|" + opsKey, fully walked
	visits  int
}

func opsKey(ops []types.RangeOperator) string {
	parts := make([]string, len(ops))
	for i, o := range ops {
		parts[i] = o.String()
	}
	return strings.Join(parts, ",")
}

func (v *evaluator) walk(name types.SetName, ops []types.RangeOperator) error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	canon, key := name.Canonical(), opsKey(ops)
	if v.visits++; v.visits > v.e.maxVisited() {
		return ErrSetTooLarge{Name: v.g.top, Limit: LimitVisited, Count: v.visits}
	}
	nd := v.g.nodes[canon]
	v.onStack[canon] = key
	defer delete(v.onStack, canon)

	for _, m := range nd.set.SetMembers() {
		switch m.Kind {
		case object.MemberPrefixRange:
			if err := v.add(m.Range, ops); err != nil {
				return err
			}
		case object.MemberAS:
			if err := v.addRoutes(v.g.routes[m.AS], appendOp(ops, m.Op)); err != nil {
				return err
			}
		case object.MemberSet:
			child := m.Set.Canonical()
			if _, ok := v.g.nodes[child]; !ok {
				continue // missing (reported) or a class discovery does not follow
			}
			childOps := appendOp(ops, m.Op)
			childKey := opsKey(childOps)
			if stackKey, on := v.onStack[child]; on {
				if stackKey != childKey {
					return ErrCyclicOperator{Set: name, Member: m.Raw}
				}
				continue // re-entered under the same operators: already contributing
			}
			if v.done[child+"|"+childKey] {
				continue
			}
			if err := v.walk(m.Set, childOps); err != nil {
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
	v.done[canon+"|"+key] = true
	return nil
}

// appendOp returns ops extended by op (a fresh slice), or ops if op is absent.
func appendOp(ops []types.RangeOperator, op types.RangeOperator) []types.RangeOperator {
	if op.IsZero() {
		return ops
	}
	return append(ops[:len(ops):len(ops)], op)
}

// addRoutes adds each route as an exact range under ops.
func (v *evaluator) addRoutes(routes []netip.Prefix, ops []types.RangeOperator) error {
	for _, p := range routes {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		exact := types.PrefixRange{Prefix: p, Op: types.RangeExact, Lo: uint8(p.Bits()), Hi: uint8(p.Bits())}
		if err := v.add(exact, ops); err != nil {
			return err
		}
	}
	return nil
}

// add applies ops to r, innermost first, and records the result if it survives
// the operators and the AFI constraint.
func (v *evaluator) add(r types.PrefixRange, ops []types.RangeOperator) error {
	for i := len(ops) - 1; i >= 0; i-- {
		var ok bool
		if r, ok = ops[i].Apply(r); !ok {
			return nil // the operator deletes this prefix (RFC 2622 §5.2)
		}
	}
	if !v.e.afiAllows(r.Prefix) {
		return nil
	}
	v.out.add(r)
	if v.out.Len() > v.e.maxPrefixes() {
		return ErrSetTooLarge{Name: v.g.top, Limit: LimitPrefixes, Count: v.out.Len()}
	}
	return nil
}
