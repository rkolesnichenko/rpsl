package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
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
	// Concurrency is how many sets, or ASes, may be fetched at once. Zero and
	// one both fetch one at a time. Discovery is breadth-first, and a whole
	// level is fetched together, so raising this hides a live registry's
	// latency without changing the result: the graph is built from the level's
	// answers in name order either way.
	Concurrency int
	// Exclude is what every expansion leaves out; see Exclusion.
	Exclude Exclusion
}

// Exclusion is what an expansion leaves out, as bgpq4's EXCEPT does: a set
// named here is never followed, fetched or reported missing, and an AS number
// named here adds nothing — not to an AS list and not its routes. It applies
// wherever an expansion meets a member (nested sets, AS members, indirect
// aut-num members, and the set and AS references inside a filter-set), but
// never to the set an Expand call names, which is expanded as asked; nor, in
// EvalFilter, to the terms of the filter passed in. A set excluded and also
// reachable another way stays out.
type Exclusion struct {
	Sets []types.SetName
	ASNs []types.ASN
}

// excluded is an Exclusion as sets, for lookups.
type excluded struct {
	sets map[string]bool
	asns map[types.ASN]bool
}

func (x excluded) set(n types.SetName) bool { return x.sets[n.String()] }
func (x excluded) as(a types.ASN) bool      { return x.asns[a] }

// excluded returns the expander's Exclusion as sets, built once per call.
func (e *Expander) excluded() excluded {
	var x excluded
	if len(e.Exclude.Sets) > 0 {
		x.sets = make(map[string]bool, len(e.Exclude.Sets))
		for _, n := range e.Exclude.Sets {
			x.sets[n.String()] = true
		}
	}
	if len(e.Exclude.ASNs) > 0 {
		x.asns = make(map[types.ASN]bool, len(e.Exclude.ASNs))
		for _, a := range e.Exclude.ASNs {
			x.asns[a] = true
		}
	}
	return x
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

// concurrency is how many fetches may be in flight, at least one.
func (e *Expander) concurrency() int {
	if e.Concurrency < 1 {
		return 1
	}
	return e.Concurrency
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
// Any other class of set returns an error wrapping ErrSetClass.
// Cycles are skipped (as in bgpq4). A missing top-level set returns an error
// wrapping ErrNotFound; missing nested sets expand to nothing and are listed by
// ASNSet.Missing. AFI only filters prefixes; ExpandAS is family-agnostic.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASNSet, error) {
	out, _, err := e.expandAS(ctx, n)
	return out, err
}

// expandAS is ExpandAS, also returning how many sets discovery reached.
func (e *Expander) expandAS(ctx context.Context, n types.SetName) (ASNSet, int, error) {
	if n.Class() != types.ClassAsSet {
		return ASNSet{}, 0, fmt.Errorf("resolve: ExpandAS %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return ASNSet{}, 0, err
	}
	out := newASSet()
	for _, nd := range g.nodes {
		for _, m := range members(nd.set) {
			if m.Kind == object.MemberAS && !g.ex.as(m.AS) {
				out.add(m.AS)
			}
		}
		for _, o := range nd.claims {
			if an, ok := o.(object.AutNum); ok && !g.ex.as(an.AS) {
				out.add(an.AS)
			}
		}
	}
	out.missing = g.missing
	return *out, g.size(), nil
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
	out, _, err := e.expandRanges(ctx, n, e.maxPrefixes())
	return out, err
}

// expandRanges is ExpandPrefixRanges with a cap of maxRanges ranges, also
// returning how many sets discovery reached.
func (e *Expander) expandRanges(ctx context.Context, n types.SetName, maxRanges int) (RangeSet, int, error) {
	if c := n.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
		return RangeSet{}, 0, fmt.Errorf("resolve: expand prefixes of %s: %w", n, ErrSetClass)
	}
	g, err := e.discover(ctx, n)
	if err != nil {
		return RangeSet{}, 0, err
	}
	if err := e.fetchRoutes(ctx, g); err != nil {
		return RangeSet{}, 0, err
	}
	v := &evaluator{e: e, ctx: ctx, g: g, out: newRangeSet(), done: map[evalState]bool{}, max: maxRanges}
	if err := v.walk(n, opStack{}); err != nil {
		return RangeSet{}, 0, err
	}
	v.out.missing = g.missing
	return *v.out, g.size(), nil
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
	ranges, _, err := e.expandRanges(ctx, n, math.MaxInt)
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
	ex      excluded                     // what the expansion leaves out
}

// size is how many sets discovery reached: those fetched and those missing.
func (g *setGraph) size() int { return len(g.nodes) + len(g.missing) }

type setNode struct {
	set    object.NamedSet
	claims []object.Object // indirect members that pass ClaimAllowed and the class rule
}

// discover fetches every set reachable from top breadth-first, so each set is
// fetched once and first reached at its shortest distance. It follows only the
// nested sets RFC 2622 allows (see nestable), so from an as-set only as-sets.
func (e *Expander) discover(ctx context.Context, top types.SetName) (*setGraph, error) {
	g := &setGraph{top: top, nodes: map[string]*setNode{}, ex: e.excluded()}
	seen := map[string]bool{top.String(): true}
	for level, depth := []types.SetName{top}, 0; len(level) > 0; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, n := range level {
			if isAnySet(n) {
				return nil, &AnySetError{Name: n}
			}
		}
		got, err := e.fetchLevel(ctx, level)
		if err != nil {
			return nil, err
		}
		var next []types.SetName
		for i, n := range level {
			res := got[i]
			if res.err != nil {
				if !errors.Is(res.err, ErrNotFound) {
					return nil, res.err
				}
				if depth == 0 {
					return nil, fmt.Errorf("expand %s: %w", top, ErrNotFound)
				}
				g.missing = append(g.missing, n)
				continue
			}
			g.nodes[n.String()] = &setNode{set: res.set, claims: res.claims}
			for _, name := range nestedNames(res.set) {
				if seen[name.String()] || g.ex.set(name) {
					continue
				}
				if depth+1 > e.maxDepth() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitDepth, Max: e.maxDepth(), Count: depth + 1}
				}
				if len(seen) >= e.maxVisited() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitVisited, Max: e.maxVisited(), Count: len(seen) + 1}
				}
				seen[name.String()] = true
				next = append(next, name)
			}
		}
		level = next
	}
	sort.Slice(g.missing, func(i, j int) bool { return g.missing[i].String() < g.missing[j].String() })
	return g, nil
}

// fetchResult is one set's worth of discovery: the set itself and the indirect
// members whose claims it honours, or the error that stopped it.
type fetchResult struct {
	set    object.NamedSet
	claims []object.Object
	err    error
}

// fetchLevel fetches every set of one breadth-first level, up to Concurrency at
// a time, and returns the results in the order the names were given — so the
// graph is built identically however many fetches ran in parallel.
func (e *Expander) fetchLevel(ctx context.Context, names []types.SetName) ([]fetchResult, error) {
	out := make([]fetchResult, len(names))
	if n := e.concurrency(); n > 1 && len(names) > 1 {
		sem := make(chan struct{}, n)
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, name types.SetName) {
				defer wg.Done()
				defer func() { <-sem }()
				out[i] = e.fetchOne(ctx, name)
			}(i, name)
		}
		wg.Wait()
		return out, ctx.Err()
	}
	for i, name := range names {
		out[i] = e.fetchOne(ctx, name)
	}
	return out, nil
}

// fetchOne fetches one set and the indirect members it honours. Every claim is
// re-checked here with ClaimAllowed, so a lenient Source cannot widen a set.
func (e *Expander) fetchOne(ctx context.Context, name types.SetName) fetchResult {
	set, err := e.Src.GetSet(ctx, name)
	if err == nil {
		set, err = checkSet(name, set)
	}
	if err != nil {
		return fetchResult{err: err}
	}
	var claims []object.Object
	if len(set.RefMntners()) > 0 {
		objs, err := e.Src.MembersByRef(ctx, set)
		if err != nil {
			return fetchResult{err: err}
		}
		for _, o := range objs {
			if o = value(o); claimClassOK(set, o) && ClaimAllowed(o, set) {
				claims = append(claims, o)
			}
		}
	}
	return fetchResult{set: set, claims: claims}
}

// checkSet returns set, as a value, if it is the set name asks for. A set
// whose class is not the one its name denotes ("route-set: AS-EVIL") is invalid
// data, and is treated as not found: expanded under its name's rules it would
// let an as-set pull in prefixes, or claims, that its class does not allow. A
// set of another name is a fault of the Source, which has answered a different
// question.
func checkSet(name types.SetName, set object.NamedSet) (object.NamedSet, error) {
	if set == nil {
		return nil, ErrNotFound // a Source that returns neither a set nor an error
	}
	set = setValue(set)
	if got := set.SetName(); got != name {
		return nil, fmt.Errorf("resolve: asked for %s, the Source returned %s", name, got)
	}
	if set.Class() != name.Class().String() {
		return nil, fmt.Errorf("resolve: %s is a %s: %w", name, set.Class(), ErrNotFound)
	}
	return set, nil
}

// setValue is value for a set: a pointer to a set class becomes the value, so
// type switches on the set see one form.
func setValue(set object.NamedSet) object.NamedSet {
	if v, ok := value(set).(object.NamedSet); ok {
		return v
	}
	return set
}

// ordered returns the graph's nodes in a stable order — the top set first,
// then the rest by canonical name — so a result built by walking them does not
// depend on map iteration order.
func (g *setGraph) ordered() []*setNode {
	names := make([]string, 0, len(g.nodes))
	for n := range g.nodes {
		if n != g.top.String() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	out := make([]*setNode, 0, len(g.nodes))
	if nd, ok := g.nodes[g.top.String()]; ok {
		out = append(out, nd)
	}
	for _, n := range names {
		out = append(out, g.nodes[n])
	}
	return out
}

// members returns the direct members of a set whose members are ASNs, prefix
// ranges and nested sets — an as-set or a route-set — and nothing for any
// other class, whose members are of a different kind entirely.
func members(set object.NamedSet) []object.SetMember {
	if s, ok := set.(object.Set); ok {
		return s.SetMembers()
	}
	return nil
}

// nestedNames returns the sets a set points to, following only the nestings
// RFC 2622 §5.1-5.6 allows for its class: an as-set lists as-sets; a route-set
// lists route-sets and as-sets (the routes their ASes originate); an rtr-set
// lists rtr-sets; a peering-set lists peering-sets. A nesting the RFC does not
// allow is invalid data and is not followed — a route-set inside an as-set
// would add prefixes that no route object backs. A filter-set has no member
// list at all; EvalFilter walks its expression instead.
func nestedNames(set object.NamedSet) []types.SetName {
	parent := set.SetName().Class()
	var out []types.SetName
	switch s := set.(type) {
	case object.Set:
		for _, m := range s.SetMembers() {
			if m.Kind == object.MemberSet && nestable(parent, m.Set.Class()) {
				out = append(out, m.Set)
			}
		}
	case object.RouterSet:
		for _, m := range s.SetRouters() {
			if m.Kind == object.RtrMemberSet && nestable(parent, m.Set.Class()) {
				out = append(out, m.Set)
			}
		}
	case object.PeeringGroup:
		for _, p := range s.SetPeerings() {
			if ref, ok := p.(policy.PeeringSetRef); ok && nestable(parent, ref.Name.Class()) {
				out = append(out, ref.Name)
			}
		}
	}
	return out
}

// nestable reports whether a set of class child may be a member of a set of
// class parent (RFC 2622 §5.1-5.6): an as-set lists as-sets; a route-set lists
// route-sets and as-sets (the routes their ASes originate); an rtr-set lists
// rtr-sets; a peering-set lists peering-sets. A filter-set is not here: it
// holds an expression rather than a member list, so EvalFilter walks it instead
// of discovery.
func nestable(parent, child types.SetClass) bool {
	switch parent {
	case types.ClassAsSet:
		return child == types.ClassAsSet
	case types.ClassRouteSet:
		return child == types.ClassRouteSet || child == types.ClassAsSet
	case types.ClassRtrSet:
		return child == types.ClassRtrSet
	case types.ClassPeeringSet:
		return child == types.ClassPeeringSet
	}
	return false
}

// isAnySet reports whether n is one of the names that denote the whole IRR.
func isAnySet(n types.SetName) bool {
	switch n.String() {
	case "AS-ANY", "RS-ANY", "RTRS-ANY", "PRNG-ANY", "FLTR-ANY":
		return true
	}
	return false
}

// claimClassOK applies RFC 2622 §5.1-5.5: an as-set's indirect members are
// aut-nums, a route-set's are routes, an rtr-set's are inet-rtrs. A
// peering-set and a filter-set have no mbrs-by-ref, so they accept no claims.
// The rule is keyed on the set's name, whose class checkSet has already
// matched against the object's.
func claimClassOK(set object.NamedSet, o object.Object) bool {
	switch set.SetName().Class() {
	case types.ClassAsSet:
		_, ok := o.(object.AutNum)
		return ok
	case types.ClassRouteSet:
		switch o.(type) {
		case object.Route, object.Route6:
			return true
		}
	case types.ClassRtrSet:
		_, ok := o.(object.InetRtr)
		return ok
	}
	return false
}

// fetchRoutes fetches, once per AS, the routes originated by every AS that is a
// member or an indirect aut-num member of a discovered set. An excluded AS is
// not fetched, so evaluation finds no routes for it.
func (e *Expander) fetchRoutes(ctx context.Context, g *setGraph) error {
	g.routes = map[types.ASN][]netip.Prefix{}
	// Collect the distinct ASes first, in a deterministic order, so the fetches
	// can run together without the result depending on which finished first.
	var need []types.ASN
	want := map[types.ASN]bool{}
	add := func(as types.ASN) {
		if !want[as] {
			want[as] = true
			need = append(need, as)
		}
	}
	for _, nd := range g.ordered() {
		for _, m := range members(nd.set) {
			if m.Kind == object.MemberAS && !g.ex.as(m.AS) {
				add(m.AS)
			}
		}
		for _, o := range nd.claims {
			if an, ok := o.(object.AutNum); ok && !g.ex.as(an.AS) {
				add(an.AS)
			}
		}
	}
	routes := make([][]netip.Prefix, len(need))
	errs := make([]error, len(need))
	if n := e.concurrency(); n > 1 && len(need) > 1 {
		sem := make(chan struct{}, n)
		var wg sync.WaitGroup
		for i, as := range need {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, as types.ASN) {
				defer wg.Done()
				defer func() { <-sem }()
				routes[i], errs[i] = e.Src.OriginatedRoutes(ctx, as, e.AFI)
			}(i, as)
		}
		wg.Wait()
	} else {
		for i, as := range need {
			routes[i], errs[i] = e.Src.OriginatedRoutes(ctx, as, e.AFI)
		}
	}
	for i, as := range need {
		if errs[i] != nil {
			return errs[i]
		}
		g.routes[as] = routes[i]
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
	for _, m := range members(nd.set) {
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
			if v.g.ex.set(m.Set) {
				continue // excluded, even the top set listing itself
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
