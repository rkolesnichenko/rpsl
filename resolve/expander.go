package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

const (
	defaultMaxDepth     = 32
	defaultMaxPrefixes  = 1 << 20
	defaultMaxVisited   = 1 << 17 // 131 072 unique sets — well above any real graph
	defaultMaxConjuncts = 1 << 12 // 4 096 — well above any router config's route-map entries
)

// Expander expands set references into concrete ASNs and prefixes. It is pure:
// all I/O is delegated to Src, all limits are explicit, and every traversal is
// context-cancellable. A zero Expander (except Src) uses the default limits
// MaxDepth=32, MaxPrefixes=1<<20 (1,048,576), MaxVisited=1<<17 (131,072),
// MaxConjuncts=1<<12 (4,096); each returns SetTooLargeError, naming the Limit,
// when breached. An Expander holds no per-call state, so one value may serve
// concurrent expansions.
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
	Src          Source
	MaxDepth     int       // cap on a set's shortest nesting distance from the top (default 32)
	MaxPrefixes  int       // cap on output prefixes, or ranges for ExpandPrefixRanges (default 1<<20)
	MaxVisited   int       // cap on distinct sets fetched and on evaluation visits (default 1<<17)
	MaxConjuncts int       // cap on the conjuncts of any disjunction, and the tests of any conjunct, NormalizeFilter builds (default 1<<12)
	AFI          types.AFI // address-family constraint; Unspecified/Any = both
	// Concurrency is how many sets, or ASes, may be fetched at once. Zero and
	// one both fetch one at a time. Discovery is breadth-first, and a whole
	// level is fetched together, so raising this hides a live registry's
	// latency without changing the result: the graph is built from a level's
	// answers in the order of its references either way.
	Concurrency int
	// Exclude is what every expansion leaves out; see Exclusion.
	Exclude Exclusion
	// Peer binds PeerAS for EvalFilter and NormalizeFilter: PeerAS denotes
	// Peer's routes, and a set template (AS1:AS-CUST:PeerAS, in a filter, an AS
	// expression or an AS-path regexp) the set it names for Peer. Zero leaves
	// them unbound: such a term is a *NotEnumerableError wrapping
	// ErrUnboundPeer. It binds inside filter-sets too. AS0 is never a peer.
	Peer types.ASN
	// Memo, when set, answers NormalizeFilter and ExpandAS from a FilterMemo
	// shared with other Expanders (see FilterMemo for which may share one).
	// It is ignored when Exclude is set. EvalFilter and the other expansions
	// do not read it.
	Memo *FilterMemo
}

// Exclusion is what an expansion leaves out, as bgpq4's EXCEPT does: a set
// named here is never followed, fetched or reported missing, and an AS number
// named here adds nothing — not to an AS list and not its routes. It applies
// wherever an expansion meets a member (nested sets, AS members, indirect
// aut-num members, and the set and AS references inside a filter-set), but
// never to the set an Expand call names, which is expanded as asked; nor, in
// EvalFilter, to the terms of the filter passed in. A set excluded and also
// reachable another way stays out. NormalizeFilter applies it only to the
// positive prefix literals of a filter: under NOT, and in every AS-path
// regexp's sets, an excluded set or AS is not left out, so exclusion never
// widens what a filter accepts. peval never applies it to peering or router
// matching, only to clause filters.
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

func (e *Expander) maxConjuncts() int { return limit(e.MaxConjuncts, defaultMaxConjuncts) }

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
// A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the
// scope does not cascade to what it lists.
//
// With Expander.Memo set and no Exclude, an answer may come from the memo; it
// is the answer ExpandAS would compute (see FilterMemo).
func (e *Expander) ExpandAS(ctx context.Context, ref types.SetRef) (ASNSet, error) {
	memo := e.Memo != nil && len(e.Exclude.Sets) == 0 && len(e.Exclude.ASNs) == 0
	var k filterKey
	if memo {
		k = filterKey{asns: true, text: ref.String(), depth: e.maxDepth(), visited: e.maxVisited()}
		if a, ok := e.Memo.get(k); ok {
			return a.asns, a.err
		}
	}
	out, _, err := e.expandAS(ctx, ref, false)
	if memo && (err == nil || ctx.Err() == nil) {
		e.Memo.putASNs(k, out, err)
	}
	return out, err
}

// expandAS is ExpandAS, also returning how many references discovery checked
// (setGraph.size), which the caller charges against MaxVisited. With anyLeaf
// (an as-set named in an AS-path regexp), a set that reaches AS-ANY is the set
// of every AS (ASNSet.Any), with nothing missing, rather than an *AnySetError.
// Either way discovery stops after the level that reaches AS-ANY; see discover.
func (e *Expander) expandAS(ctx context.Context, ref types.SetRef, anyLeaf bool) (ASNSet, int, error) {
	if ref.Name().Class() != types.ClassAsSet {
		return ASNSet{}, 0, fmt.Errorf("resolve: ExpandAS %s: %w", ref, ErrSetClass)
	}
	g, err := e.discover(ctx, ref, anyLeaf)
	if err != nil {
		return ASNSet{}, 0, err
	}
	if len(g.any) > 0 {
		// Every AS: nothing a missing set could have added changes that, so
		// none is reported (as peval.inASSet does for a peering).
		return NewAnyASNSet(), g.size(), nil
	}
	out := newASSet()
	for _, nd := range g.nodes {
		for _, m := range members(nd.set) {
			if m.Kind == object.MemberAS && !g.ex.as(m.AS) {
				out.add(m.AS)
			}
		}
		for _, o := range nd.claims {
			if an, ok := o.(*object.AutNum); ok && !g.ex.as(an.AS) {
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
// A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the
// scope does not cascade to what it lists.
func (e *Expander) ExpandPrefixRanges(ctx context.Context, ref types.SetRef) (RangeSet, error) {
	out, _, err := e.expandRanges(ctx, ref, e.maxPrefixes())
	return out, err
}

// expandRanges is ExpandPrefixRanges with a cap of maxRanges ranges, also
// returning how many sets discovery reached.
func (e *Expander) expandRanges(ctx context.Context, ref types.SetRef, maxRanges int) (RangeSet, int, error) {
	if c := ref.Name().Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
		return RangeSet{}, 0, fmt.Errorf("resolve: expand prefixes of %s: %w", ref, ErrSetClass)
	}
	g, err := e.discover(ctx, ref, false)
	if err != nil {
		return RangeSet{}, 0, err
	}
	if err := e.fetchRoutes(ctx, g); err != nil {
		return RangeSet{}, 0, err
	}
	v := &evaluator{e: e, ctx: ctx, g: g, out: newRangeSet(), done: map[evalState]bool{}, max: maxRanges}
	if err := v.walk(ref, opStack{}); err != nil {
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
// A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the
// scope does not cascade to what it lists.
func (e *Expander) ExpandPrefixes(ctx context.Context, ref types.SetRef) (PrefixSet, error) {
	// Ranges are not capped here: overlapping ones ("/31" and "/31^+") are
	// several ranges but no more prefixes, and only distinct prefixes count.
	// The walk that finds them is bounded by MaxVisited.
	ranges, _, err := e.expandRanges(ctx, ref, math.MaxInt)
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
				return PrefixSet{}, &SetTooLargeError{Name: ref, Limit: LimitPrefixes, Max: e.maxPrefixes(), Count: out.Len()}
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
	top     types.SetRef
	nodes   map[types.SetRef]*setNode    // fetched sets, by the reference that reached them
	missing []types.SetRef               // nested sets that were not found
	any     []types.SetRef               // references to AS-ANY reached, never fetched (discover's anyLeaf only)
	routes  map[types.ASN][]netip.Prefix // originated routes (prefix expansions only)
	ex      excluded                     // what the expansion leaves out
	reached int                          // references that passed discovery's checks (see size)
	levels  [][]types.SetRef             // the fetched sets, one breadth-first level each, in discovery order (fetchClaims)
}

// size is how many references passed discovery's checks: every set fetched
// or missing, and for a graph reaching AS-ANY also the references to AS-ANY
// and the unfetched ones on the level after the one that reached it. Without
// AS-ANY it is len(nodes)+len(missing).
func (g *setGraph) size() int { return g.reached }

type setNode struct {
	set    object.NamedSet
	claims []object.Object // indirect members that pass ClaimAllowed and the class rule; filled by fetchClaims
}

// discover fetches every set reachable from top breadth-first, so each set is
// fetched once and first reached at its shortest distance. It follows only the
// nested sets RFC 2622 allows (see nestable), so from an as-set only as-sets. A
// reference scoped to a registry is its own node: RIPE::AS-X and AS-X are
// fetched separately (the scope selects where, draft §2.3, and never
// cascades: a node's nested references come from its own object).
//
// A top that names the whole IRR (isAnySet) is an *AnySetError. A nested
// reference to one passes the same checks as any other (seen, exclusion,
// MaxDepth, MaxVisited) and is never fetched — an object in the Source under
// that name is never read. Discovery stops after the level whose processing
// reaches one: every reference on that level is checked, nothing past it is
// fetched, since whatever lies deeper cannot change "every AS". Without
// anyLeaf that is an *AnySetError; with it, the references are recorded in the
// graph's any list and the graph is returned. Only an as-set's expansion for
// an AS-path regexp sets anyLeaf (expandAS); both modes stop at the same
// point, so a peering and a regexp naming one set agree on MaxDepth.
//
// Sets are fetched without their indirect members. Only a discovery that ends
// without refusing and without reaching AS-ANY fetches them (fetchClaims), so
// an answer that never needs the claims never asks for them and cannot fail
// on them. Claims add no nested references, so the graph, the limits and the
// answer are the same as fetching them with each set.
func (e *Expander) discover(ctx context.Context, top types.SetRef, anyLeaf bool) (*setGraph, error) {
	if isAnySet(top.Name()) {
		return nil, &AnySetError{Name: top.Name()}
	}
	g := &setGraph{top: top, nodes: map[types.SetRef]*setNode{}, ex: e.excluded()}
	seen := map[types.SetRef]bool{top: true}
	for level, depth := []types.SetRef{top}, 0; len(level) > 0; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		got, err := e.fetchLevel(ctx, level)
		if err != nil {
			return nil, err
		}
		var next, fetched []types.SetRef
		var anyRef types.SetRef // the first reference to AS-ANY this level reaches
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
			g.nodes[n] = &setNode{set: res.set}
			fetched = append(fetched, n)
			for _, ref := range nestedRefs(res.set) {
				if seen[ref] || g.ex.set(ref.Name()) {
					continue
				}
				if depth+1 > e.maxDepth() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitDepth, Max: e.maxDepth(), Count: depth + 1}
				}
				if len(seen) >= e.maxVisited() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitVisited, Max: e.maxVisited(), Count: len(seen) + 1}
				}
				seen[ref] = true
				if isAnySet(ref.Name()) {
					if anyRef.IsZero() {
						anyRef = ref
					}
					if anyLeaf {
						g.any = append(g.any, ref)
					}
					continue
				}
				next = append(next, ref)
			}
		}
		g.levels = append(g.levels, fetched)
		if !anyRef.IsZero() {
			if !anyLeaf {
				return nil, &AnySetError{Name: anyRef.Name()}
			}
			break
		}
		level = next
	}
	sort.Slice(g.missing, func(i, j int) bool { return g.missing[i].String() < g.missing[j].String() })
	g.reached = len(seen)
	if len(g.any) == 0 {
		if err := e.fetchClaims(ctx, g); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// fetchResult is one set's worth of discovery: the set itself, or the error
// that stopped it.
type fetchResult struct {
	set object.NamedSet
	err error
}

// fetchLevel fetches every set of one breadth-first level, up to Concurrency at
// a time, and returns the results in the order the refs were given — so the
// graph is built identically however many fetches ran in parallel.
func (e *Expander) fetchLevel(ctx context.Context, refs []types.SetRef) ([]fetchResult, error) {
	out := make([]fetchResult, len(refs))
	if e.each(len(refs), func(i int) { out[i] = e.fetchOne(ctx, refs[i]) }) {
		return out, ctx.Err()
	}
	return out, nil
}

// each calls do(i) for every i in [0, n), up to Concurrency at a time, and
// returns once every call has, reporting whether they ran concurrently. Each
// call writes only its own index, so what the caller reads afterwards does
// not depend on the order they finished in.
func (e *Expander) each(n int, do func(i int)) (concurrent bool) {
	c := e.concurrency()
	if c <= 1 || n <= 1 {
		for i := range n {
			do(i)
		}
		return false
	}
	sem := make(chan struct{}, c)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			do(i)
		}()
	}
	wg.Wait()
	return true
}

// fetchOne fetches one set, without its indirect members (see fetchClaims).
func (e *Expander) fetchOne(ctx context.Context, ref types.SetRef) fetchResult {
	set, err := e.Src.GetSet(ctx, ref)
	if err == nil {
		set, err = checkSet(ref, set)
	}
	if err != nil {
		return fetchResult{err: err}
	}
	return fetchResult{set: set}
}

// fetchClaims fills in the indirect members each node of a discovered graph
// honours, level by level in discovery order, a level's fetches running
// together as in fetchLevel. It returns the first error in that order, and
// the context's error if it was cancelled during a level, so a cancelled
// expansion is never answered without its claims.
func (e *Expander) fetchClaims(ctx context.Context, g *setGraph) error {
	for _, level := range g.levels {
		errs := make([]error, len(level))
		e.each(len(level), func(i int) {
			nd := g.nodes[level[i]]
			nd.claims, errs[i] = e.claimsOf(ctx, nd.set)
		})
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// claimsOf returns the indirect members set honours. Every claim is re-checked
// here with ClaimAllowed, so a lenient Source cannot widen a set.
func (e *Expander) claimsOf(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	if len(set.RefMntners()) == 0 {
		return nil, nil
	}
	objs, err := e.Src.MembersByRef(ctx, set)
	if err != nil {
		return nil, err
	}
	var claims []object.Object
	for _, o := range objs {
		if claimClassOK(set, o) && ClaimAllowed(o, set) {
			claims = append(claims, o)
		}
	}
	return claims, nil
}

// checkSet returns set if it is the set ref asks for. A set of another name,
// or for a scoped ref one from another registry, is a fault of the Source,
// which has answered a different question: a backend that ignored the scope
// must not be expanded as if it had honoured it. A set whose class is not the
// one its name denotes ("route-set: AS-EVIL") is invalid data, and is treated
// as not found: expanded under its name's rules it would let an as-set pull in
// prefixes, or claims, that its class does not allow.
func checkSet(ref types.SetRef, set object.NamedSet) (object.NamedSet, error) {
	if isNil(set) {
		return nil, ErrNotFound // a Source that returns neither a set (nil or a typed nil) nor an error
	}
	name := ref.Name()
	if got := set.SetName(); got != name {
		return nil, fmt.Errorf("resolve: asked for %s, the Source returned %s", ref, got)
	}
	if ref.IsScoped() && !equalFoldASCII(strings.TrimSpace(set.SetSource()), ref.Source()) {
		return nil, fmt.Errorf("resolve: asked for %s, the Source returned %s from %q", ref, name, set.SetSource())
	}
	if set.Class() != name.Class().String() {
		return nil, fmt.Errorf("resolve: %s is a %s: %w", ref, set.Class(), ErrNotFound)
	}
	return set, nil
}

// ordered returns the graph's nodes in a stable order — the top set first,
// then the rest by reference — so a result built by walking them does not
// depend on map iteration order.
func (g *setGraph) ordered() []*setNode {
	refs := make([]types.SetRef, 0, len(g.nodes))
	for r := range g.nodes {
		if r != g.top {
			refs = append(refs, r)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	out := make([]*setNode, 0, len(g.nodes))
	if nd, ok := g.nodes[g.top]; ok {
		out = append(out, nd)
	}
	for _, r := range refs {
		out = append(out, g.nodes[r])
	}
	return out
}

// members returns the members a resolver follows of a set whose members are
// ASNs, prefix ranges and nested sets — an as-set or a route-set — src-members:
// first (object.DirectMembers), and nothing for any other class.
func members(set object.NamedSet) []object.SetMember {
	if s, ok := set.(object.Set); ok {
		return object.DirectMembers(s)
	}
	return nil
}

// nestedRefs returns the sets a set points to, following only the nestings
// RFC 2622 §5.1-5.6 allows for its class: an as-set lists as-sets; a route-set
// lists route-sets and as-sets (the routes their ASes originate); an rtr-set
// lists rtr-sets; a peering-set lists peering-sets. A nesting the RFC does not
// allow is invalid data and is not followed — a route-set inside an as-set
// would add prefixes that no route object backs. A filter-set has no member
// list at all; EvalFilter walks its expression instead. A src-members:
// reference is scoped (object.DirectMembers); every other is not.
func nestedRefs(set object.NamedSet) []types.SetRef {
	parent := set.SetName().Class()
	var out []types.SetRef
	switch s := set.(type) {
	case object.Set:
		for _, m := range object.DirectMembers(s) {
			if m.Kind == object.MemberSet && nestable(parent, m.Set.Class()) && !m.Ref().IsZero() {
				out = append(out, m.Ref())
			}
		}
	case object.RouterGroup:
		for _, m := range s.SetRouters() {
			if m.Kind == object.RtrMemberSet && nestable(parent, m.Set.Class()) {
				out = append(out, types.Ref(m.Set))
			}
		}
	case object.PeeringGroup:
		for _, p := range s.SetPeerings() {
			if ref, ok := p.(policy.PeeringSetRef); ok && nestable(parent, ref.Name.Class()) {
				out = append(out, types.Ref(ref.Name))
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
// AS-ANY and RS-ANY are RFC 2622 §5.3's; RTRS-ANY, PRNG-ANY and FLTR-ANY have
// no basis in the RFC and are refused alike. It reads the name only, so a
// registry scope on a reference to one (RIPE::AS-ANY) is ignored, and a
// hierarchical name with an AS-ANY component (AS208301:AS-ANY) is an ordinary
// set.
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
		_, ok := o.(*object.AutNum)
		return ok
	case types.ClassRouteSet:
		switch o.(type) {
		case *object.Route, *object.Route6:
			return true
		}
	case types.ClassRtrSet:
		_, ok := o.(*object.InetRtr)
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
			if an, ok := o.(*object.AutNum); ok && !g.ex.as(an.AS) {
				add(an.AS)
			}
		}
	}
	routes := make([][]netip.Prefix, len(need))
	errs := make([]error, len(need))
	e.each(len(need), func(i int) { routes[i], errs[i] = e.Src.OriginatedRoutes(ctx, need[i], e.AFI) })
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
	set types.SetRef
	ops opStack
}

func (v *evaluator) walk(ref types.SetRef, ops opStack) error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	v.done[evalState{ref, ops}] = true
	if v.visits++; v.visits > v.e.maxVisited() {
		return &SetTooLargeError{Name: v.g.top, Limit: LimitVisited, Max: v.e.maxVisited(), Count: v.visits}
	}
	nd := v.g.nodes[ref]
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
			if !nestable(ref.Name().Class(), m.Set.Class()) {
				continue // e.g. a route-set listed in an as-set, even if reachable elsewhere
			}
			if v.g.ex.set(m.Set) {
				continue // excluded, even the top set listing itself
			}
			child := m.Ref()
			if _, ok := v.g.nodes[child]; !ok {
				continue // missing (reported)
			}
			next := ops.push(m.Op)
			if v.done[evalState{child, next}] {
				continue // already walked, or on the current path: its ranges are already counted
			}
			if err := v.walk(child, next); err != nil {
				return err
			}
		}
	}
	for _, o := range nd.claims {
		var err error
		switch t := o.(type) {
		case *object.Route:
			err = v.addRoutes([]netip.Prefix{t.Prefix}, ops)
		case *object.Route6:
			err = v.addRoutes([]netip.Prefix{t.Prefix}, ops)
		case *object.AutNum:
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
