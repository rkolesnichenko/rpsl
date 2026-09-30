package resolve

import (
	"context"
	"errors"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// NormalFilter is a filter in disjunctive normal form: it matches a route when
// any of its conjuncts does, and one with no conjuncts matches nothing. It is
// what a router configuration can express — one route-map entry per conjunct
// — and what IRRToolSet's peval computes.
type NormalFilter struct {
	Conjuncts []Conjunct
	missing   []types.SetRef
}

// Missing lists the sets the filter named that the Source does not have,
// sorted by String(); they denoted nothing.
func (f NormalFilter) Missing() []types.SetRef { return f.missing }

// Conjunct matches a route when every part does: its prefix lies in one of
// Prefixes and in none of NotPrefixes, every PathMatch holds of its AS path
// and every CommunityMatch of its communities.
type Conjunct struct {
	Prefixes    RangeSet // ANY is 0.0.0.0/0^0-32 and ::/0^0-128, trimmed to the Expander's AFI
	NotPrefixes RangeSet // only ranges that meet Prefixes are kept
	Paths       []PathMatch
	Communities []CommunityMatch
	any         bool
}

// AnyPrefix reports whether Prefixes is every prefix of the Expander's address
// family, so a printer can leave the prefix match out.
func (c Conjunct) AnyPrefix() bool { return c.any }

// PathMatch is an AS-path regexp a route's path must match (or, Negated, must
// not). RE has PeerAS and set templates bound. Sets holds every as-set RE
// names, expanded, so a printer can write the regexp without a registry;
// AS-ANY, which matches any AS, has no entry. The regexp is never evaluated
// here (design §13). Sets is always expanded with Expander.Exclude cleared, in
// either polarity: a set can reject even inside a regexp that is not negated
// ("[^AS-A]" matches an AS not in AS-A), so an excluded member left out of it
// would widen what the filter accepts (see NormalizeFilter).
type PathMatch struct {
	Negated bool
	RE      *policy.ASPathRE
	Sets    map[types.SetName]ASNSet
}

// CommunityMatch is a community test a route must pass (or, Negated, fail).
type CommunityMatch struct {
	Negated bool
	Test    policy.FilterCommunity
}

// NormalizeFilter evaluates f into disjunctive normal form. What can be
// enumerated — prefix lists, set and AS references, PeerAS for a bound Peer —
// folds into prefix ranges, through the same evaluation as EvalFilter; AS-path
// regexps and community tests stay symbolic and are never evaluated (design
// §13). NOT is pushed to the leaves. AS-ANY and RS-ANY in filter position
// denote every route, as ANY does (RFC 2622 §5.1, §5.2). A filter-set that
// holds a regexp or a community test is inlined, once per polarity however
// often f names it; referenced with a range operator, or on a cycle of
// filter-sets, it is a *NotEnumerableError naming it. A term naming the peer
// with no Peer bound is a *NotEnumerableError wrapping ErrUnboundPeer. An
// AS-path regexp that did not parse is a *NotEnumerableError too.
//
// Expander.Exclude only ever narrows what f accepts, so it applies to one
// thing: a positive prefix literal, evaluated with it as EvalFilter would. A
// negated literal — a NOT'd term, or a filter-set inlined under NOT — is
// evaluated with Exclude cleared, so the rejecting side is always the term's
// true value; otherwise removing a set or AS from the deny side would admit
// it instead of leaving it out. That holds through an inlined filter-set too,
// since polarity is tracked through the inlining. Exclude never applies inside
// an AS-path regexp, in either polarity: PathMatch.Sets is always the sets'
// full expansion.
//
// Whenever EvalFilter(f) succeeds, NormalizeFilter(f) has at most one
// conjunct, with no NotPrefixes, Paths or Communities, and its Prefixes are
// EvalFilter's answer. MaxConjuncts caps both the conjuncts of every
// disjunction built on the way and the tests (Paths and Communities, a test
// repeated in a conjunct counted once) of every conjunct; MaxVisited caps the
// sets fetched, the filter terms evaluated and the normalization steps taken,
// together. Each is a *SetTooLargeError naming the limit.
func (e *Expander) NormalizeFilter(ctx context.Context, f policy.Filter) (NormalFilter, error) {
	nf, _, err := e.normalize(ctx, f)
	return nf, err
}

// normalize is NormalizeFilter, also returning the largest disjunction built.
func (e *Expander) normalize(ctx context.Context, f policy.Filter) (NormalFilter, int, error) {
	n := &normalizer{ev: newFilterEval(e, ctx), inline: map[string]bool{}, memo: map[string][]nconj{}}
	n.ev.anyAll = true
	// noEx is the same Expander with Exclude cleared, for negated contexts: a
	// deny side must be evaluated in full, or removing an excluded set or AS
	// from it would admit what it was meant to leave out (see NormalizeFilter).
	// prefixRanges/asSet and discovery apply an Expander's own Exclude, so the
	// two evaluators cannot share their caches.
	noExclude := *e
	noExclude.Exclude = Exclusion{}
	n.noEx = newFilterEval(&noExclude, ctx)
	n.noEx.anyAll = true
	cs, err := n.norm(f, false, 0)
	if err != nil {
		return NormalFilter{}, n.peak, err
	}
	nf, err := n.finish(cs)
	return nf, n.peak, err
}

// nconj is a conjunct being built.
type nconj struct {
	pos   rangeSetOf // nil: no prefix constraint
	neg   rangeSetOf
	paths []PathMatch
	comms []CommunityMatch
}

// normalizer builds one normal form. What it caches for the whole call: each
// set fetched, each route-set and as-set expansion (in ev, and again in noEx),
// and the normal form of each filter-set it inlines, by polarity — so a
// filter-set named any number of times is inlined once per polarity. What it
// evaluates afresh: each enumerable literal, filter-sets inside it included
// (filterEval.run starts a new fixpoint per literal). Every step is charged
// against MaxVisited.
//
// noEx is a second filterEval, over the same Expander with Exclude cleared,
// used for negated literals and for every AS-path regexp's sets (see
// NormalizeFilter); it has its own caches, since the two evaluators must not
// share prefixRanges/asSet/filter-set results.
type normalizer struct {
	ev     *filterEval
	noEx   *filterEval
	peak   int                // the largest disjunction built, or the most tests in one conjunct
	inline map[string]bool    // filter-sets being inlined, against cycles
	memo   map[string][]nconj // inlined filter-sets' normal forms, by polarity and SetRef.String()
}

// evFor returns the evaluator a literal normalized under the given polarity
// must use: ev, with Exclude applied, when neg is false; noEx, with Exclude
// cleared, when neg is true.
func (n *normalizer) evFor(neg bool) *filterEval {
	if neg {
		return n.noEx
	}
	return n.ev
}

// out returns a disjunction, charging it against MaxConjuncts.
func (n *normalizer) out(cs []nconj) ([]nconj, error) {
	if len(cs) > n.peak {
		n.peak = len(cs)
	}
	if max := n.ev.e.maxConjuncts(); len(cs) > max {
		return nil, &SetTooLargeError{Name: n.ev.cur, Limit: LimitConjuncts, Max: max, Count: len(cs)}
	}
	return cs, nil
}

// norm normalizes f, negated when neg, charging the step against MaxVisited.
func (n *normalizer) norm(f policy.Filter, neg bool, depth int) ([]nconj, error) {
	ev := n.ev
	if err := ev.ctx.Err(); err != nil {
		return nil, err
	}
	if depth > ev.e.maxDepth() {
		return nil, &SetTooLargeError{Name: ev.cur, Limit: LimitDepth, Max: ev.e.maxDepth(), Count: depth}
	}
	if err := ev.visit(1); err != nil {
		return nil, err
	}
	sym, err := n.symbolic(f, false, neg, map[string]bool{})
	if err != nil {
		return nil, err
	}
	if !sym {
		return n.literal(f, neg)
	}
	switch x := f.(type) {
	case policy.FilterNot:
		return n.norm(x.Inner, !neg, depth+1)
	case policy.FilterOr:
		return n.group(x.Terms, false, neg, depth)
	case policy.FilterAnd:
		return n.group(x.Terms, true, neg, depth)
	case policy.FilterPathRE:
		pm, err := n.path(x)
		if err != nil {
			return nil, err
		}
		pm.Negated = neg
		return n.out([]nconj{{paths: []PathMatch{pm}}})
	case policy.FilterCommunity:
		return n.out([]nconj{{comms: []CommunityMatch{{Negated: neg, Test: x}}}})
	case policy.FilterSetRef:
		return n.filterSet(x, neg, depth)
	}
	return nil, &NotEnumerableError{Term: filterText(f), Why: "unknown filter term"}
}

// literal evaluates an enumerable filter to one literal: the ranges it denotes
// or, when neg, their complement. neg selects the evaluator (see evFor), so a
// negated literal's complement is always exact, never missing an excluded set
// or AS's routes.
func (n *normalizer) literal(f policy.Filter, neg bool) ([]nconj, error) {
	ev := n.evFor(neg)
	ev.approx = nil
	rs, err := ev.run(f)
	if err != nil {
		return nil, err
	}
	if neg {
		return n.out([]nconj{{neg: rs}})
	}
	if len(rs) == 0 {
		return nil, nil
	}
	return n.out([]nconj{{pos: rs}})
}

// symbolic reports whether f holds a term that stays symbolic in the normal
// form — NOT, an AS-path regexp, a community test — itself or through the
// filter-sets it names. inSet is whether f is inside a filter-set, where
// Exclude applies; neg is the polarity f will be normalized under. An excluded
// filter-set is only ever treated as vacuously empty in a positive context (as
// skipSet treats it during evaluation); under negation that would admit what
// it should reject, so the walk does not skip it there and inlines it instead
// (see NormalizeFilter). seen breaks cycles.
func (n *normalizer) symbolic(f policy.Filter, inSet, neg bool, seen map[string]bool) (bool, error) {
	switch x := f.(type) {
	case policy.FilterNot, policy.FilterPathRE, policy.FilterCommunity:
		return true, nil
	case policy.FilterOr:
		return n.anySymbolic(x.Terms, inSet, neg, seen)
	case policy.FilterAnd:
		return n.anySymbolic(x.Terms, inSet, neg, seen)
	case policy.FilterSetRef:
		if x.Name.Class() != types.ClassFilterSet || isAnySet(x.Name) ||
			!neg && (inSet || !n.ev.cur.IsZero()) && n.ev.ex.set(x.Name) {
			return false, nil
		}
		ref := types.Ref(x.Name)
		if seen[ref.String()] {
			return false, nil
		}
		seen[ref.String()] = true
		fg, err := n.ev.filterSet(ref)
		if err != nil || fg == nil {
			return false, err
		}
		return n.symbolic(n.ev.pick(fg), true, neg, seen)
	}
	return false, nil
}

func (n *normalizer) anySymbolic(fs []policy.Filter, inSet, neg bool, seen map[string]bool) (bool, error) {
	for _, f := range fs {
		if sym, err := n.symbolic(f, inSet, neg, seen); sym || err != nil {
			return sym, err
		}
	}
	return false, nil
}

// group normalizes an AND (and) or an OR of terms, negated when neg. Its
// enumerable terms fold into one literal first — their intersection or union,
// by the evaluator EvalFilter uses — so only symbolic terms multiply
// conjuncts. By De Morgan, a positive AND and a negated OR are a product of
// their terms' disjunctions, and the other two a union.
func (n *normalizer) group(terms []policy.Filter, and, neg bool, depth int) ([]nconj, error) {
	if len(terms) == 0 {
		return n.literal(policy.FilterOr{}, neg)
	}
	var enum []policy.Filter
	var parts [][]nconj
	for _, t := range terms {
		sym, err := n.symbolic(t, false, neg, map[string]bool{})
		if err != nil {
			return nil, err
		}
		if !sym {
			enum = append(enum, t)
			continue
		}
		cs, err := n.norm(t, neg, depth+1)
		if err != nil {
			return nil, err
		}
		parts = append(parts, cs)
	}
	if len(enum) > 0 {
		var lit policy.Filter = policy.FilterOr{Terms: enum}
		if and {
			lit = policy.FilterAnd{Terms: enum}
		}
		cs, err := n.literal(lit, neg)
		if err != nil {
			return nil, err
		}
		parts = append([][]nconj{cs}, parts...)
	}
	if and != neg {
		return n.product(parts)
	}
	var out []nconj
	for _, p := range parts {
		out = append(out, p...)
	}
	return n.out(out)
}

// product is the conjunction of disjunctions, distributed: one conjunct per
// choice of one conjunct from each, less those that meet in no prefix.
func (n *normalizer) product(parts [][]nconj) ([]nconj, error) {
	acc := []nconj{{}}
	for _, p := range parts {
		var next []nconj
		for _, x := range acc {
			if err := n.ev.ctx.Err(); err != nil {
				return nil, err
			}
			for _, y := range p {
				c, ok, err := n.merge(x, y)
				if err != nil {
					return nil, err
				}
				if ok {
					next = append(next, c)
				}
			}
			if _, err := n.out(next); err != nil {
				return nil, err
			}
		}
		if acc = next; len(acc) == 0 {
			break
		}
	}
	return n.out(acc)
}

// merge conjoins two conjuncts: positive ranges intersect, negated ones
// union, tests accumulate — a test already present (the same polarity and
// text) is kept once, and a conjunct of more than MaxConjuncts tests is a
// *SetTooLargeError. ok is false when the positive ranges do not meet.
func (n *normalizer) merge(x, y nconj) (nconj, bool, error) {
	c := nconj{
		paths: append([]PathMatch(nil), x.paths...),
		comms: append([]CommunityMatch(nil), x.comms...),
	}
	if len(y.paths) > 0 {
		seen := make(map[string]bool, len(x.paths))
		for _, p := range x.paths {
			seen[p.key()] = true
		}
		for _, p := range y.paths {
			if k := p.key(); !seen[k] {
				seen[k] = true
				c.paths = append(c.paths, p)
			}
		}
	}
	if len(y.comms) > 0 {
		seen := make(map[string]bool, len(x.comms))
		for _, m := range x.comms {
			seen[m.key()] = true
		}
		for _, m := range y.comms {
			if k := m.key(); !seen[k] {
				seen[k] = true
				c.comms = append(c.comms, m)
			}
		}
	}
	tests := len(c.paths) + len(c.comms)
	if tests > n.peak {
		n.peak = tests
	}
	if max := n.ev.e.maxConjuncts(); tests > max {
		return nconj{}, false, &SetTooLargeError{Name: n.ev.cur, Limit: LimitConjuncts, Max: max, Count: tests}
	}
	switch {
	case x.pos == nil:
		c.pos = y.pos
	case y.pos == nil:
		c.pos = x.pos
	default:
		p, err := n.ev.intersect(x.pos, y.pos)
		if err != nil {
			return nconj{}, false, err
		}
		if len(p) == 0 {
			return nconj{}, false, nil
		}
		c.pos = p
	}
	if len(x.neg) > 0 || len(y.neg) > 0 {
		c.neg = make(rangeSetOf, len(x.neg)+len(y.neg))
		for r := range x.neg {
			c.neg[r] = struct{}{}
		}
		for r := range y.neg {
			c.neg[r] = struct{}{}
		}
	}
	return c, true, nil
}

// key identifies a PathMatch within a conjunct: its polarity and its text.
func (m PathMatch) key() string {
	if m.Negated {
		return "!" + m.RE.String()
	}
	return m.RE.String()
}

// key identifies a CommunityMatch within a conjunct: its polarity and its text.
func (m CommunityMatch) key() string {
	if m.Negated {
		return "!" + m.Test.String()
	}
	return m.Test.String()
}

// path binds an AS-path regexp to the peer and expands the as-sets it names,
// always with Exclude cleared (see the PathMatch doc): a set can sit on the
// rejecting side of a regexp even when the regexp is not negated ("[^AS-A]"),
// so leaving a member out would widen what the regexp accepts.
func (n *normalizer) path(x policy.FilterPathRE) (PathMatch, error) {
	if x.Regexp == nil {
		return PathMatch{}, &NotEnumerableError{Term: filterText(x), Why: "the AS-path regexp did not parse"}
	}
	re := x.Regexp
	if re.UsesPeer() {
		if n.ev.e.Peer == 0 {
			return PathMatch{}, unboundPeer(filterText(x))
		}
		re = re.Bind(n.ev.e.Peer)
	}
	pm := PathMatch{RE: re, Sets: map[types.SetName]ASNSet{}}
	ev := n.noEx
	for _, name := range re.SetNames() {
		if isAnySet(name) {
			continue
		}
		s, err := ev.asSet(name)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return PathMatch{}, err
			}
			ev.note(types.Ref(name))
		}
		for _, m := range s.Missing() {
			ev.note(m)
		}
		pm.Sets[name] = s
	}
	return pm, nil
}

// filterSet inlines a filter-set that holds a symbolic term, once per
// polarity: what it normalizes to depends only on the set and the polarity
// (inside it, cur is the set itself), so a later reference reuses the first
// one's normal form.
func (n *normalizer) filterSet(x policy.FilterSetRef, neg bool, depth int) ([]nconj, error) {
	if !x.Op.IsZero() {
		return nil, &NotEnumerableError{Term: filterText(x),
			Why: "a range operator on a filter-set with an AS-path regexp or a community test"}
	}
	ref := types.Ref(x.Name)
	key := ref.String()
	memoKey := key
	if neg {
		memoKey = "!" + key
	}
	if cs, ok := n.memo[memoKey]; ok {
		return cs, nil
	}
	if n.inline[key] {
		return nil, &NotEnumerableError{Term: x.Name.String(),
			Why: "a cycle of filter-sets through an AS-path regexp or a community test"}
	}
	fg, err := n.ev.filterSet(ref)
	if err != nil {
		return nil, err
	}
	if fg == nil {
		return n.literal(x, neg)
	}
	outer := n.ev.cur
	n.inline[key], n.ev.cur = true, ref
	cs, err := n.norm(n.ev.pick(fg), neg, depth+1)
	delete(n.inline, key)
	n.ev.cur = outer
	if err != nil {
		return nil, err
	}
	n.memo[memoKey] = cs
	return cs, nil
}

// finish turns the conjuncts built into the result: a missing prefix
// constraint becomes every prefix, positive ranges wholly inside a negated one
// go, negated ranges meeting no positive one go, and what then matches no
// prefix, or repeats an earlier conjunct, is dropped.
func (n *normalizer) finish(cs []nconj) (NormalFilter, error) {
	ev := n.ev
	all := ev.everything()
	var nf NormalFilter
	seen := map[string]bool{}
	for _, c := range cs {
		pos := c.pos
		if pos == nil {
			pos = all
		}
		neg := rangeSetOf{}
		if len(c.neg) > 0 {
			covered := map[types.PrefixRange]bool{}
			if err := ev.pairs(pos, c.neg, func(x, y types.PrefixRange) error {
				if in, ok := x.Intersect(y); ok && in == x {
					covered[x] = true
				}
				return nil
			}); err != nil {
				return NormalFilter{}, err
			}
			if len(covered) > 0 {
				rest := make(rangeSetOf, len(pos))
				for x := range pos {
					if !covered[x] {
						rest[x] = struct{}{}
					}
				}
				pos = rest
			}
			if err := ev.pairs(c.neg, pos, func(x, y types.PrefixRange) error {
				if _, ok := x.Intersect(y); ok {
					neg[x] = struct{}{}
				}
				return nil
			}); err != nil {
				return NormalFilter{}, err
			}
		}
		if len(pos) == 0 {
			continue
		}
		conj := Conjunct{
			Prefixes:    toRangeSet(pos),
			NotPrefixes: toRangeSet(neg),
			Paths:       c.paths,
			Communities: c.comms,
			any:         covers(pos, all),
		}
		key := conj.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		nf.Conjuncts = append(nf.Conjuncts, conj)
	}
	nf.missing = mergedMissing(n.ev.missing, n.noEx.missing)
	return nf, nil
}

// mergedMissing merges the sets noted missing by both evaluators — the
// positive one and the Exclude-cleared one NormalizeFilter uses under
// negation — deduplicated and sorted by String().
func mergedMissing(a, b []types.SetRef) []types.SetRef {
	seen := make(map[types.SetRef]bool, len(a)+len(b))
	out := make([]types.SetRef, 0, len(a)+len(b))
	for _, refs := range [2][]types.SetRef{a, b} {
		for _, r := range refs {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return sortedRefs(out)
}

// covers reports whether every range of b is in a.
func covers(a, b rangeSetOf) bool {
	for r := range b {
		if _, ok := a[r]; !ok {
			return false
		}
	}
	return true
}

func toRangeSet(rs rangeSetOf) RangeSet {
	out := newRangeSet()
	for r := range rs {
		out.add(r)
	}
	return *out
}

// String renders the normal form as RPSL: its conjuncts joined by OR, or
// "NOT ANY" when it has none. policy.ParseFilter reads it back to a filter
// that matches the same routes when normalized under the same Expander.AFI.
// The text carries no address family of its own: under AFIv4, "ANY" is every
// IPv4 prefix and "NOT {…}" leaves the rest of IPv4, but read back under
// AFIAny both would take in IPv6 too.
func (f NormalFilter) String() string {
	if len(f.Conjuncts) == 0 {
		return "NOT ANY"
	}
	parts := make([]string, len(f.Conjuncts))
	for i, c := range f.Conjuncts {
		s := c.String()
		if len(f.Conjuncts) > 1 && strings.Contains(s, " AND ") {
			s = "(" + s + ")"
		}
		parts[i] = s
	}
	return strings.Join(parts, " OR ")
}

// String renders the conjunct as RPSL: its parts joined by AND, the prefix
// list left out when it is every prefix and something else constrains.
func (c Conjunct) String() string {
	var parts []string
	switch {
	case !c.any:
		parts = append(parts, policy.FilterPrefixList{Ranges: c.Prefixes.List()}.String())
	case c.NotPrefixes.Len() == 0 && len(c.Paths) == 0 && len(c.Communities) == 0:
		parts = append(parts, "ANY")
	}
	if c.NotPrefixes.Len() > 0 {
		parts = append(parts, "NOT "+policy.FilterPrefixList{Ranges: c.NotPrefixes.List()}.String())
	}
	for _, p := range c.Paths {
		s := "<" + p.RE.String() + ">"
		if p.Negated {
			s = "NOT " + s
		}
		parts = append(parts, s)
	}
	for _, m := range c.Communities {
		s := m.Test.String()
		if m.Negated {
			s = "NOT " + s
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " AND ")
}
