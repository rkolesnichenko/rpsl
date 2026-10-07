package resolve

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// MemSource is an in-memory Source built from a decoded corpus. It is the
// backend used by tests and by callers that have loaded an IRRd snapshot or
// .db dump into memory. Indirect (member-of) claims and mnt-by maintainers are
// read generically from each object's lossless attributes, so MembersByRef can
// enforce the mbrs-by-ref mntner check without a typed field on every class.
type MemSource struct {
	sets    map[types.SetName][]memSet   // every held copy, precedence order (winner first)
	dflt    func(source string) bool     // the sources unscoped lookups and routes see; nil: all
	routes  map[types.ASN][]netip.Prefix // origin AS -> originated prefixes, default sources only
	claims  map[string][]object.Object   // canonical set name -> member-of claimants, every source
	autnums map[types.ASN][]policyEntry  // AS -> aut-num copies, precedence order
	rtrs    map[string][]policyEntry     // upper-case inet-rtr name -> copies, precedence order
	rank    func(source string) int      // precedence rank; lower wins, ties keep load order
	policy  bool                         // serves aut-nums and inet-rtrs (else AutNum/InetRtr are ErrNoPolicy)

	index      bool                      // keeps namedBy (NewMemSource always; a Corpus's MemSource when IndexPeers)
	namedBy    map[types.ASN][]types.ASN // AS -> the aut-nums naming it, ascending
	autnumList []types.ASN               // every aut-num served, ascending
}

// memSet is one copy of a set and its upper-case source.
type memSet struct {
	set    object.NamedSet
	source string
}

// NewMemSource indexes a corpus of objects — decoded, or built by the caller.
// Sets are indexed by name, route/route6 prefixes by origin AS, and
// aut-num/route/route6 member-of claims by each named set.
//
// When the same set name appears more than once (e.g. dumps from several IRRs),
// sourcePrecedence decides which object an unscoped lookup returns, like
// IRRd's !s: the set whose source: is listed earliest wins (case-insensitive),
// sources not listed rank after all listed ones, and ties go to the object
// loaded first. Routes are unioned across sources. A scoped reference
// (RIPE::AS-FOO) finds the copy whose source: is that registry, whatever the
// precedence; one no object's source: names is ErrNotFound.
//
// It is a PolicySource that serves every aut-num and inet-rtr in objs.
//
// Corpus.Source builds with it too, so that the two cannot answer differently.
func NewMemSource(objs []object.Object, sourcePrecedence ...string) *MemSource {
	return newMemSource(objs, sourcePrecedence, nil)
}

// newMemSource is NewMemSource whose unscoped lookups and routes see only the
// sources dflt admits (nil: all). Scoped lookups and claims see every source.
func newMemSource(objs []object.Object, sourcePrecedence []string, dflt func(string) bool) *MemSource {
	s := &MemSource{
		sets:    map[types.SetName][]memSet{},
		dflt:    dflt,
		routes:  map[types.ASN][]netip.Prefix{},
		claims:  map[string][]object.Object{},
		autnums: map[types.ASN][]policyEntry{},
		rtrs:    map[string][]policyEntry{},
		policy:  true, // it indexes every aut-num and inet-rtr it is given
		index:   true, // it keeps a peer index for every aut-num it is given
	}
	s.rank = func(source string) int {
		for i, src := range sourcePrecedence {
			if equalFoldASCII(source, strings.TrimSpace(src)) {
				return i
			}
		}
		return len(sourcePrecedence)
	}
	for _, o := range objs {
		if isNil(o) {
			continue
		}
		if set, ok := o.(object.NamedSet); ok {
			n := set.SetName()
			s.sets[n] = append(s.sets[n], memSet{set, strings.ToUpper(strings.TrimSpace(set.SetSource()))})
		}
		if p, origin, ok := routeOf(o); ok && s.admits(sourceOf(o)) {
			s.routes[origin] = append(s.routes[origin], p)
		}
		s.indexClaims(o)
		switch t := o.(type) {
		case *object.AutNum:
			// An aut-num whose key did not decode is no AS (claimant agrees):
			// addPolicy would otherwise index it under the AS0 it defaults to.
			if _, _, _, ok := claimant(t); ok {
				s.addPolicy("aut-num", t.AS.String(), t.Source, t, "", nil)
			}
		case *object.InetRtr:
			if rtrKey(t.Name) != "" {
				s.addPolicy("inet-rtr", t.Name, t.Source, t, "", nil)
			}
		}
	}
	s.finish()
	return s
}

// finish orders every copy of a set, aut-num and inet-rtr by precedence;
// ties keep load order, so the object loaded first wins.
func (s *MemSource) finish() {
	for _, copies := range s.sets {
		sort.SliceStable(copies, func(i, j int) bool { return s.rank(copies[i].source) < s.rank(copies[j].source) })
	}
	for _, es := range s.autnums {
		sort.SliceStable(es, func(i, j int) bool { return s.rank(es[i].source) < s.rank(es[j].source) })
	}
	for _, es := range s.rtrs {
		sort.SliceStable(es, func(i, j int) bool { return s.rank(es[i].source) < s.rank(es[j].source) })
	}
	s.buildIndex()
}

func (s *MemSource) admits(source string) bool {
	return s.dflt == nil || s.dflt(strings.ToUpper(strings.TrimSpace(source)))
}

// indexClaims records a claimant under every set its member-of names. Whether a
// claim is honored is decided at query time by ClaimAllowed.
func (s *MemSource) indexClaims(o object.Object) {
	memberOf, _, _, ok := claimant(o)
	if !ok {
		return
	}
	seen := map[types.SetName]bool{}
	for _, n := range memberOf {
		if !seen[n] {
			seen[n] = true
			s.claims[n.String()] = append(s.claims[n.String()], o)
		}
	}
}

// GetSet returns the set ref names or ErrNotFound: for an unscoped ref the
// copy the precedence puts first among the default sources, for a scoped one
// the copy of that registry.
func (s *MemSource) GetSet(_ context.Context, ref types.SetRef) (object.NamedSet, error) {
	for _, c := range s.sets[ref.Name()] {
		if ref.IsScoped() {
			if c.source == ref.Source() {
				return c.set, nil
			}
		} else if s.admits(c.source) {
			return c.set, nil
		}
	}
	return nil, ErrNotFound
}

// OriginatedRoutes returns the prefixes originated by as, filtered to afi.
func (s *MemSource) OriginatedRoutes(_ context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range s.routes[as] {
		if afiMatches(afi, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// MembersByRef returns the objects claiming member-of set whose claim
// ClaimAllowed honors.
func (s *MemSource) MembersByRef(_ context.Context, set object.NamedSet) ([]object.Object, error) {
	var out []object.Object
	for _, o := range s.claims[set.SetName().String()] {
		if ClaimAllowed(o, set) {
			out = append(out, o)
		}
	}
	return out, nil
}

// afiMatches reports whether a prefix satisfies an AFI constraint.
func afiMatches(afi types.AFI, p netip.Prefix) bool {
	switch afi {
	case types.AFIv4:
		return p.Addr().Is4()
	case types.AFIv6:
		return p.Addr().Is6()
	default:
		return true
	}
}

var _ Source = (*MemSource)(nil)
