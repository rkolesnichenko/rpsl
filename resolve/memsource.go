package resolve

import (
	"context"
	"net/netip"
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
	sets   map[string]object.NamedSet   // canonical set name -> set
	routes map[types.ASN][]netip.Prefix // origin AS -> originated prefixes
	claims map[string][]object.Object   // canonical set name -> member-of claimants
}

// NewMemSource indexes a corpus of objects — decoded, or built by the caller,
// as values or pointers. Sets are indexed by name, route/route6 prefixes by
// origin AS, and aut-num/route/route6 member-of claims by each named set.
//
// When the same set name appears more than once (e.g. dumps from several IRRs),
// sourcePrecedence decides which object is used, like IRRd's !s: the set whose
// source: is listed earliest wins (case-insensitive), sources not listed rank
// after all listed ones, and ties go to the object loaded first. Routes are
// unioned across sources.
func NewMemSource(objs []object.Object, sourcePrecedence ...string) *MemSource {
	s := &MemSource{
		sets:   map[string]object.NamedSet{},
		routes: map[types.ASN][]netip.Prefix{},
		claims: map[string][]object.Object{},
	}
	rank := func(source string) int {
		for i, src := range sourcePrecedence {
			if equalFoldASCII(strings.TrimSpace(source), src) {
				return i
			}
		}
		return len(sourcePrecedence)
	}
	setRank := map[string]int{}
	for _, o := range objs {
		if o = value(o); o == nil {
			continue
		}
		if set, ok := o.(object.NamedSet); ok {
			key, r := set.SetName().String(), rank(set.SetSource())
			if prev, dup := setRank[key]; !dup || r < prev {
				s.sets[key], setRank[key] = set, r
			}
		}
		// A route whose origin did not decode is no AS's, not AS0's.
		switch t := o.(type) {
		case object.Route:
			if t.Prefix.IsValid() && (t.Origin != 0 || asnDecodes(t, "origin")) {
				s.routes[t.Origin] = append(s.routes[t.Origin], t.Prefix)
			}
		case object.Route6:
			if t.Prefix.IsValid() && (t.Origin != 0 || asnDecodes(t, "origin")) {
				s.routes[t.Origin] = append(s.routes[t.Origin], t.Prefix)
			}
		}
		s.indexClaims(o)
	}
	return s
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

// GetSet returns the named set or ErrNotFound.
func (s *MemSource) GetSet(_ context.Context, name types.SetName) (object.NamedSet, error) {
	if set, ok := s.sets[name.String()]; ok {
		return set, nil
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
