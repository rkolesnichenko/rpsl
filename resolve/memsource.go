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
	sets   map[string]object.Set        // canonical set name -> set
	routes map[types.ASN][]netip.Prefix // origin AS -> originated prefixes
	claims map[string][]object.Object   // canonical set name -> member-of claimants
}

// NewMemSource indexes a corpus of decoded objects. Sets are indexed by
// canonical name, route/route6 prefixes by origin AS, and every object's
// member-of claims by the canonical name of each referenced set.
//
// When the same set name appears more than once (e.g. dumps from several IRRs),
// sourcePrecedence decides which object is used, like IRRd's !s: the set whose
// source: is listed earliest wins (case-insensitive), sources not listed rank
// after all listed ones, and ties go to the object loaded first. Routes are
// unioned across sources.
func NewMemSource(objs []object.Object, sourcePrecedence ...string) *MemSource {
	s := &MemSource{
		sets:   map[string]object.Set{},
		routes: map[types.ASN][]netip.Prefix{},
		claims: map[string][]object.Object{},
	}
	rank := func(o object.Object) int {
		if raw := o.Raw(); raw != nil {
			if a, ok := raw.GetFirst("source"); ok {
				for i, src := range sourcePrecedence {
					if strings.EqualFold(strings.TrimSpace(a.Value), src) {
						return i
					}
				}
			}
		}
		return len(sourcePrecedence)
	}
	setRank := map[string]int{}
	for _, o := range objs {
		if set, ok := o.(object.Set); ok {
			key := set.SetName().Canonical()
			if prev, dup := setRank[key]; !dup || rank(o) < prev {
				s.sets[key], setRank[key] = set, rank(o)
			}
		}
		switch t := o.(type) {
		case object.Route:
			if t.Prefix.IsValid() {
				s.routes[t.Origin] = append(s.routes[t.Origin], t.Prefix)
			}
		case object.Route6:
			if t.Prefix.IsValid() {
				s.routes[t.Origin] = append(s.routes[t.Origin], t.Prefix)
			}
		}
		s.indexClaims(o)
	}
	return s
}

// indexClaims records this object under every set its member-of items name.
// Whether a claim is honored is decided at query time by ClaimAllowed.
func (s *MemSource) indexClaims(o object.Object) {
	seen := map[string]bool{}
	for _, a := range o.Raw().GetAll("member-of") {
		for _, it := range a.List() {
			n, err := types.ParseSetName(it.Value)
			if err != nil || seen[n.Canonical()] {
				continue
			}
			seen[n.Canonical()] = true
			s.claims[n.Canonical()] = append(s.claims[n.Canonical()], o)
		}
	}
}

// GetSet returns the named set or ErrNotFound.
func (s *MemSource) GetSet(_ context.Context, name types.SetName) (object.Set, error) {
	if set, ok := s.sets[name.Canonical()]; ok {
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
// ClaimAllowed honors under mntners ("ANY" admits any maintainer).
func (s *MemSource) MembersByRef(_ context.Context, set types.SetName, mntners []string) ([]object.Object, error) {
	var out []object.Object
	for _, o := range s.claims[set.Canonical()] {
		if ClaimAllowed(o, set, mntners) {
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
