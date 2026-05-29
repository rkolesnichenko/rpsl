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
	claims map[string][]claim           // canonical set name -> member-of claimants
}

type claim struct {
	obj     object.Object
	mntners []string // lower-cased mnt-by values
}

// NewMemSource indexes a corpus of decoded objects. Sets are indexed by
// canonical name, route/route6 prefixes by origin AS, and every object's
// member-of claims by the canonical name of each referenced set.
func NewMemSource(objs []object.Object) *MemSource {
	s := &MemSource{
		sets:   map[string]object.Set{},
		routes: map[types.ASN][]netip.Prefix{},
		claims: map[string][]claim{},
	}
	for _, o := range objs {
		if set, ok := o.(object.Set); ok {
			s.sets[set.SetName().Canonical()] = set
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

// indexClaims records this object under every set its member-of attributes name.
func (s *MemSource) indexClaims(o object.Object) {
	raw := o.Raw()
	memberOf := raw.GetAll("member-of")
	if len(memberOf) == 0 {
		return
	}
	var mntners []string
	for _, a := range raw.GetAll("mnt-by") {
		mntners = append(mntners, strings.ToLower(strings.TrimSpace(a.Value)))
	}
	c := claim{obj: o, mntners: mntners}
	for _, a := range memberOf {
		s.claims[canonSetKey(a.Value)] = append(s.claims[canonSetKey(a.Value)], c)
	}
}

// canonSetKey canonicalizes a set-name string for indexing, falling back to a
// trimmed upper-case form when the value does not parse as a set name.
func canonSetKey(v string) string {
	if n, err := types.ParseSetName(v); err == nil {
		return n.Canonical()
	}
	return strings.ToUpper(strings.TrimSpace(v))
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

// MembersByRef returns claimants of set maintained by one of mntners. "ANY"
// (case-insensitive) admits any maintainer.
func (s *MemSource) MembersByRef(_ context.Context, set types.SetName, mntners []string) ([]object.Object, error) {
	allow := make(map[string]bool, len(mntners))
	any := false
	for _, m := range mntners {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "any" {
			any = true
		}
		allow[m] = true
	}
	var out []object.Object
	for _, c := range s.claims[set.Canonical()] {
		if any || intersects(c.mntners, allow) {
			out = append(out, c.obj)
		}
	}
	return out, nil
}

func intersects(have []string, allow map[string]bool) bool {
	for _, h := range have {
		if allow[h] {
			return true
		}
	}
	return false
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
