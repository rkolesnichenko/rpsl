package resolve

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// ASNSet is a deduplicated set of ASNs produced by ExpandAS.
type ASNSet struct {
	m       map[types.ASN]struct{}
	missing []types.SetName
}

// Missing lists the nested sets that were referenced but not found, sorted by
// canonical name. They expanded to nothing (as in bgpq4).
func (s ASNSet) Missing() []types.SetName { return s.missing }

func newASSet() *ASNSet { return &ASNSet{m: make(map[types.ASN]struct{})} }

func (s *ASNSet) add(a types.ASN) { s.m[a] = struct{}{} }

// Has reports membership.
func (s ASNSet) Has(a types.ASN) bool { _, ok := s.m[a]; return ok }

// Len reports the number of distinct ASNs.
func (s ASNSet) Len() int { return len(s.m) }

// List returns the ASNs in ascending order (deterministic for tests/output).
func (s ASNSet) List() []types.ASN {
	out := make([]types.ASN, 0, len(s.m))
	for a := range s.m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PrefixSet is a deduplicated set of prefixes produced by ExpandPrefixes.
type PrefixSet struct {
	m       map[netip.Prefix]struct{}
	missing []types.SetName
}

// Missing lists the nested sets that were referenced but not found; see
// ASNSet.Missing.
func (s PrefixSet) Missing() []types.SetName { return s.missing }

func newPrefixSet() *PrefixSet { return &PrefixSet{m: make(map[netip.Prefix]struct{})} }

func (s *PrefixSet) add(p netip.Prefix) { s.m[p] = struct{}{} }

// Has reports membership.
func (s PrefixSet) Has(p netip.Prefix) bool { _, ok := s.m[p]; return ok }

// Len reports the number of distinct prefixes.
func (s PrefixSet) Len() int { return len(s.m) }

// List returns the prefixes ordered by address then prefix length.
func (s PrefixSet) List() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.m))
	for p := range s.m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// RangeSet is a deduplicated set of prefix ranges produced by
// ExpandPrefixRanges: the expansion before materialization, as bgpq4 emits it
// with le/ge bounds. Ranges are held in canonical form (types.PrefixRange.
// Canonical), so equivalent spellings count once.
type RangeSet struct {
	m       map[types.PrefixRange]struct{}
	missing []types.SetName
}

func newRangeSet() *RangeSet { return &RangeSet{m: make(map[types.PrefixRange]struct{})} }

func (s *RangeSet) add(r types.PrefixRange) { s.m[r] = struct{}{} }

// Has reports whether the set holds a range denoting the same prefixes as r.
func (s RangeSet) Has(r types.PrefixRange) bool {
	_, ok := s.m[r]
	return ok
}

// Len reports the number of distinct ranges.
func (s RangeSet) Len() int { return len(s.m) }

// Missing lists the nested sets that were referenced but not found; see
// ASNSet.Missing.
func (s RangeSet) Missing() []types.SetName { return s.missing }

// List returns the ranges ordered by address, prefix length, then window.
func (s RangeSet) List() []types.PrefixRange {
	out := make([]types.PrefixRange, 0, len(s.m))
	for r := range s.m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if c := a.Prefix().Addr().Compare(b.Prefix().Addr()); c != 0 {
			return c < 0
		}
		if a.Prefix().Bits() != b.Prefix().Bits() {
			return a.Prefix().Bits() < b.Prefix().Bits()
		}
		if a.Lo() != b.Lo() {
			return a.Lo() < b.Lo()
		}
		return a.Hi() < b.Hi()
	})
	return out
}

// String lists the ASNs in ascending order, e.g. "[AS1 AS2]".
func (s ASNSet) String() string { return listString(s.List()) }

// String lists the prefixes in List order.
func (s PrefixSet) String() string { return listString(s.List()) }

// String lists the ranges in List order, e.g. "[10.0.0.0/8 192.0.2.0/24^+]".
func (s RangeSet) String() string { return listString(s.List()) }

func listString[T fmt.Stringer](items []T) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = it.String()
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// RouterSet is the result of expanding an rtr-set: the distinct routers it
// denotes, by address or by inet-rtr name.
type RouterSet struct {
	m       map[types.RouterID]struct{}
	missing []types.SetName
}

func newRouterSet() *RouterSet { return &RouterSet{m: map[types.RouterID]struct{}{}} }

func (s *RouterSet) add(r types.RouterID) {
	if !r.IsZero() {
		s.m[r] = struct{}{}
	}
}

// Has reports whether the set contains r.
func (s RouterSet) Has(r types.RouterID) bool { _, ok := s.m[r]; return ok }

// Len returns the number of distinct routers.
func (s RouterSet) Len() int { return len(s.m) }

// Missing returns the nested sets that were not found, sorted.
func (s RouterSet) Missing() []types.SetName { return s.missing }

// List returns the routers sorted by their canonical text.
func (s RouterSet) List() []types.RouterID {
	out := make([]types.RouterID, 0, len(s.m))
	for r := range s.m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// String renders the routers as a comma-separated list.
func (s RouterSet) String() string { return listString(s.List()) }

// PeeringSet is the result of expanding a peering-set: the peerings it denotes,
// in discovery order, with duplicates removed by their canonical text.
type PeeringSet struct {
	list    []policy.Peering
	seen    map[string]bool
	missing []types.SetName
}

func newPeeringSet() *PeeringSet { return &PeeringSet{seen: map[string]bool{}} }

func (s *PeeringSet) add(p policy.Peering) {
	if p == nil {
		return
	}
	text := peeringText(p)
	if s.seen[text] {
		return
	}
	s.seen[text] = true
	s.list = append(s.list, p)
}

// Has reports whether the set contains a peering that renders as text.
func (s PeeringSet) Has(text string) bool { return s.seen[text] }

// Len returns the number of distinct peerings.
func (s PeeringSet) Len() int { return len(s.list) }

// Missing returns the nested sets that were not found, sorted.
func (s PeeringSet) Missing() []types.SetName { return s.missing }

// List returns the peerings in discovery order.
func (s PeeringSet) List() []policy.Peering {
	out := make([]policy.Peering, len(s.list))
	copy(out, s.list)
	return out
}

// Strings returns each peering's canonical text, in the same order as List.
func (s PeeringSet) Strings() []string {
	out := make([]string, len(s.list))
	for i, p := range s.list {
		out[i] = peeringText(p)
	}
	return out
}

// String renders the peerings as a space-separated list in brackets, as the
// other result types do.
func (s PeeringSet) String() string { return "[" + strings.Join(s.Strings(), " ") + "]" }

// peeringText is a peering's canonical text, the identity by which the result
// deduplicates.
func peeringText(p policy.Peering) string {
	if v, ok := p.(interface{ String() string }); ok {
		return v.String()
	}
	return fmt.Sprintf("%v", p)
}

// sortedNames returns a copy of ns sorted by canonical name.
func sortedNames(ns []types.SetName) []types.SetName {
	out := make([]types.SetName, len(ns))
	copy(out, ns)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
