package resolve

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// ASSet is a deduplicated set of ASNs produced by ExpandAS.
type ASSet struct {
	m       map[types.ASN]struct{}
	missing []types.SetName
}

// Missing lists the nested sets that were referenced but not found, sorted by
// canonical name. They expanded to nothing (as in bgpq4).
func (s ASSet) Missing() []types.SetName { return s.missing }

func newASSet() *ASSet { return &ASSet{m: make(map[types.ASN]struct{})} }

func (s *ASSet) add(a types.ASN) { s.m[a] = struct{}{} }

// Has reports membership.
func (s ASSet) Has(a types.ASN) bool { _, ok := s.m[a]; return ok }

// Len reports the number of distinct ASNs.
func (s ASSet) Len() int { return len(s.m) }

// List returns the ASNs in ascending order (deterministic for tests/output).
func (s ASSet) List() []types.ASN {
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
// ASSet.Missing.
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
// with le/ge bounds.
type RangeSet struct {
	m       map[types.PrefixRange]struct{}
	missing []types.SetName
}

func newRangeSet() *RangeSet { return &RangeSet{m: make(map[types.PrefixRange]struct{})} }

func (s *RangeSet) add(r types.PrefixRange) { s.m[r] = struct{}{} }

// Has reports membership.
func (s RangeSet) Has(r types.PrefixRange) bool { _, ok := s.m[r]; return ok }

// Len reports the number of distinct ranges.
func (s RangeSet) Len() int { return len(s.m) }

// Missing lists the nested sets that were referenced but not found; see
// ASSet.Missing.
func (s RangeSet) Missing() []types.SetName { return s.missing }

// List returns the ranges ordered by address, prefix length, then window.
func (s RangeSet) List() []types.PrefixRange {
	out := make([]types.PrefixRange, 0, len(s.m))
	for r := range s.m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c < 0
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() < b.Prefix.Bits()
		}
		if a.Lo != b.Lo {
			return a.Lo < b.Lo
		}
		return a.Hi < b.Hi
	})
	return out
}

// String lists the ASNs in ascending order, e.g. "[AS1 AS2]".
func (s ASSet) String() string { return listString(s.List()) }

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
