package resolve

import (
	"net/netip"
	"sort"

	"github.com/rkolesnichenko/rpsl/types"
)

// ASSet is a deduplicated set of ASNs produced by ExpandAS.
type ASSet struct {
	m map[types.ASN]struct{}
}

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
	m map[netip.Prefix]struct{}
}

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
