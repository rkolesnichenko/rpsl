// Package rpki makes set expansion RPKI-aware the way IRRd 4 is. IRRd checks
// every route and route6 object with RFC 6811 origin validation against the
// ROAs it imports, and suppresses the invalid ones — they vanish from query
// answers, database exports and NRTM — and it serves each ROA as a pseudo
// route object with "source: RPKI". RADB lists RPKI among its default sources,
// so bgpq4 against RADB sees both effects; a registry's own dump, a RIPE
// whois server or an older IRRd shows neither.
//
// VRPs holds the validated ROA payloads, as a relying-party validator exports
// them (ReadJSON), optionally amended by an RFC 8416 SLURM file (ApplySLURM).
// Filter wraps any resolve.Source and drops what IRRd would suppress, and
// WriteRPSL writes IRRd's pseudo objects as a dump, for resolve.DumpLoader to
// read as the registry RPKI.
//
// Like the rest of the resolve module this package opens no sockets: fetching
// the VRPs, and deciding how fresh they must be, is the caller's business.
package rpki

import (
	"fmt"
	"iter"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/types"
)

// VRP is one validated ROA payload (RFC 6811 §2): AS ASN may originate Prefix
// and its more specifics up to MaxLength bits.
type VRP struct {
	Prefix    netip.Prefix // canonical: host bits clear
	MaxLength uint8        // Prefix.Bits() <= MaxLength <= 32 (IPv4) or 128 (IPv6)
	ASN       types.ASN    // 0: an AS0 ROA, which covers but never matches (RFC 6483 §4)
	TA        string       // trust anchor as the validator reported it; "SLURM file" for a SLURM assertion
}

// State is a route's RFC 6811 validation state.
type State uint8

const (
	NotFound State = iota // no VRP covers the route's prefix
	Valid                 // a covering VRP names the origin and allows the length
	Invalid               // VRPs cover the prefix, and none of them matches
)

// String returns the state as IRRd spells it in rpki-ov-state:.
func (s State) String() string {
	switch s {
	case NotFound:
		return "not_found"
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

// VRPs is an immutable, indexed set of VRPs, safe for concurrent use. The zero
// value and nil hold none.
type VRPs struct {
	all []VRP
	v4  family
	v6  family
}

// family indexes one address family's VRPs by exact prefix, with a bitmask of
// the prefix lengths present so that Validate looks up only lengths that have
// VRPs — real data uses a few dozen of IPv6's 129.
type family struct {
	byPrefix map[netip.Prefix][]grant
	lengths  [3]uint64 // bit n: some VRP has length n
}

type grant struct {
	maxLength uint8
	asn       types.ASN
}

// NewVRPs indexes vs, keeping their order for All. It refuses a VRP whose
// prefix is not valid and canonical, or whose MaxLength is shorter than the
// prefix or longer than the family allows.
func NewVRPs(vs []VRP) (*VRPs, error) {
	return indexVRPs(append([]VRP(nil), vs...))
}

// indexVRPs is NewVRPs over a slice it may keep: ReadJSON's and ApplySLURM's
// own, so that half a million VRPs are not held twice.
func indexVRPs(vs []VRP) (*VRPs, error) {
	s := &VRPs{all: vs}
	for i, v := range s.all {
		if err := check(v); err != nil {
			return nil, fmt.Errorf("rpki: VRP %d: %w", i, err)
		}
		s.fam(v.Prefix).add(v)
	}
	return s, nil
}

func check(v VRP) error {
	if !v.Prefix.IsValid() {
		return fmt.Errorf("no prefix")
	}
	if v.Prefix != v.Prefix.Masked() {
		return fmt.Errorf("prefix %s has host bits set", v.Prefix)
	}
	if int(v.MaxLength) < v.Prefix.Bits() || int(v.MaxLength) > v.Prefix.Addr().BitLen() {
		return fmt.Errorf("max length %d outside /%d to /%d for %s", v.MaxLength, v.Prefix.Bits(), v.Prefix.Addr().BitLen(), v.Prefix)
	}
	return nil
}

func (s *VRPs) fam(p netip.Prefix) *family {
	if p.Addr().Is4() {
		return &s.v4
	}
	return &s.v6
}

func (f *family) add(v VRP) {
	if f.byPrefix == nil {
		f.byPrefix = map[netip.Prefix][]grant{}
	}
	f.byPrefix[v.Prefix] = append(f.byPrefix[v.Prefix], grant{v.MaxLength, v.ASN})
	f.lengths[v.Prefix.Bits()/64] |= 1 << (v.Prefix.Bits() % 64)
}

// Validate returns the RFC 6811 state of a route for prefix p originated by
// origin, as IRRd computes it: Valid when a VRP covering p names origin, which
// is not 0, with a MaxLength of at least p's length; Invalid when VRPs cover p
// but none matches; NotFound when none covers it. A VRP covers p when its
// prefix is p or less specific, in the same family. p is read as its canonical
// prefix; the zero Prefix is NotFound.
func (s *VRPs) Validate(p netip.Prefix, origin types.ASN) State {
	if s == nil || !p.IsValid() {
		return NotFound
	}
	f := s.fam(p)
	covered := false
	for l := 0; l <= p.Bits(); l++ {
		if f.lengths[l/64]&(1<<(l%64)) == 0 {
			continue
		}
		q, _ := p.Addr().Prefix(l)
		for _, g := range f.byPrefix[q] {
			if g.asn != 0 && g.asn == origin && p.Bits() <= int(g.maxLength) {
				return Valid
			}
			covered = true
		}
	}
	if covered {
		return Invalid
	}
	return NotFound
}

// Len returns the number of VRPs.
func (s *VRPs) Len() int {
	if s == nil {
		return 0
	}
	return len(s.all)
}

// All yields the VRPs in the order they were given or read.
func (s *VRPs) All() iter.Seq[VRP] {
	return func(yield func(VRP) bool) {
		if s == nil {
			return
		}
		for _, v := range s.all {
			if !yield(v) {
				return
			}
		}
	}
}
