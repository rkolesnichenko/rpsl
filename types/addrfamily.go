package types

import (
	"fmt"
	"strings"
)

// AFI is an address-family identifier (RFC 4012 afi dictionary).
type AFI uint8

const (
	AFIUnspecified AFI = iota // no afi clause: legacy import:/export:
	AFIv4                     // ipv4
	AFIv6                     // ipv6
	AFIAny                    // any
)

func (a AFI) String() string {
	switch a {
	case AFIv4:
		return "ipv4"
	case AFIv6:
		return "ipv6"
	case AFIAny:
		return "any"
	default:
		return "unspecified"
	}
}

// SAFI is a subsequent address-family identifier.
type SAFI uint8

const (
	SAFIUnspecified SAFI = iota // no sub-family given (defaults to unicast in practice)
	SAFIUnicast                 // unicast
	SAFIMulticast               // multicast
	SAFIAny                     // any
)

func (s SAFI) String() string {
	switch s {
	case SAFIUnicast:
		return "unicast"
	case SAFIMulticast:
		return "multicast"
	case SAFIAny:
		return "any"
	default:
		return "unspecified"
	}
}

// AddrFamily is an RFC 4012 address family such as "ipv4.unicast" or "any". It
// is comparable so it works as a map key and in the expansion engine's AFI
// constraint.
type AddrFamily struct {
	AFI  AFI
	SAFI SAFI
}

// ParseAddrFamily parses an afi token: "ipv4", "ipv6", "any" optionally suffixed
// with ".unicast", ".multicast", or ".any". It is case-insensitive.
func ParseAddrFamily(s string) (AddrFamily, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return AddrFamily{}, fmt.Errorf("rpsl/types: invalid afi: empty")
	}
	left, right, hasDot := strings.Cut(t, ".")

	var af AddrFamily
	switch left {
	case "ipv4":
		af.AFI = AFIv4
	case "ipv6":
		af.AFI = AFIv6
	case "any":
		af.AFI = AFIAny
	default:
		return AddrFamily{}, fmt.Errorf("rpsl/types: invalid afi %q: unknown address family %q", s, left)
	}

	if !hasDot {
		af.SAFI = SAFIUnspecified
		return af, nil
	}
	switch right {
	case "unicast":
		af.SAFI = SAFIUnicast
	case "multicast":
		af.SAFI = SAFIMulticast
	case "any":
		af.SAFI = SAFIAny
	default:
		return AddrFamily{}, fmt.Errorf("rpsl/types: invalid afi %q: unknown sub-family %q", s, right)
	}
	return af, nil
}

// String renders the address family back to its canonical text form. A family
// with an unspecified sub-family renders as just the AFI (e.g. "any", "ipv4").
func (a AddrFamily) String() string {
	if a.SAFI == SAFIUnspecified {
		return a.AFI.String()
	}
	return a.AFI.String() + "." + a.SAFI.String()
}

// Covers reports whether address family a (which may be a wildcard such as
// "any" or "ipv4.any") includes the concrete family b. AFIAny covers any AFI;
// SAFIAny or SAFIUnspecified covers any SAFI; otherwise the components must
// match exactly.
func (a AddrFamily) Covers(b AddrFamily) bool {
	if a.AFI != AFIAny && a.AFI != b.AFI {
		return false
	}
	if a.SAFI != SAFIAny && a.SAFI != SAFIUnspecified && a.SAFI != b.SAFI {
		return false
	}
	return true
}
