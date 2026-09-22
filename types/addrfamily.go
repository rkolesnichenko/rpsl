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

// String returns "ipv4", "ipv6", "any" or "unspecified".
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
	SAFIUnspecified SAFI = iota // no sub-family given: unicast and multicast (RFC 4012 §2.2)
	SAFIUnicast                 // unicast
	SAFIMulticast               // multicast
)

// String returns "unicast", "multicast" or "unspecified".
func (s SAFI) String() string {
	switch s {
	case SAFIUnicast:
		return "unicast"
	case SAFIMulticast:
		return "multicast"
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

// ParseAddrFamily parses an RFC 4012 afi token: "ipv4", "ipv6" or "any",
// optionally suffixed with ".unicast" or ".multicast". It is case-insensitive.
func ParseAddrFamily(s string) (AddrFamily, error) {
	t := strings.ToLower(strings.Trim(s, " \t"))
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
// "any" or "ipv4") includes the concrete family b. AFIAny covers any AFI and
// SAFIUnspecified covers unicast and multicast (RFC 4012 §2.2); otherwise the
// components must match exactly.
func (a AddrFamily) Covers(b AddrFamily) bool {
	if a.AFI != AFIAny && a.AFI != b.AFI {
		return false
	}
	if a.SAFI != SAFIUnspecified && a.SAFI != b.SAFI {
		return false
	}
	return true
}
