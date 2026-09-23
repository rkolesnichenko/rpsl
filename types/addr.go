package types

import (
	"net/netip"
	"strings"
)

// RPSL writes IPv4 addresses in dotted decimal (RFC 2622 §2), and registries
// hold some with zero-padded octets: ARIN's IRR has routes such as
// "064.006.160.000/19". netip rejects those, because C's inet_aton would read a
// leading zero as octal; RPSL has no octal, and IRRd reads the octets as
// decimal ("was reformatted as 64.6.160.0/19"). These functions read addresses
// the RPSL way. Everything else is netip's grammar, IPv6 included.

// ParseAddr parses an IP address. It is netip.ParseAddr, except that an IPv4
// octet may have leading zeros, read as decimal: "010.0.0.1" is 10.0.0.1.
func ParseAddr(s string) (netip.Addr, error) {
	if canon, ok := unpadIPv4(s); ok {
		s = canon
	}
	return netip.ParseAddr(s)
}

// ParsePrefix parses an IP prefix, reading zero-padded IPv4 octets as
// ParseAddr does.
func ParsePrefix(s string) (netip.Prefix, error) {
	if addr, bits, found := strings.Cut(s, "/"); found {
		if canon, ok := unpadIPv4(addr); ok {
			s = canon + "/" + bits
		}
	}
	return netip.ParsePrefix(s)
}

// PaddedIPv4 reports whether s — an address, or a prefix "a/n" — is IPv4 with
// an octet written with a leading zero, which ParseAddr and ParsePrefix read
// as decimal. A caller uses it to report the spelling.
func PaddedIPv4(s string) bool {
	addr, _, _ := strings.Cut(s, "/")
	_, ok := unpadIPv4(addr)
	return ok
}

// unpadIPv4 returns s with the leading zeros of its octets removed, and true,
// when s is four dot-separated runs of digits of which at least one has a
// leading zero. Anything else is left to netip, unchanged.
func unpadIPv4(s string) (string, bool) {
	octets := strings.Split(s, ".")
	if len(octets) != 4 {
		return "", false
	}
	padded := false
	for i, o := range octets {
		if o == "" || strings.Trim(o, "0123456789") != "" {
			return "", false
		}
		if len(o) > 1 && o[0] == '0' {
			padded = true
			if o = strings.TrimLeft(o, "0"); o == "" {
				o = "0"
			}
			octets[i] = o
		}
	}
	if !padded {
		return "", false
	}
	return strings.Join(octets, "."), true
}
