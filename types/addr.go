package types

import (
	"net/netip"
	"strconv"
	"strings"
)

// RPSL writes IPv4 addresses in dotted decimal (RFC 2622 §2), and registries
// hold some with zero-padded octets: ARIN's IRR has routes such as
// "064.006.160.000/19". netip rejects those, because C's inet_aton would read a
// leading zero as octal; RPSL has no octal, and IRRd reads the octets as
// decimal ("was reformatted as 64.6.160.0/19"). Registries also hold IPv4
// prefixes with fewer than four octets, "143.208.148/22" in RADB route-sets,
// which IRRd (through Python's IPy) reads with the missing octets zero. These
// functions read addresses the RPSL way. Everything else is netip's grammar,
// IPv6 included.

// ParseAddr parses an IP address. It is netip.ParseAddr, except that an IPv4
// octet may have leading zeros, read as decimal: "010.0.0.1" is 10.0.0.1.
func ParseAddr(s string) (netip.Addr, error) {
	if canon, ok := unpadIPv4(s); ok {
		s = canon
	}
	return netip.ParseAddr(s)
}

// ParsePrefix parses an IP prefix, reading zero-padded IPv4 octets as
// ParseAddr does, and an IPv4 prefix of fewer than four octets with the
// missing ones zero: "143.208.148/22" is 143.208.148.0/22 and "10/8" is
// 10.0.0.0/8. The length is required; a short address alone is not a prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	if addr, bits, found := strings.Cut(s, "/"); found {
		addr = fillIPv4(addr, bits)
		if canon, ok := unpadIPv4(addr); ok {
			addr = canon
		}
		s = addr + "/" + bits
	}
	return netip.ParsePrefix(s)
}

// PaddedIPv4 reports whether s — an address, or a prefix "a/n" — is IPv4 with
// an octet written with a leading zero, which ParseAddr and ParsePrefix read
// as decimal. A caller uses it to report the spelling.
func PaddedIPv4(s string) bool {
	addr, bits, found := strings.Cut(s, "/")
	if found {
		addr = fillIPv4(addr, bits)
	}
	_, ok := unpadIPv4(addr)
	return ok
}

// AbbreviatedIPv4 reports whether s is an IPv4 prefix written with fewer than
// four octets ("143.208.148/22", "10/8"), which ParsePrefix reads with the
// missing octets zero. A caller uses it to report the spelling.
func AbbreviatedIPv4(s string) bool {
	addr, bits, found := strings.Cut(s, "/")
	return found && fillIPv4(addr, bits) != addr
}

// fillIPv4 returns addr with ".0" appended up to four octets when addr is one
// to three dot-separated decimal octets (each at most 255, zero-padding
// allowed) and bits is a run of digits; otherwise it returns addr unchanged.
// A single number of 256 or more — an address as a 32-bit integer, to Python's
// IPy — is not an octet, so it is left for netip to reject.
func fillIPv4(addr, bits string) string {
	if bits == "" || strings.Trim(bits, "0123456789") != "" {
		return addr
	}
	octets := strings.Split(addr, ".")
	if len(octets) > 3 {
		return addr
	}
	for _, o := range octets {
		if o == "" || strings.Trim(o, "0123456789") != "" {
			return addr
		}
		if v, err := strconv.Atoi(o); err != nil || v > 255 {
			return addr
		}
	}
	return addr + strings.Repeat(".0", 4-len(octets))
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
