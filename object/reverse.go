package object

import (
	"net/netip"
	"strconv"
	"strings"
)

// ReverseRange returns the addresses a reverse-delegation domain covers: an
// in-addr.arpa zone of one to four octets, RIPE's range form of a /24's
// addresses ("0-127.2.0.192.in-addr.arpa", only in the first of four labels),
// or an ip6.arpa zone of nibbles. ok is false for any other name, e164.arpa
// among them. Names compare without regard to case or a trailing dot.
func (d Domain) ReverseRange() (lo, hi netip.Addr, ok bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Name), "."))
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		return reverseV4(strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), "."))
	case strings.HasSuffix(name, ".ip6.arpa"):
		return reverseV6(strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), "."))
	}
	return netip.Addr{}, netip.Addr{}, false
}

// reverseV4 reads in-addr.arpa labels, least significant octet first.
func reverseV4(labels []string) (lo, hi netip.Addr, ok bool) {
	if len(labels) < 1 || len(labels) > 4 {
		return
	}
	var from, to [4]byte
	for i, l := range labels {
		octet := len(labels) - 1 - i
		a, b, isRange := strings.Cut(l, "-")
		if isRange && (i != 0 || len(labels) != 4) {
			return // a range stands only for the last octet of a full address
		}
		x, okA := parseOctet(a)
		y := x
		if isRange {
			var okB bool
			if y, okB = parseOctet(b); !okB || y < x {
				return
			}
		}
		if !okA {
			return
		}
		from[octet], to[octet] = x, y
	}
	for i := len(labels); i < 4; i++ {
		from[i], to[i] = 0, 255
	}
	return netip.AddrFrom4(from), netip.AddrFrom4(to), true
}

// parseOctet reads a decimal octet written without leading zeros, as DNS
// labels of a reverse zone are.
func parseOctet(s string) (byte, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 255 {
		return 0, false
	}
	return byte(n), true
}

// reverseV6 reads ip6.arpa nibble labels, least significant nibble first.
func reverseV6(labels []string) (lo, hi netip.Addr, ok bool) {
	if len(labels) < 1 || len(labels) > 32 {
		return
	}
	var from, to [16]byte
	n := len(labels)
	for i, l := range labels {
		if len(l) != 1 {
			return
		}
		v, err := strconv.ParseUint(l, 16, 8)
		if err != nil {
			return
		}
		pos := n - 1 - i // nibble index from the most significant
		from[pos/2] |= byte(v) << (4 * (1 - pos%2))
	}
	to = from
	for pos := n; pos < 32; pos++ {
		to[pos/2] |= 0xf << (4 * (1 - pos%2))
	}
	return netip.AddrFrom16(from), netip.AddrFrom16(to), true
}
