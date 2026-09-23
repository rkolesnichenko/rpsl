package types

import (
	"net/netip"
	"testing"
)

// RPSL addresses are dotted decimal (RFC 2622 §2): a zero-padded octet is
// decimal, as IRRd reads it, never octal.
func TestParseAddrAndPrefix(t *testing.T) {
	for _, c := range []struct {
		in     string
		want   string // "" for an error
		padded bool
	}{
		{"064.006.160.000", "64.6.160.0", true},
		{"010.0.0.1", "10.0.0.1", true}, // decimal ten, not octal eight
		{"0192.0.2.1", "192.0.2.1", true},
		{"192.000.002.001", "192.0.2.1", true},
		{"192.0.2.1", "192.0.2.1", false},
		{"0.0.0.0", "0.0.0.0", false},
		{"256.0.0.1", "", false},
		{"0256.0.0.1", "", true},
		{"1.2.3", "", false},
		{"1..2.3", "", false},
		{"1.2.3.4.5", "", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"2001:0db8::0001", "2001:db8::1", false}, // IPv6 groups may always be padded
		{"::ffff:010.0.0.1", "", false},           // IPv4 inside IPv6 stays strict
	} {
		a, err := ParseAddr(c.in)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("ParseAddr(%q) = %v, want an error", c.in, a)
		case c.want != "" && (err != nil || a.String() != c.want):
			t.Errorf("ParseAddr(%q) = %v, %v; want %s", c.in, a, err, c.want)
		}
		if got := PaddedIPv4(c.in); got != c.padded {
			t.Errorf("PaddedIPv4(%q) = %v, want %v", c.in, got, c.padded)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"064.006.160.000/19", "64.6.160.0/19"},
		{"010.0.0.0/8", "10.0.0.0/8"},
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"2001:0db8::/32", "2001:db8::/32"},
		{"256.0.0.0/8", ""},
		{"064.006.160.000/33", ""},
		{"064.006.160.000", ""}, // an address is not a prefix
	} {
		p, err := ParsePrefix(c.in)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("ParsePrefix(%q) = %v, want an error", c.in, p)
		case c.want != "" && (err != nil || p.String() != c.want):
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", c.in, p, err, c.want)
		}
	}
	if !PaddedIPv4("064.006.160.000/19") || PaddedIPv4("64.6.160.0/19") {
		t.Error("PaddedIPv4 misjudges a prefix")
	}
}

// ParsePrefixRange and ParseRouterID read addresses with the same grammar.
func TestPaddedOctetsInRangesAndRouters(t *testing.T) {
	r, err := ParsePrefixRange("064.006.160.000/19^+")
	if err != nil || r.String() != "64.6.160.0/19^+" {
		t.Errorf("ParsePrefixRange = %v, %v; want 64.6.160.0/19^+", r, err)
	}
	id, err := ParseRouterID("010.000.000.001")
	if a, ok := id.Addr(); err != nil || !ok || a != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("ParseRouterID = %v, %v; want the address 10.0.0.1", id, err)
	}
}
