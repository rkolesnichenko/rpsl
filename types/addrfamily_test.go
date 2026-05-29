package types

import "testing"

func TestParseAddrFamily(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		afi  AFI
		safi SAFI
		str  string
	}{
		{"ipv4.unicast", true, AFIv4, SAFIUnicast, "ipv4.unicast"},
		{"ipv6.unicast", true, AFIv6, SAFIUnicast, "ipv6.unicast"},
		{"any.unicast", true, AFIAny, SAFIUnicast, "any.unicast"},
		{"ipv4.multicast", true, AFIv4, SAFIMulticast, "ipv4.multicast"},
		{"any", true, AFIAny, SAFIUnspecified, "any"},
		{"ipv4", true, AFIv4, SAFIUnspecified, "ipv4"},
		{"IPv6.Unicast", true, AFIv6, SAFIUnicast, "ipv6.unicast"}, // case-insensitive
		{"ipv5", false, 0, 0, ""},
		{"ipv4.broadcast", false, 0, 0, ""},
		{"", false, 0, 0, ""},
	}
	for _, c := range cases {
		af, err := ParseAddrFamily(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseAddrFamily(%q) err=%v, ok=%v", c.in, err, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		if af.AFI != c.afi || af.SAFI != c.safi {
			t.Errorf("ParseAddrFamily(%q) = {afi=%v safi=%v}, want {%v %v}", c.in, af.AFI, af.SAFI, c.afi, c.safi)
		}
		if af.String() != c.str {
			t.Errorf("ParseAddrFamily(%q).String() = %q, want %q", c.in, af.String(), c.str)
		}
	}
}
