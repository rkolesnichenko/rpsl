package types

import "testing"

func TestAddrFamilyCovers(t *testing.T) {
	v4u := AddrFamily{AFI: AFIv4, SAFI: SAFIUnicast}
	v6u := AddrFamily{AFI: AFIv6, SAFI: SAFIUnicast}
	v4m := AddrFamily{AFI: AFIv4, SAFI: SAFIMulticast}

	cases := []struct {
		name string
		a, b AddrFamily
		want bool
	}{
		{"exact", v4u, v4u, true},
		{"afi-any covers v4", AddrFamily{AFIAny, SAFIUnicast}, v4u, true},
		{"afi-any covers v6", AddrFamily{AFIAny, SAFIUnicast}, v6u, true},
		{"safi-unspecified covers unicast", AddrFamily{AFIv4, SAFIUnspecified}, v4u, true},
		{"safi-any covers multicast", AddrFamily{AFIv4, SAFIAny}, v4m, true},
		{"any.any covers v6.multicast", AddrFamily{AFIAny, SAFIAny}, AddrFamily{AFIv6, SAFIMulticast}, true},
		{"v4 does not cover v6", v4u, v6u, false},
		{"unicast does not cover multicast", v4u, v4m, false},
	}
	for _, c := range cases {
		if got := c.a.Covers(c.b); got != c.want {
			t.Errorf("%s: %v.Covers(%v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}
