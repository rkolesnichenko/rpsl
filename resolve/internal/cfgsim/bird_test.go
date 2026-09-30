package cfgsim

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

const birdSample = `
filter F {
  if (net ~ [ 10.0.0.0/8{16,24}, 192.0.2.0/24+ ]) && !(net ~ [ 10.2.0.0/16+ ]) then {
    if ((1,1) ~ bgp_community) && !((6,6) ~ bgp_community) then {
      bgp_local_pref = 900;
      bgp_community.add((7,7));
      bgp_community.delete((1,1));
      bgp_path.prepend(3);
      bgp_path.prepend(1);
      bgp_path.prepend(1);
      accept;
    }
    if (bgp_path ~ [= 2 * [10, 11] =]) then {
      bgp_med = 5;
      bgp_next_hop = 192.0.2.1;
      accept;
    }
  }
  if ((delete(bgp_community, [ (9,9), (9,10) ]).len = 0) && ((9,9) ~ bgp_community) && ((9,10) ~ bgp_community)) then {
    bgp_community = -empty-;
    accept;
  }
  if (bgp_community.len = 0) && (net ~ [ 172.31.0.0/16 ]) then accept;
  reject;
}
protocol bgp peer_10_0_0_2 {
  local 10.0.0.1 as 1;
  neighbor 10.0.0.2 as 2;
  ipv4 {
    import filter F;
    export none;
  };
}
`

func TestBIRDFilters(t *testing.T) {
	c, err := ParseBIRD(birdSample)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), false); !ok || name != "F" {
		t.Errorf("import filter %q, %v", name, ok)
	}
	if _, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), true); ok {
		t.Errorf("export none attached a filter")
	}
	for _, x := range []struct {
		r      Route
		accept bool
		attrs  Attrs
	}{
		{route("10.1.0.0/16", []types.ASN{2}, "1:1"), true,
			Attrs{LocalPref: 900, MED: -1, Communities: []string{"7:7"}, Prepended: []types.ASN{1, 1, 3}}},
		{route("10.1.0.0/16", []types.ASN{2, 10}), true, Attrs{LocalPref: -1, MED: 5, NextHop: "192.0.2.1"}},
		{route("192.0.2.128/25", []types.ASN{2, 11}), true, Attrs{LocalPref: -1, MED: 5, NextHop: "192.0.2.1"}},
		{route("10.2.1.0/24", []types.ASN{2, 10}), false, Attrs{}},
		{route("172.16.0.0/16", []types.ASN{2}, "9:9", "9:10"), true, Attrs{LocalPref: -1, MED: -1}},
		{route("172.16.0.0/16", []types.ASN{2}, "9:9", "9:10", "9:11"), false, Attrs{}},
		{route("172.31.0.0/16", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: -1}},
		{route("172.31.0.0/16", []types.ASN{2}, "1:1"), false, Attrs{}},
	} {
		ok, a, err := c.Policy("F", x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("F(%v) = %v %+v, %v; want %v %+v", x.r, ok, a, err, x.accept, x.attrs)
		}
	}
}

// BIRD's &&, ||, = and ~ share one precedence: an unparenthesized test is a
// type error on the router, and in cfgsim.
func TestBIRDFlatPrecedence(t *testing.T) {
	c, err := ParseBIRD("filter G {\n  if net ~ [ 10.0.0.0/8+ ] && bgp_path ~ [= * =] then accept;\n  reject;\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Policy("G", route("10.1.0.0/16", []types.ASN{2})); err == nil {
		t.Errorf("an unparenthesized test evaluated")
	}
	for _, bad := range []string{
		"filter F { accept; }\nfilter F { reject; }\n",
		"filter F { frob; }\n",
		"filter F { if (net ~ [ 10.0.0.0/8+ ]) then { accept; }\n",
		"protocol bgp p { ipv4 { import filter F; }; }\n",
		"frobnicate;\n",
	} {
		if _, err := ParseBIRD(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestBIRDSyntax(t *testing.T) {
	err := BIRDSyntax(birdSample)
	if errors.Is(err, ErrNoBIRD) {
		t.Skip("bird is not installed")
	}
	if err != nil {
		t.Errorf("bird -p refuses the sample: %v", err)
	}
	if BIRDSyntax("filter X { frob; }\n") == nil {
		t.Errorf("bird -p accepted nonsense")
	}
}
