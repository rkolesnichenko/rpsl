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
	// Lists alone, as WritePrefixList and WriteASPathList write them, name no
	// protocol, which bird -p refuses on its own: BIRDSyntax supplies one.
	lists := "filter pl100 {\n  if (net ~ [ 10.0.0.0/8{16,24} ]) then accept;\n  reject;\n}\n" +
		"define pl101 = [ 10.0.0.0/8{16,24} ];\n"
	if err := BIRDSyntax(lists); err != nil {
		t.Errorf("bird -p refuses lists without a protocol: %v", err)
	}
	for _, bad := range []string{"filter X { frob; }\n", "filter X { frob; }\n" + birdSample} {
		if BIRDSyntax(bad) == nil {
			t.Errorf("bird -p accepted nonsense %q", bad)
		}
	}
}

// TestBIRDIfElse checks both arms of if/then/else, in block form and as the
// single-statement form ("if E then accept; else reject;").
func TestBIRDIfElse(t *testing.T) {
	c, err := ParseBIRD(`
filter I {
  if (net ~ [ 10.0.0.0/8+ ]) then {
    bgp_local_pref = 100;
    accept;
  } else {
    bgp_local_pref = 200;
    accept;
  }
  reject;
}
filter J {
  if (net ~ [ 10.0.0.0/8+ ]) then accept; else reject;
}
`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, a, err := c.Policy("I", route("10.1.0.0/16", nil)); err != nil || !ok || !reflect.DeepEqual(a, Attrs{LocalPref: 100, MED: -1}) {
		t.Errorf("I(10.1.0.0/16) = %v %+v, %v; want the then-branch, LocalPref 100", ok, a, err)
	}
	if ok, a, err := c.Policy("I", route("192.0.2.0/24", nil)); err != nil || !ok || !reflect.DeepEqual(a, Attrs{LocalPref: 200, MED: -1}) {
		t.Errorf("I(192.0.2.0/24) = %v %+v, %v; want the else-branch, LocalPref 200", ok, a, err)
	}
	if ok, _, err := c.Policy("J", route("10.1.0.0/16", nil)); err != nil || !ok {
		t.Errorf("J(10.1.0.0/16) = %v, %v; want the then-branch, accept", ok, err)
	}
	if ok, _, err := c.Policy("J", route("192.0.2.0/24", nil)); err != nil || ok {
		t.Errorf("J(192.0.2.0/24) = %v, %v; want the else-branch, reject", ok, err)
	}
}

// TestBIRDFallOffEnd checks a top-level filter with no trailing reject;: a
// non-matching route falls off the end and is rejected; a matching one is
// still accepted by its own if.
func TestBIRDFallOffEnd(t *testing.T) {
	c, err := ParseBIRD("filter H {\n  if (net ~ [ 10.0.0.0/8+ ]) then accept;\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := c.Policy("H", route("10.1.0.0/16", nil)); err != nil || !ok {
		t.Errorf("H(10.1.0.0/16) = %v, %v; want accept", ok, err)
	}
	if ok, a, err := c.Policy("H", route("192.0.2.0/24", nil)); err != nil || ok || !reflect.DeepEqual(a, Attrs{}) {
		t.Errorf("H(192.0.2.0/24) = %v %+v, %v; want reject (falling off the end)", ok, a, err)
	}
}

// TestBIRDRouterID checks the top-level "router id X;" is accepted (and
// skipped), and that a malformed one missing its ";" is an error.
func TestBIRDRouterID(t *testing.T) {
	c, err := ParseBIRD("router id 10.0.0.1;\nfilter K {\n  accept;\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := c.Policy("K", route("10.0.0.0/8", nil)); err != nil || !ok {
		t.Errorf("K(...) = %v, %v; want accept", ok, err)
	}
	if _, err := ParseBIRD("router id 10.0.0.1\nfilter K {\n  accept;\n}\n"); err == nil {
		t.Errorf("\"router id\" without a semicolon parsed")
	}
}

// TestBIRDDuplicateProtocol checks a protocol defined twice under one name
// is refused, as BIRD itself refuses it.
func TestBIRDDuplicateProtocol(t *testing.T) {
	_, err := ParseBIRD("protocol bgp P {\n  neighbor 10.0.0.2 as 2;\n}\nprotocol bgp P {\n  neighbor 10.0.0.3 as 3;\n}\n")
	if err == nil {
		t.Errorf("a protocol defined twice under one name parsed")
	}
}

// TestBIRDLiteralsAndAll checks true/false literals in a condition, and
// "import all;"/"export all;" in a channel, which attach nothing.
func TestBIRDLiteralsAndAll(t *testing.T) {
	c, err := ParseBIRD(`
filter T {
  if false then {
    bgp_local_pref = 111;
    accept;
  }
  if true then {
    bgp_local_pref = 222;
    accept;
  }
  reject;
}
protocol bgp Q {
  neighbor 10.0.0.4 as 4;
  ipv4 {
    import all;
    export all;
  };
}
`)
	if err != nil {
		t.Fatal(err)
	}
	want := Attrs{LocalPref: 222, MED: -1}
	if ok, a, err := c.Policy("T", route("10.0.0.0/8", nil)); err != nil || !ok || !reflect.DeepEqual(a, want) {
		t.Errorf("T(...) = %v %+v, %v; want %+v (the \"if true\" branch, \"if false\" skipped)", ok, a, err, want)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.4"), false); ok {
		t.Errorf("import all attached filter %q", name)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.4"), true); ok {
		t.Errorf("export all attached filter %q", name)
	}
}

// TestBIRDTruncatedInputs checks that truncated input is diagnosed, never
// panics.
func TestBIRDTruncatedInputs(t *testing.T) {
	for _, in := range []string{
		"filter F { if (net ~",
		"filter F { bgp_med =",
		"protocol bgp p { neighbor",
		"filter F { if (",
	} {
		in := in
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseBIRD(%q) panicked: %v", in, r)
				}
			}()
			if _, err := ParseBIRD(in); err == nil {
				t.Errorf("ParseBIRD(%q) parsed", in)
			}
		}()
	}
}
