package rtconfig

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestBIRDImportGolden(t *testing.T) {
	s, p := fixturePolicy(t,
		"from AS2 action pref = 10; community.append(1:100); accept AS2 AND NOT {10.2.128.0/17}",
		"from AS2 accept ANY AND NOT community(2:666) AND <^AS2 .* AS-FOO$>",
	)
	var b bytes.Buffer
	if err := writeImport(&Generator{Vendor: BIRD2}, &b, s, p); err != nil {
		t.Fatal(err)
	}
	want := `filter MyMap_2_1 {
  if (net ~ [ 10.2.0.0/16 ]) then {
    bgp_local_pref = 990;
    bgp_community.add((1,100));
    accept;
  }
  if (bgp_path ~ [= 2 * [10, 11] =]) && !((2,666) ~ bgp_community) then {
    accept;
  }
  reject;
}
protocol bgp peer_10_0_0_2 {
  local 10.0.0.1 as 1;
  neighbor 10.0.0.2 as 2;
  ipv4 {
    import filter MyMap_2_1;
    export none;
  };
}
`
	if got := b.String(); got != want {
		t.Errorf("WriteImport+WriteSessions =\n%s\nwant\n%s", got, want)
	}
	for _, x := range []struct {
		r      cfgsim.Route
		accept bool
		attrs  cfgsim.Attrs
	}{
		{rt("10.2.0.0/16", []types.ASN{2}), true, cfgsim.Attrs{LocalPref: 990, MED: -1, Communities: []string{"1:100"}}},
		{rt("10.2.128.0/17", []types.ASN{2, 10}), true, cfgsim.Attrs{LocalPref: -1, MED: -1}},
		{rt("10.2.128.0/17", []types.ASN{2, 12}), false, cfgsim.Attrs{}},
		{rt("192.0.2.0/24", []types.ASN{2, 7, 11}, "2:666"), false, cfgsim.Attrs{}},
		{rt("192.0.2.0/24", []types.ASN{2, 7, 11}), true, cfgsim.Attrs{LocalPref: -1, MED: -1}},
	} {
		ok, a := simulate(t, BIRD2, b.String(), s, false, x.r)
		if ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%v: %v %+v; want %v %+v", x.r, ok, a, x.accept, x.attrs)
		}
	}
}

func TestBIRDCommunitiesAndActions(t *testing.T) {
	s, p := fixturePolicy(t, "from AS2 accept community == {1:2, 1:3}")
	var b bytes.Buffer
	if err := writeImport(&Generator{Vendor: BIRD2}, &b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		comms  []string
		accept bool
	}{
		{[]string{"1:2", "1:3"}, true},
		{[]string{"1:3", "1:2"}, true},
		{[]string{"1:2", "1:3", "1:4"}, false},
		{[]string{"1:2"}, false},
		{nil, false},
	} {
		if ok, _ := simulate(t, BIRD2, b.String(), s, false, rt("10.2.0.0/16", []types.ASN{2}, x.comms...)); ok != x.accept {
			t.Errorf("community == {1:2, 1:3} over %v: %v\n%s", x.comms, ok, b.String())
		}
	}

	b.Reset()
	s, p = fixturePolicy(t, "from AS2 action community = {5:5}; aspath.prepend(AS1, AS1, AS3); next-hop = 192.0.2.1; accept AS2")
	if err := writeImport(&Generator{Vendor: BIRD2}, &b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"    bgp_community = -empty-;\n    bgp_community.add((5,5));\n",
		"    bgp_path.prepend(3);\n    bgp_path.prepend(1);\n    bgp_path.prepend(1);\n", "    bgp_next_hop = 192.0.2.1;\n"} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}
	ok, a := simulate(t, BIRD2, b.String(), s, false, rt("10.2.0.0/16", []types.ASN{2}, "9:9"))
	want := cfgsim.Attrs{LocalPref: -1, MED: -1, Communities: []string{"5:5"}, Prepended: []types.ASN{1, 1, 3}, NextHop: "192.0.2.1"}
	if !ok || !reflect.DeepEqual(a, want) {
		t.Errorf("got %v %+v, want %+v\n%s", ok, a, want, b.String())
	}

	// An IPv6 next-hop, in an IPv6 session's filter.
	b.Reset()
	s, p = fixturePolicyFor(t, v6Session, "mp-import: afi ipv6.unicast from AS2 action next-hop = 2001:db8::1; accept AS2")
	if err := writeImport(&Generator{Vendor: BIRD2}, &b, s, p); err != nil {
		t.Fatal(err)
	}
	ok, a = simulate(t, BIRD2, b.String(), s, false, rt("2001:db8:2::/48", []types.ASN{2}))
	want = cfgsim.Attrs{LocalPref: -1, MED: -1, NextHop: "2001:db8::1"}
	if !ok || !reflect.DeepEqual(a, want) {
		t.Errorf("got %v %+v, want %+v\n%s", ok, a, want, b.String())
	}
}

// One protocol per neighbour, naming its import and export filters; a
// second WriteSessions writes nothing.
func TestBIRDSessions(t *testing.T) {
	g := &Generator{Vendor: BIRD2}
	var b bytes.Buffer
	s, p := fixturePolicy(t, "from AS2 accept AS2")
	if err := g.WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	if err := g.WriteExport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	s6, p6 := fixturePolicyFor(t, v6Session, "mp-import: afi ipv6.unicast from AS2 accept AS2")
	if err := g.WriteImport(&b, s6, p6); err != nil {
		t.Fatal(err)
	}
	if err := g.WriteSessions(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if n := strings.Count(out, "protocol bgp "); n != 2 {
		t.Errorf("%d protocols, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "  ipv4 {\n    import filter MyMap_2_1;\n    export filter MyMap_2_2;\n  };\n") {
		t.Errorf("the v4 neighbour's filters are not in one channel:\n%s", out)
	}
	c, err := cfgsim.Parse("bird", out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, x := range []struct {
		addr   string
		export bool
		name   string
	}{{"10.0.0.2", false, "MyMap_2_1"}, {"10.0.0.2", true, "MyMap_2_2"}, {"2001:db8::2", false, "MyMap_2_3"}} {
		if name, ok := c.Attached(netip.MustParseAddr(x.addr), x.export); !ok || name != x.name {
			t.Errorf("Attached(%s, %v) = %q, %v; want %s", x.addr, x.export, name, ok, x.name)
		}
	}
	if err := cfgsim.BIRDSyntax(out); err != nil && !errors.Is(err, cfgsim.ErrNoBIRD) {
		t.Error(err)
	}
	b.Reset()
	if err := g.WriteSessions(&b); err != nil || b.Len() != 0 {
		t.Errorf("a second WriteSessions wrote %q, %v", b.String(), err)
	}
}

func TestBIRDLists(t *testing.T) {
	g := &Generator{Vendor: BIRD2}
	_, p := fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24} AND NOT {10.2.0.0/16^+}")
	var b bytes.Buffer
	if err := g.WritePrefixList(&b, p.Clauses[0].Filter, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	_, p2 := fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24}")
	if err := g.WritePrefixList(&b, p2.Clauses[0].Filter, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	_, p3 := fixturePolicy(t, "from AS2 accept NOT <^AS2 .* AS-FOO$>")
	if err := g.WriteASPathList(&b, p3.Clauses[0].Filter.Conjuncts[0].Paths[0]); err != nil {
		t.Fatal(err)
	}
	want := "filter pl100 {\n  if (net ~ [ 10.0.0.0/8{16,24} ]) && !(net ~ [ 10.2.0.0/16+ ]) then accept;\n  reject;\n}\n" +
		"define pl101 = [ 10.0.0.0/8{16,24} ];\n" +
		"filter as100 {\n  if !(bgp_path ~ [= 2 * [10, 11] =]) then accept;\n  reject;\n}\n"
	if b.String() != want {
		t.Errorf("lists =\n%s\nwant\n%s", b.String(), want)
	}
	if err := cfgsim.BIRDSyntax(b.String()); err != nil && !errors.Is(err, cfgsim.ErrNoBIRD) {
		t.Error(err)
	}
	var ue *UnsupportedError
	if err := g.WriteNetworks(&b, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}); !errors.As(err, &ue) || ue.Cause != CauseNetworks {
		t.Errorf("WriteNetworks: %v", err)
	}
}
