package rtconfig

import (
	"bytes"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestXRImportGolden(t *testing.T) {
	s, p := fixturePolicy(t,
		"from AS2 action pref = 10; community.append(1:100); accept AS2 AND NOT {10.2.128.0/17}",
		"from AS2 accept ANY AND NOT community(2:666) AND <^AS2 AS-FOO*$>",
	)
	var b bytes.Buffer
	if err := (&Generator{Vendor: IOSXR}).WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	want := `!
prefix-set pl100-permit
  10.2.0.0/16
end-set
!
as-path-set as100
  ios-regex '^_2(_(10|11))*$'
end-set
!
community-set cs100
  2:666
end-set
!
route-policy MyMap_2_1
  if destination in pl100-permit then
    set local-preference 990
    set community (1:100) additive
    done
  endif
  if as-path in as100 and not community matches-every cs100 then
    done
  endif
  drop
end-policy
!
router bgp 1
 neighbor 10.0.0.2
  remote-as 2
  address-family ipv4 unicast
   route-policy MyMap_2_1 in
  !
 !
!
`
	if got := b.String(); got != want {
		t.Errorf("WriteImport =\n%s\nwant\n%s", got, want)
	}
	for _, x := range []struct {
		r      cfgsim.Route
		accept bool
		attrs  cfgsim.Attrs
	}{
		{rt("10.2.0.0/16", []types.ASN{2}), true, cfgsim.Attrs{LocalPref: 990, MED: -1, Communities: []string{"1:100"}}},
		{rt("10.2.128.0/17", []types.ASN{2, 10}), true, cfgsim.Attrs{LocalPref: -1, MED: -1}},
		{rt("10.2.128.0/17", []types.ASN{2, 12}), false, cfgsim.Attrs{}},
		{rt("192.0.2.0/24", []types.ASN{2, 11}, "2:666"), false, cfgsim.Attrs{}},
		// No community at all: "not matches-every" holds (D11 is rtconfig's).
		{rt("192.0.2.0/24", []types.ASN{2, 11}), true, cfgsim.Attrs{LocalPref: -1, MED: -1}},
	} {
		ok, a := simulate(t, IOSXR, b.String(), s, false, x.r)
		if ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%v: %v %+v; want %v %+v", x.r, ok, a, x.accept, x.attrs)
		}
	}
}

func TestXRActionsAndV6(t *testing.T) {
	g := &Generator{Vendor: IOSXR}
	s, p := fixturePolicy(t, "from AS2 action aspath.prepend(AS1, AS1, AS3); med = igp_cost; next-hop = self; community = {}; accept AS2")
	var b bytes.Buffer
	if err := g.WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"    prepend as-path 3 1\n    prepend as-path 1 2\n", "    set med igp-cost\n",
		"    delete community all\n", "    set next-hop self\n"} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}
	ok, a := simulate(t, IOSXR, b.String(), s, false, rt("10.2.0.0/16", []types.ASN{2}, "5:5"))
	want := cfgsim.Attrs{LocalPref: -1, MED: -1, MEDIGP: true, Prepended: []types.ASN{1, 1, 3}, NextHop: "self"}
	if !ok || !reflect.DeepEqual(a, want) {
		t.Errorf("got %v %+v, want %+v\n%s", ok, a, want, b.String())
	}

	b.Reset()
	s, p = fixturePolicyFor(t, v6Session, "mp-import: afi ipv6.unicast from AS2 accept AS2")
	if err := g.WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"  2001:db8:2::/48\n", " neighbor 2001:db8::2\n", "  address-family ipv6 unicast\n"} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}
	if ok, _ := simulate(t, IOSXR, b.String(), s, false, rt("2001:db8:2::/48", []types.ASN{2})); !ok {
		t.Errorf("v6 route refused:\n%s", b.String())
	}
}

func TestXRListsAndNetworks(t *testing.T) {
	g := &Generator{Vendor: IOSXR}
	_, p := fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24} AND NOT {10.2.0.0/16^+}")
	var b bytes.Buffer
	if err := g.WritePrefixList(&b, p.Clauses[0].Filter, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	want := "!\nprefix-set pl100-permit\n  10.0.0.0/8 ge 16 le 24\nend-set\n" +
		"!\nprefix-set pl100-deny\n  10.2.0.0/16 le 32\nend-set\n" +
		"!\nroute-policy pl100\n  if destination in pl100-permit and not destination in pl100-deny then\n" +
		"    done\n  endif\n  drop\nend-policy\n"
	if b.String() != want {
		t.Errorf("WritePrefixList =\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	_, p = fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24}")
	if err := g.WritePrefixList(&b, p.Clauses[0].Filter, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	if want := "!\nprefix-set pl101\n  10.0.0.0/8 ge 16 le 24\nend-set\n"; b.String() != want {
		t.Errorf("WritePrefixList without denies =\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	if err := g.WriteNetworks(&b, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}); err != nil {
		t.Fatal(err)
	}
	if want := "address-family ipv4 unicast\n network 10.1.0.0/16\n!\naddress-family ipv6 unicast\n network 2001:db8::/32\n!\n"; b.String() != want {
		t.Errorf("WriteNetworks = %q", b.String())
	}
}
