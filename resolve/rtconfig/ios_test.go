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

func TestIOSImportGolden(t *testing.T) {
	s, p := fixturePolicy(t,
		"from AS2 action pref = 10; community.append(1:100); accept AS2 AND NOT {10.2.128.0/17}",
		"from AS2 accept ANY AND NOT community(2:666) AND <^AS2 AS-FOO*$>",
	)
	var b bytes.Buffer
	if err := (&Generator{Vendor: IOS}).WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	want := `!
no route-map MyMap_2_1
!
no ip prefix-list pl100
ip prefix-list pl100 seq 5 permit 10.2.0.0/16
!
route-map MyMap_2_1 permit 1
 match ip address prefix-list pl100
 set local-preference 990
 set community 1:100 additive
!
no ip as-path access-list 100
ip as-path access-list 100 permit ^_2(_(10|11))*$
!
no ip community-list standard cl100
ip community-list standard cl100 deny 2:666
ip community-list standard cl100 permit internet
!
route-map MyMap_2_1 permit 2
 match as-path 100
 match community cl100
!
route-map MyMap_2_1 deny 3
!
router bgp 1
 neighbor 10.0.0.2 remote-as 2
 neighbor 10.0.0.2 route-map MyMap_2_1 in
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
	} {
		ok, a := simulate(t, IOS, b.String(), s, false, x.r)
		if ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%v: %v %+v; want %v %+v", x.r, ok, a, x.accept, x.attrs)
		}
	}
}

// Refusing a construct writes nothing, and uses up no names.
func TestWriteIsAllOrNothing(t *testing.T) {
	for _, v := range Vendors() {
		g := &Generator{Vendor: v}
		s, p := fixturePolicy(t,
			"from AS2 accept AS2",
			"from AS2 accept <[^AS1]>",
		)
		var b bytes.Buffer
		if err := g.WriteImport(&b, s, p); !errors.Is(err, ErrUnsupported) || b.Len() != 0 {
			t.Errorf("%v: err %v, wrote %d bytes", v, err, b.Len())
		}
		_, p = fixturePolicy(t, "from AS2 accept AS2")
		if err := g.WriteImport(&b, s, p); err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		if !strings.Contains(b.String(), "_2_1") {
			t.Errorf("%v: the refused write used up a name:\n%s", v, b.String())
		}
	}
}

// A route a clause's negation rejects falls through to the next clause:
// negations stay inside lists, never become a deny entry of the map.
func TestFallThrough(t *testing.T) {
	for _, v := range Vendors() {
		s, p := fixturePolicy(t,
			"from AS2 accept {10.0.0.0/8^+} AND NOT {10.2.0.0/16^+} AND NOT <AS666> AND NOT community(6:6)",
			"from AS2 action pref = 5; accept ANY",
		)
		var b bytes.Buffer
		if err := writeImport(&Generator{Vendor: v}, &b, s, p); err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		for _, r := range []cfgsim.Route{
			rt("10.2.0.0/16", []types.ASN{2}),
			rt("10.9.0.0/16", []types.ASN{2, 666}),
			rt("10.9.0.0/16", []types.ASN{2}, "6:6"),
		} {
			ok, a := simulate(t, v, b.String(), s, false, r)
			if !ok || a.LocalPref != 995 {
				t.Errorf("%v %v: %v %+v; want the second clause (local-pref 995)\n%s", v, r, ok, a, b.String())
			}
		}
		if ok, a := simulate(t, v, b.String(), s, false, rt("10.9.0.0/16", []types.ASN{2})); !ok || a.LocalPref != -1 {
			t.Errorf("%v: 10.9.0.0/16 via AS2: %v %+v; want the first clause", v, ok, a)
		}
	}
}

// A session no clause applies to still gets a policy, and it refuses
// everything — not the vendor's default.
func TestEmptyPolicyRejects(t *testing.T) {
	for _, v := range Vendors() {
		s, p := fixturePolicy(t, "from AS3 accept ANY")
		if len(p.Clauses) != 0 {
			t.Fatalf("fixture: %d clauses", len(p.Clauses))
		}
		var b bytes.Buffer
		if err := writeImport(&Generator{Vendor: v}, &b, s, p); err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		if ok, _ := simulate(t, v, b.String(), s, false, rt("10.2.0.0/16", []types.ASN{2})); ok {
			t.Errorf("%v: an empty policy accepted a route:\n%s", v, b.String())
		}
	}
}

func TestIOSv6AndExport(t *testing.T) {
	s, p := fixturePolicyFor(t, v6Session, "mp-import: afi ipv6.unicast from AS2 accept AS2")
	var b bytes.Buffer
	g := &Generator{Vendor: IOS}
	if err := g.WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"ipv6 prefix-list pl100 seq 5 permit 2001:db8:2::/48",
		" match ipv6 address prefix-list pl100",
		" address-family ipv6 unicast",
		"  neighbor 2001:db8::2 route-map MyMap_2_1 in",
	} {
		if !strings.Contains(b.String(), line+"\n") {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}
	if ok, _ := simulate(t, IOS, b.String(), s, false, rt("2001:db8:2::/48", []types.ASN{2})); !ok {
		t.Errorf("v6 route refused:\n%s", b.String())
	}
	b.Reset()
	_, pe := fixturePolicy(t, "from AS2 accept AS2")
	if err := g.WriteExport(&b, v4Session, pe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), " neighbor 10.0.0.2 route-map MyMap_2_2 out\n") {
		t.Errorf("export attachment missing:\n%s", b.String())
	}
}

func TestIOSListsDefaultsNetworks(t *testing.T) {
	g := &Generator{Vendor: IOS}
	_, p := fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24} AND NOT {10.2.0.0/16^+}")
	var b bytes.Buffer
	if err := g.WritePrefixList(&b, p.Clauses[0].Filter, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	want := "!\nno ip prefix-list pl100\nip prefix-list pl100 seq 5 deny 10.2.0.0/16 le 32\n" +
		"ip prefix-list pl100 seq 10 permit 10.0.0.0/8 ge 16 le 24\n"
	if b.String() != want {
		t.Errorf("WritePrefixList =\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	if err := g.WriteNetworks(&b, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}); err != nil {
		t.Fatal(err)
	}
	if b.String() != "network 10.1.0.0 mask 255.255.0.0\nnetwork 2001:db8::/32\n" {
		t.Errorf("WriteNetworks = %q", b.String())
	}
	var ue *UnsupportedError
	for _, v := range []Vendor{Junos, BIRD2} {
		if err := (&Generator{Vendor: v}).WriteNetworks(&b, nil); !errors.As(err, &ue) || ue.Cause != CauseNetworks {
			t.Errorf("%v WriteNetworks: %v", v, err)
		}
	}
}

// IOS numbers as-path access-lists 1 to 500 (ruling R22): a number past it is
// refused with a plain error, before anything is written, rather than written
// as a line IOS rejects. The other vendors name their AS-path lists and have
// no such limit.
func TestIOSASPathListLimit(t *testing.T) {
	_, pp := fixturePolicy(t, "from AS2 accept <^AS2>")
	m := pp.Clauses[0].Filter.Conjuncts[0].Paths[0]
	g := &Generator{Vendor: IOS, Names: Naming{ASPathACLNo: 499}}
	var b bytes.Buffer
	for _, want := range []string{"499", "500"} {
		b.Reset()
		if err := g.WriteASPathList(&b, m); err != nil || !strings.Contains(b.String(), "ip as-path access-list "+want+" permit") {
			t.Fatalf("list %s: %v\n%s", want, err, b.String())
		}
	}
	b.Reset()
	err := g.WriteASPathList(&b, m)
	if err == nil || errors.Is(err, ErrUnsupported) || b.Len() > 0 {
		t.Errorf("list 501: err %v, wrote %q; want a plain error and nothing written", err, b.String())
	}

	s, p := fixturePolicy(t, "from AS2 accept <^AS2>", "from AS2 accept <^AS2 AS3>", "from AS2 accept <AS2 AS3>")
	g = &Generator{Vendor: IOS, Names: Naming{ASPathACLNo: 499}}
	b.Reset()
	if err := g.WriteImport(&b, s, p); err == nil || errors.Is(err, ErrUnsupported) || b.Len() > 0 {
		t.Errorf("an import needing lists 499-501: err %v, wrote %q; want a plain error and nothing written", err, b.String())
	}
	if err := g.WriteImport(&b, s, pp); err != nil {
		t.Errorf("an import needing list 499 after the refusal: %v", err)
	}
	for _, v := range []Vendor{Junos, IOSXR, BIRD2} {
		g := &Generator{Vendor: v, Names: Naming{ASPathACLNo: 600}}
		if err := g.WriteASPathList(&b, m); err != nil {
			t.Errorf("%v list 600: %v", v, err)
		}
	}
}
