package cfgsim

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func route(p string, path []types.ASN, comms ...string) Route {
	return Route{Prefix: netip.MustParsePrefix(p), Path: path, Communities: comms}
}

// rtconfig's own IOS output reads as IRRToolSet meant it.
func TestIOSReadsRtconfig(t *testing.T) {
	text, err := os.ReadFile("testdata/rtconfig-ios-import.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseIOS(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), false); !ok || name != "AS2-IN-1" {
		t.Fatalf("Attached(10.0.0.2) = %q, %v", name, ok)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
		attrs  Attrs
	}{
		{"AS2-IN-1", route("10.1.0.0/16", []types.ASN{2, 1}), true,
			Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"AS2-IN-1", route("10.11.0.0/16", []types.ASN{2}), true,
			Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"AS2-IN-1", route("10.1.0.0/24", []types.ASN{2}), false, Attrs{}},
		{"AS2-IN-1", route("192.0.2.0/24", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: -1}},
		// 10.x routes: the first entry of AS4's and AS5's maps (ANY AND NOT
		// FLTR-BOGONS, access-list 152) refuses 10.0.0.0/8, so the later
		// entries decide.
		{"AS4-IN-3", route("10.44.0.0/16", []types.ASN{4, 10, 1}, "4:1"), true, Attrs{LocalPref: -1, MED: -1, Communities: []string{"4:1"}}},
		{"AS4-IN-3", route("10.44.0.0/16", []types.ASN{4, 13}, "4:1"), false, Attrs{}},
		{"AS5-IN-4", route("10.5.0.0/16", []types.ASN{5}), true, Attrs{LocalPref: -1, MED: -1, Prepended: []types.ASN{1, 1}}},
		{"AS5-IN-4", route("10.55.0.0/16", []types.ASN{5}, "5:666"), false, Attrs{}},
		{"AS5-IN-4", route("10.55.0.0/16", []types.ASN{5}), true, Attrs{LocalPref: -1, MED: -1, Prepended: []types.ASN{1, 1}}},
	} {
		ok, a, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%s(%v) = %v %+v, %v; want %v %+v", x.name, x.r, ok, a, err, x.accept, x.attrs)
		}
	}
}

func TestIOSPrefixListsAndSets(t *testing.T) {
	const text = `
no ip prefix-list pl100
ip prefix-list pl100 seq 5 deny 10.2.128.0/17 le 32
ip prefix-list pl100 seq 10 permit 10.2.0.0/16 le 24
ip as-path access-list 100 deny _666_
ip as-path access-list 100 permit .*
ip community-list standard cl100 permit 1:2 1:3
ip community-list standard cl101 permit 9:9
route-map M permit 10
 match ip address prefix-list pl100
 match as-path 100
 match community cl100
 set local-preference 900
 set community 7:7 additive
 set comm-list cl101 delete
 set as-path prepend 1 1
 set ip next-hop 192.0.2.1
route-map M permit 20
 match community cl101 exact-match
 set metric-type internal
route-map M deny 30
router bgp 1
 neighbor 10.0.0.2 remote-as 2
 neighbor 10.0.0.2 route-map M in
`
	c, err := ParseIOS(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		r      Route
		accept bool
		attrs  Attrs
	}{
		{route("10.2.1.0/24", []types.ASN{2}, "1:2", "1:3", "9:9"), true,
			Attrs{LocalPref: 900, MED: -1, Communities: []string{"1:2", "1:3", "7:7"}, Prepended: []types.ASN{1, 1}, NextHop: "192.0.2.1"}},
		{route("10.2.200.0/24", []types.ASN{2}, "1:2", "1:3"), false, Attrs{}},
		{route("10.2.1.0/24", []types.ASN{2, 666}, "1:2", "1:3"), false, Attrs{}},
		{route("10.2.1.0/25", []types.ASN{2}, "1:2", "1:3"), false, Attrs{}},
		{route("192.0.2.0/24", []types.ASN{2}, "9:9"), true, Attrs{LocalPref: -1, MED: -1, MEDIGP: true, Communities: []string{"9:9"}}},
		{route("192.0.2.0/24", []types.ASN{2}, "9:9", "1:1"), false, Attrs{}},
	} {
		ok, a, err := c.Policy("M", x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("M(%v) = %v %+v, %v; want %v %+v", x.r, ok, a, err, x.accept, x.attrs)
		}
	}
	if _, err := ParseIOS("route-map M permit 10\n match nonsense 1\n"); err == nil {
		t.Errorf("an unknown line parsed")
	}
}
