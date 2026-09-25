package filtergen

import (
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// entries turns RPSL ranges into sorted entries, as rpslq --ranges does.
func entries(t *testing.T, specs ...string) []Entry {
	t.Helper()
	var out []Entry
	for _, s := range specs {
		r, err := types.ParsePrefixRange(s)
		if err != nil {
			t.Fatal(err)
		}
		p := r.Prefix()
		exact := int(r.Lo()) == p.Bits() && r.Hi() == r.Lo()
		out = append(out, Entry{Prefix: p, Aggregate: !exact, Lo: int(r.Lo()), Hi: int(r.Hi())})
	}
	Sort(out)
	return out
}

func render(t *testing.T, o Options, es []Entry) string {
	t.Helper()
	var b strings.Builder
	if err := WritePrefixes(&b, o, es); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A few vendors, as bgpq4 1.16 prints them; the differential tests hold every
// vendor to the bgpq4 binary.
func TestFormats(t *testing.T) {
	v4 := entries(t, "203.0.113.0/31^32-32", "192.0.2.0/24", "10.0.0.0/30^30-32", "10.0.0.0/31")
	cases := []struct {
		v    Vendor
		want string
	}{
		{Cisco, "no ip prefix-list NN\n" +
			"ip prefix-list NN permit 10.0.0.0/30 le 32\n" +
			"ip prefix-list NN permit 10.0.0.0/31\n" +
			"ip prefix-list NN permit 192.0.2.0/24\n" +
			"ip prefix-list NN permit 203.0.113.0/31 ge 32 le 32\n"},
		{JSON, "{ \"NN\": [\n" +
			"    { \"prefix\": \"10.0.0.0\\/30\", \"exact\": false, \"less-equal\": 32 },\n" +
			"    { \"prefix\": \"10.0.0.0\\/31\", \"exact\": true },\n" +
			"    { \"prefix\": \"192.0.2.0\\/24\", \"exact\": true },\n" +
			"    { \"prefix\": \"203.0.113.0\\/31\", \"exact\": false,\n      \"greater-equal\": 32, \"less-equal\": 32 }\n" +
			"] }\n"},
		{BIRD, "NN = [\n" +
			"    10.0.0.0/30{30,32},\n" +
			"    10.0.0.0/31,\n" +
			"    192.0.2.0/24,\n" +
			"    203.0.113.0/31{32,32}\n" +
			"];\n"},
		{Plain, "10.0.0.0/30^+\n10.0.0.0/31\n192.0.2.0/24\n203.0.113.0/31^-\n"},
		{Huawei, "undo ip ip-prefix NN\n" +
			"ip ip-prefix NN permit 10.0.0.0 30 less-equal 32\n" +
			"ip ip-prefix NN permit 10.0.0.0 31\n" +
			"ip ip-prefix NN permit 192.0.2.0 24\n" +
			"ip ip-prefix NN permit 203.0.113.0 31 greater-equal 32 less-equal 32\n"},
	}
	for _, c := range cases {
		if got := render(t, Options{Vendor: c.v}, v4); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.v, got, c.want)
		}
	}
	// Junos prefix-lists hold exact prefixes only.
	var b strings.Builder
	if err := WritePrefixes(&b, Options{Vendor: Junos}, v4); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Junos with ranges: %v", err)
	}
	exact := entries(t, "192.0.2.0/24", "10.0.0.0/8")
	if got, want := render(t, Options{Vendor: Junos}, exact), "policy-options {\nreplace:\n prefix-list NN {\n    10.0.0.0/8;\n    192.0.2.0/24;\n }\n}\n"; got != want {
		t.Errorf("Junos:\n got %q\nwant %q", got, want)
	}
}

// Empty lists, as bgpq4 prints them: Cisco denies everything, BIRD prints
// nothing at all.
func TestEmpty(t *testing.T) {
	for _, c := range []struct {
		o    Options
		want string
	}{
		{Options{Vendor: Cisco}, "no ip prefix-list NN\n! generated prefix-list NN is empty\nip prefix-list NN deny 0.0.0.0/0\n"},
		{Options{Vendor: Cisco, V6: true, Sequence: true}, "no ipv6 prefix-list NN\n! generated prefix-list NN is empty\nipv6 prefix-list NN seq 1 deny ::/0\n"},
		{Options{Vendor: JSON}, "{ \"NN\": [\n] }\n"},
		{Options{Vendor: BIRD}, ""},
		{Options{Vendor: Junos}, "policy-options {\nreplace:\n prefix-list NN {\n }\n}\n"},
		{Options{Vendor: OpenBGPD, AS: 65000}, "# generated prefix-list NN (AS 65000) is empty\ndeny from AS 65000\n"},
		{Options{Vendor: Plain}, ""},
	} {
		if got := render(t, c.o, nil); got != c.want {
			t.Errorf("empty %s:\n got %q\nwant %q", c.o.Vendor, got, c.want)
		}
	}
}

// The Cisco extended access-list's wildcard arithmetic.
func TestCiscoACL(t *testing.T) {
	es := entries(t, "192.0.2.0/24", "10.0.0.0/8^16-24", "198.51.100.0/24^+", "203.0.113.1/32")
	want := "no ip access-list extended NN\nip access-list extended NN\n" +
		" permit ip 10.0.0.0 0.255.255.0 255.255.0.0 0.0.255.0\n" +
		" permit ip host 192.0.2.0 host 255.255.255.0\n" +
		" permit ip 198.51.100.0 0.0.0.255 255.255.255.0 0.0.0.255\n" +
		" permit ip host 203.0.113.1 host 0.0.0.0\n"
	if got := render(t, Options{Vendor: Cisco, Kind: RouteFilter}, es); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestUserFormat(t *testing.T) {
	es := entries(t, "192.0.2.0/24", "10.0.0.0/8^16-24")
	got := render(t, Options{Vendor: UserFormat, Name: "L", Format: `%N %n/%l %a-%A %m %i 100%%\t\x`}, es)
	want := "L 10.0.0.0/8 16-24 255.0.0.0 0.255.255.255 100%\tx" +
		"L 192.0.2.0/24 24-24 255.255.255.0 0.0.0.255 100%\tx\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	for _, f := range []string{"%q", "a%", `a\`} {
		if err := (Options{Vendor: UserFormat, Format: f}).Check(false, 0, 0); !errors.Is(err, ErrUnsupported) {
			t.Errorf("-F %q: %v", f, err)
		}
	}
}

// AS lists wrap at the width, as bgpq4 -t does.
func TestASLists(t *testing.T) {
	var asns []types.ASN
	for i := 10; i >= 1; i-- {
		asns = append(asns, types.ASN(i))
	}
	for _, c := range []struct {
		o    Options
		want string
	}{
		{Options{Vendor: JSON, Kind: ASSet, Width: 8}, "{\"NN\": [\n  1,2,3,4,5,6,7,8,\n  9,10\n]}\n"},
		{Options{Vendor: BIRD, Kind: ASSet, Width: 8}, "NN = [\n    1, 2, 3, 4, 5, 6, 7, 8,\n    9, 10\n];\n"},
		{Options{Vendor: OpenBGPD, Kind: ASSet, Width: 0}, "as-set NN {\n\t1 2 3 4 5 6 7 8 9 10\n}\n"},
		{Options{Vendor: Plain, Kind: ASSet}, "AS1\nAS2\nAS3\nAS4\nAS5\nAS6\nAS7\nAS8\nAS9\nAS10\n"},
		{Options{Vendor: Cisco, Kind: ASPath, AS: 3, Width: 4}, "no ip as-path access-list NN\n" +
			"ip as-path access-list NN permit ^3(_3)*$\n" +
			"ip as-path access-list NN permit ^3(_[0-9]+)*_(1|2|4|5)$\n" +
			"ip as-path access-list NN permit ^3(_[0-9]+)*_(6|7|8|9)$\n" +
			"ip as-path access-list NN permit ^3(_[0-9]+)*_(10)$\n"},
		{Options{Vendor: Junos, Kind: ASList, AS: 99, Width: 5}, "policy-options {\nreplace:\n as-list-group NN {\n" +
			"  as-list a0 members [ 1 2 3 4 5 ];\n  as-list a1 members [ 6 7 8 9 10 ];\n }\n}\n"},
	} {
		var b strings.Builder
		if err := WriteASNs(&b, c.o, asns); err != nil {
			t.Fatal(err)
		}
		if b.String() != c.want {
			t.Errorf("%s %s:\n got %q\nwant %q", c.o.Vendor, c.o.Kind, b.String(), c.want)
		}
	}
	var b strings.Builder
	if err := WriteASNs(&b, Options{Vendor: Cisco, Kind: ASSet}, asns); !errors.Is(err, ErrUnsupported) {
		t.Errorf("an AS set in Cisco format: %v", err)
	}
}

// Check refuses what bgpq4 refuses.
func TestCheck(t *testing.T) {
	for _, c := range []struct {
		o         Options
		aggregate bool
		refine    int
		ok        bool
	}{
		{Options{Vendor: Junos}, true, 0, false},
		{Options{Vendor: Junos, Kind: RouteFilter}, true, 0, true},
		{Options{Vendor: Junos}, false, 28, false},
		{Options{Vendor: Nokia, Kind: RouteFilter}, true, 0, false},
		{Options{Vendor: Cisco, Kind: ASPath}, true, 0, false},
		{Options{Vendor: Cisco, Kind: RouteFilter, V6: true}, false, 0, false},
		{Options{Vendor: BIRD, Sequence: true}, false, 0, false},
		{Options{Vendor: MikroTik7, Kind: ASPath}, false, 0, false},
		{Options{Vendor: CiscoXR, Kind: RouteFilter}, false, 0, false},
		{Options{Vendor: Cisco, Match: "x"}, false, 0, false},
		{Options{Vendor: Arista, Sequence: true}, true, 24, true},
	} {
		err := c.o.Check(c.aggregate, c.refine, 0)
		if (err == nil) != c.ok {
			t.Errorf("%+v -A %v -R %d: %v", c.o, c.aggregate, c.refine, err)
		}
	}
}
