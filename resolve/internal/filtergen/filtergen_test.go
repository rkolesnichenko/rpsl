package filtergen

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func ranges(t *testing.T, specs ...string) []types.PrefixRange {
	t.Helper()
	var out []types.PrefixRange
	for _, s := range specs {
		r, err := types.ParsePrefixRange(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func render(t *testing.T, f Format, l List) string {
	t.Helper()
	var b strings.Builder
	if err := Write(&b, f, l); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Each format, as bgpq4 1.16 prints it: exact prefixes sorted by address and
// then length, and a range in bgpq4's aggregated form.
func TestFormats(t *testing.T) {
	v4 := List{Name: "NN", V6: false, Ranges: ranges(t, "203.0.113.0/31^32-32", "192.0.2.0/24", "10.0.0.0/30^30-32", "10.0.0.0/31")}
	cases := []struct {
		f    Format
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
	}
	for _, c := range cases {
		if got := render(t, c.f, v4); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.f, got, c.want)
		}
	}
	// Junos prefix-lists hold exact prefixes only.
	var b strings.Builder
	if err := Write(&b, Junos, v4); err == nil {
		t.Error("Junos with ranges: no error")
	}
	exact := List{Name: "NN", Ranges: ranges(t, "192.0.2.0/24", "10.0.0.0/8")}
	if got, want := render(t, Junos, exact), "policy-options {\nreplace:\n prefix-list NN {\n    10.0.0.0/8;\n    192.0.2.0/24;\n }\n}\n"; got != want {
		t.Errorf("Junos:\n got %q\nwant %q", got, want)
	}
}

func TestIPv6AndNames(t *testing.T) {
	l := List{Name: "MYLIST", V6: true, Ranges: ranges(t, "2001:db8:1::2/127", "2001:db8::/32")}
	if got, want := render(t, Cisco, l), "no ipv6 prefix-list MYLIST\nipv6 prefix-list MYLIST permit 2001:db8::/32\nipv6 prefix-list MYLIST permit 2001:db8:1::2/127\n"; got != want {
		t.Errorf("Cisco v6:\n got %q\nwant %q", got, want)
	}
}

// Empty lists, as bgpq4 prints them: Cisco denies everything, BIRD prints
// nothing at all.
func TestEmpty(t *testing.T) {
	for _, c := range []struct {
		f    Format
		v6   bool
		want string
	}{
		{Cisco, false, "no ip prefix-list NN\n! generated prefix-list NN is empty\nip prefix-list NN deny 0.0.0.0/0\n"},
		{Cisco, true, "no ipv6 prefix-list NN\n! generated prefix-list NN is empty\nipv6 prefix-list NN deny ::/0\n"},
		{JSON, false, "{ \"NN\": [\n] }\n"},
		{BIRD, false, ""},
		{Junos, false, "policy-options {\nreplace:\n prefix-list NN {\n }\n}\n"},
		{Plain, false, ""},
	} {
		if got := render(t, c.f, List{Name: "NN", V6: c.v6}); got != c.want {
			t.Errorf("empty %s (v6 %v):\n got %q\nwant %q", c.f, c.v6, got, c.want)
		}
	}
}

// AS lists wrap eight to a line, as bgpq4 -t does.
func TestASLists(t *testing.T) {
	var asns []types.ASN
	for i := 10; i >= 1; i-- {
		asns = append(asns, types.ASN(i))
	}
	for _, c := range []struct {
		f    Format
		want string
	}{
		{JSON, "{\"NN\": [\n  1,2,3,4,5,6,7,8,\n  9,10\n]}\n"},
		{BIRD, "NN = [\n    1, 2, 3, 4, 5, 6, 7, 8,\n    9, 10\n];\n"},
		{Plain, "AS1\nAS2\nAS3\nAS4\nAS5\nAS6\nAS7\nAS8\nAS9\nAS10\n"},
	} {
		var b strings.Builder
		if err := WriteASList(&b, c.f, "NN", asns); err != nil {
			t.Fatal(err)
		}
		if b.String() != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.f, b.String(), c.want)
		}
	}
	for _, c := range []struct {
		f    Format
		want string
	}{{JSON, "{\"NN\": [\n]}\n"}, {BIRD, "NN = [];\n"}} {
		var b strings.Builder
		_ = WriteASList(&b, c.f, "NN", nil)
		if b.String() != c.want {
			t.Errorf("empty AS list %s: %q, want %q", c.f, b.String(), c.want)
		}
	}
	var b strings.Builder
	if err := WriteASList(&b, Cisco, "NN", asns); err == nil {
		t.Error("an AS list in Cisco format: no error")
	}
}

// MaxLen drops what is longer and clamps a range that reaches past it.
func TestMaxLen(t *testing.T) {
	got := MaxLen(ranges(t, "10.0.0.0/8^+", "192.0.2.0/24", "198.51.100.0/25", "203.0.113.0/24^25-26"), 24)
	var s []string
	for _, r := range got {
		s = append(s, r.String())
	}
	if want := "10.0.0.0/8^8-24 192.0.2.0/24"; strings.Join(s, " ") != want {
		t.Errorf("MaxLen = %v, want %s", s, want)
	}
}

// Enumerate turns ranges into the exact prefixes they hold, deduplicated.
func TestEnumerate(t *testing.T) {
	got, err := Enumerate(ranges(t, "10.0.0.0/30^+", "10.0.0.0/31", "192.0.2.0/24"), 100)
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, r := range got {
		s = append(s, r.String())
	}
	if want := "10.0.0.0/30 10.0.0.0/31 10.0.0.0/32 10.0.0.1/32 10.0.0.2/31 10.0.0.2/32 10.0.0.3/32 192.0.2.0/24"; strings.Join(sortedStrings(got), " ") != want {
		t.Errorf("Enumerate = %v, want %s", s, want)
	}
	if _, err := Enumerate(ranges(t, "10.0.0.0/8^+"), 1000); err == nil {
		t.Error("Enumerate over its cap: no error")
	}
	_ = netip.Prefix{}
}

func sortedStrings(rs []types.PrefixRange) []string {
	Sort(rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return out
}
