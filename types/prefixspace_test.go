package types

import (
	"net/netip"
	"slices"
	"testing"
)

func mr(t *testing.T, s string) PrefixRange {
	t.Helper()
	r, err := ParsePrefixRange(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return r
}

func spaceOf(t *testing.T, ss ...string) PrefixSpace {
	t.Helper()
	var rs []PrefixRange
	for _, s := range ss {
		rs = append(rs, mr(t, s))
	}
	return SpaceOf(rs...)
}

func rangeStrings(s PrefixSpace) []string {
	var out []string
	for r := range s.Ranges() {
		out = append(out, r.String())
	}
	return out
}

func TestSpaceEmpty(t *testing.T) {
	var zero PrefixSpace
	for _, s := range []PrefixSpace{zero, SpaceOf(), spaceOf(t, "192.0.2.1/32^-")} {
		if !s.IsEmpty() {
			t.Errorf("%v: not empty", s)
		}
		if p, ok := s.Example(); ok {
			t.Errorf("empty space has an example %v", p)
		}
		if got := rangeStrings(s); len(got) != 0 {
			t.Errorf("empty space ranges %v", got)
		}
		if s.String() != "{}" {
			t.Errorf("String %q, want {}", s.String())
		}
		if !s.Equal(zero) {
			t.Errorf("%v not Equal to the zero space", s)
		}
	}
}

func TestSpaceContains(t *testing.T) {
	s := spaceOf(t, "10.0.0.0/24^+", "2001:db8::/32^48")
	for _, c := range []struct {
		p    string
		want bool
	}{
		{"10.0.0.0/24", true},
		{"10.0.0.128/25", true},
		{"10.0.0.7/32", true},
		{"10.0.1.0/24", false},
		{"10.0.0.0/23", false},
		{"0.0.0.0/0", false},
		{"2001:db8:1::/48", true},
		{"2001:db8::/32", false},
		{"2001:db8::/49", false},
		{"2001:db9::/48", false},
	} {
		if got := s.Contains(netip.MustParsePrefix(c.p)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.p, got, c.want)
		}
	}
	if s.Contains(netip.Prefix{}) {
		t.Error("Contains of the zero prefix")
	}
}

// Canonical form: the same set built different ways is Equal and has the
// same ranges.
func TestSpaceCanonical(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want []string
	}{
		// two halves lift to their parent
		{[]string{"10.0.0.0/25^25", "10.0.0.128/25^25"}, []string{"10.0.0.0/24^25"}, []string{"10.0.0.0/24^25"}},
		// a range under one already covered adds nothing
		{[]string{"10.0.0.0/24^+", "10.0.0.0/25^26"}, []string{"10.0.0.0/24^+"}, []string{"10.0.0.0/24^+"}},
		// order of construction does not matter
		{[]string{"10.0.1.0/24", "10.0.0.0/24^25-26"}, []string{"10.0.0.0/24^25-26", "10.0.1.0/24"}, []string{"10.0.0.0/24^25-26", "10.0.1.0/24"}},
		// adjacent windows on one node merge into one run
		{[]string{"10.0.0.0/24^25", "10.0.0.0/24^26"}, []string{"10.0.0.0/24^25-26"}, []string{"10.0.0.0/24^25-26"}},
		// lifting cascades: four quarters, two levels up
		{[]string{"10.0.0.0/26^26", "10.0.0.64/26^26", "10.0.0.128/26^26", "10.0.0.192/26^26"}, []string{"10.0.0.0/24^26"}, []string{"10.0.0.0/24^26"}},
		// families are kept apart, IPv4 first
		{[]string{"2001:db8::/48", "10.0.0.0/8"}, []string{"10.0.0.0/8", "2001:db8::/48"}, []string{"10.0.0.0/8", "2001:db8::/48"}},
	} {
		a, b := spaceOf(t, c.a...), spaceOf(t, c.b...)
		if !a.Equal(b) {
			t.Errorf("%v (%v) and %v (%v) are not Equal", c.a, rangeStrings(a), c.b, rangeStrings(b))
		}
		if got := rangeStrings(a); !slices.Equal(got, c.want) {
			t.Errorf("%v: ranges %v, want %v", c.a, got, c.want)
		}
	}
	if spaceOf(t, "10.0.0.0/24").Equal(spaceOf(t, "10.0.0.0/24^+")) {
		t.Error("different sets are Equal")
	}
}

func TestSpaceExample(t *testing.T) {
	for _, c := range []struct {
		ranges []string
		want   string
	}{
		{[]string{"10.0.0.128/25", "10.0.0.0/26"}, "10.0.0.128/25"},
		{[]string{"10.0.0.0/24^26-28"}, "10.0.0.0/26"},
		{[]string{"10.0.1.0/24", "10.0.0.0/24"}, "10.0.0.0/24"},
		{[]string{"2001:db8::/32", "10.0.0.0/24"}, "10.0.0.0/24"},
		{[]string{"2001:db8::/32^40-48"}, "2001:db8::/40"},
		{[]string{"0.0.0.0/0^+"}, "0.0.0.0/0"},
	} {
		got, ok := spaceOf(t, c.ranges...).Example()
		if !ok || got.String() != c.want {
			t.Errorf("%v: Example %v %v, want %s", c.ranges, got, ok, c.want)
		}
	}
}

func TestFullSpace(t *testing.T) {
	v4, v6, both := FullSpace(AFIv4), FullSpace(AFIv6), FullSpace(AFIAny)
	if got := rangeStrings(v4); !slices.Equal(got, []string{"0.0.0.0/0^+"}) {
		t.Errorf("FullSpace(AFIv4) ranges %v", got)
	}
	if got := rangeStrings(v6); !slices.Equal(got, []string{"::/0^+"}) {
		t.Errorf("FullSpace(AFIv6) ranges %v", got)
	}
	if got := rangeStrings(both); !slices.Equal(got, []string{"0.0.0.0/0^+", "::/0^+"}) {
		t.Errorf("FullSpace(AFIAny) ranges %v", got)
	}
	if !FullSpace(AFIUnspecified).Equal(both) {
		t.Error("FullSpace(AFIUnspecified) is not both families")
	}
	for _, p := range []string{"0.0.0.0/0", "255.255.255.255/32", "10.0.0.0/8"} {
		if !v4.Contains(netip.MustParsePrefix(p)) || v6.Contains(netip.MustParsePrefix(p)) {
			t.Errorf("%s: v4 %v, v6 %v", p, v4.Contains(netip.MustParsePrefix(p)), v6.Contains(netip.MustParsePrefix(p)))
		}
	}
	if !v6.Contains(netip.MustParsePrefix("2001:db8::1/128")) {
		t.Error("FullSpace(AFIv6) lacks a /128")
	}
}

func TestSpaceString(t *testing.T) {
	if got := spaceOf(t, "10.0.0.0/24^+", "2001:db8::/48").String(); got != "{10.0.0.0/24^+, 2001:db8::/48}" {
		t.Errorf("String %q", got)
	}
}
