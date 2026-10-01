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

func TestSpaceOperations(t *testing.T) {
	for _, c := range []struct {
		name   string
		a, b   []string
		union  []string
		inter  []string
		minus  []string
		subset bool
	}{
		{
			name:  "disjoint",
			a:     []string{"10.0.0.0/24"},
			b:     []string{"10.0.1.0/24"},
			union: []string{"10.0.0.0/23^24"},
			inter: nil,
			minus: []string{"10.0.0.0/24"},
		},
		{
			name:   "a inside b",
			a:      []string{"10.0.0.0/24^25"},
			b:      []string{"10.0.0.0/24^+"},
			union:  []string{"10.0.0.0/24^+"},
			inter:  []string{"10.0.0.0/24^25"},
			minus:  nil,
			subset: true,
		},
		{
			name:  "a hole: every /24 of 10.0.0.0/23 but one",
			a:     []string{"10.0.0.0/23^24"},
			b:     []string{"10.0.0.0/24"},
			union: []string{"10.0.0.0/23^24"},
			inter: []string{"10.0.0.0/24"},
			minus: []string{"10.0.1.0/24"},
		},
		{
			name:  "minus a deeper prefix of a length a holds above",
			a:     []string{"10.0.0.0/8^24"},
			b:     []string{"10.0.0.0/24"},
			union: []string{"10.0.0.0/8^24"},
			inter: []string{"10.0.0.0/24"},
			minus: []string{"10.0.1.0/24", "10.0.2.0/23^24", "10.0.4.0/22^24", "10.0.8.0/21^24", "10.0.16.0/20^24",
				"10.0.32.0/19^24", "10.0.64.0/18^24", "10.0.128.0/17^24", "10.1.0.0/16^24", "10.2.0.0/15^24",
				"10.4.0.0/14^24", "10.8.0.0/13^24", "10.16.0.0/12^24", "10.32.0.0/11^24", "10.64.0.0/10^24", "10.128.0.0/9^24"},
		},
		{
			name:  "minus one length of a window",
			a:     []string{"10.0.0.0/24^24-26"},
			b:     []string{"10.0.0.0/24^25"},
			union: []string{"10.0.0.0/24^24-26"},
			inter: []string{"10.0.0.0/24^25"},
			minus: []string{"10.0.0.0/24", "10.0.0.0/24^26"},
		},
		{
			name:  "union lifts",
			a:     []string{"10.0.0.0/25^25-26"},
			b:     []string{"10.0.0.128/25^25-26"},
			union: []string{"10.0.0.0/24^25-26"},
			inter: nil,
			minus: []string{"10.0.0.0/25^25-26"},
		},
		{
			name:   "families apart",
			a:      []string{"10.0.0.0/24", "2001:db8::/32^48"},
			b:      []string{"2001:db8::/32^+"},
			union:  []string{"10.0.0.0/24", "2001:db8::/32^+"},
			inter:  []string{"2001:db8::/32^48"},
			minus:  []string{"10.0.0.0/24"},
			subset: false,
		},
		{
			name:   "empty operands",
			a:      nil,
			b:      []string{"10.0.0.0/24"},
			union:  []string{"10.0.0.0/24"},
			inter:  nil,
			minus:  nil,
			subset: true,
		},
	} {
		a, b := spaceOf(t, c.a...), spaceOf(t, c.b...)
		for _, op := range []struct {
			name string
			got  PrefixSpace
			want []string
		}{
			{"Union", a.Union(b), c.union},
			{"Intersect", a.Intersect(b), c.inter},
			{"Minus", a.Minus(b), c.minus},
		} {
			if got := rangeStrings(op.got); !slices.Equal(got, op.want) {
				t.Errorf("%s: %s = %v, want %v", c.name, op.name, got, op.want)
			}
			if !op.got.Equal(spaceOf(t, op.want...)) {
				t.Errorf("%s: %s is not canonical: not Equal to its own ranges rebuilt", c.name, op.name)
			}
		}
		if got := a.Subset(b); got != c.subset {
			t.Errorf("%s: Subset %v, want %v", c.name, got, c.subset)
		}
	}
}

// The operands are never changed: an operation shares their nodes but
// builds new ones where it differs.
func TestSpaceOperandsUnchanged(t *testing.T) {
	a := spaceOf(t, "10.0.0.0/25^25-26")
	b := spaceOf(t, "10.0.0.128/25^25-26")
	before := a.String() + b.String()
	_ = a.Union(b)
	_ = a.Minus(b)
	_ = a.Intersect(b)
	if after := a.String() + b.String(); after != before {
		t.Errorf("operands changed: %s, then %s", before, after)
	}
}
