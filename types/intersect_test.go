package types

import (
	"net/netip"
	"testing"
)

// Two tiny universes, small enough that every range under them can be
// enumerated in full and compared against a brute-force oracle.
var universes = []string{"10.0.0.0/29", "2001:db8::/126"}

// allRanges returns every PrefixRange whose base is a prefix under universe and
// whose length window lies within that base's family.
func allRanges(t *testing.T, universe string) []PrefixRange {
	t.Helper()
	u, err := netip.ParsePrefix(universe)
	if err != nil {
		t.Fatal(err)
	}
	maxBits := u.Addr().BitLen()
	spread, ok := NewPrefixRange(u, u.Bits(), maxBits)
	if !ok {
		t.Fatalf("NewPrefixRange(%s): not ok", universe)
	}
	var out []PrefixRange
	for base := range spread.All() {
		for lo := base.Bits(); lo <= maxBits; lo++ {
			for hi := lo; hi <= maxBits; hi++ {
				r, ok := NewPrefixRange(base, lo, hi)
				if !ok {
					t.Fatalf("NewPrefixRange(%s, %d, %d): not ok", base, lo, hi)
				}
				out = append(out, r)
			}
		}
	}
	return out
}

// denote returns the set of concrete prefixes r stands for.
func denote(r PrefixRange) map[netip.Prefix]bool {
	m := map[netip.Prefix]bool{}
	for p := range r.All() {
		m[p] = true
	}
	return m
}

// Intersect denotes exactly the prefixes both operands denote.
func TestPrefixRangeIntersectMatchesOracle(t *testing.T) {
	for _, universe := range universes {
		rs := allRanges(t, universe)
		sets := make([]map[netip.Prefix]bool, len(rs))
		for i, r := range rs {
			sets[i] = denote(r)
		}
		for i, r := range rs {
			for j, s := range rs {
				want := map[netip.Prefix]bool{}
				for p := range sets[i] {
					if sets[j][p] {
						want[p] = true
					}
				}
				got, ok := r.Intersect(s)
				if ok != (len(want) > 0) {
					t.Fatalf("%s ∩ %s: ok = %v, want %v (oracle has %d prefixes)",
						r, s, ok, len(want) > 0, len(want))
				}
				if !ok {
					continue
				}
				have := denote(got)
				if len(have) != len(want) {
					t.Fatalf("%s ∩ %s = %s: denotes %d prefixes, want %d", r, s, got, len(have), len(want))
				}
				for p := range want {
					if !have[p] {
						t.Fatalf("%s ∩ %s = %s: missing %s", r, s, got, p)
					}
				}
			}
		}
	}
}

// Intersect is commutative and idempotent, and its result is canonical.
func TestPrefixRangeIntersectAlgebra(t *testing.T) {
	for _, universe := range universes {
		rs := allRanges(t, universe)
		for _, r := range rs {
			if got, ok := r.Intersect(r); !ok || got != r {
				t.Fatalf("%s ∩ itself = %s, %v; want %s, true", r, got, ok, r)
			}
			for _, s := range rs {
				a, aok := r.Intersect(s)
				b, bok := s.Intersect(r)
				if aok != bok || a != b {
					t.Fatalf("%s ∩ %s = %s,%v but reversed = %s,%v", r, s, a, aok, b, bok)
				}
			}
		}
	}
}

// Ranges of different address families never intersect.
func TestPrefixRangeIntersectAcrossFamilies(t *testing.T) {
	v4 := allRanges(t, "10.0.0.0/29")
	v6 := allRanges(t, "2001:db8::/126")
	for _, r := range v4 {
		for _, s := range v6 {
			if got, ok := r.Intersect(s); ok {
				t.Fatalf("%s ∩ %s = %s, want no intersection", r, s, got)
			}
		}
	}
}

// The zero and empty ranges intersect with nothing.
func TestPrefixRangeIntersectEmpty(t *testing.T) {
	host, err := ParsePrefixRange("192.0.2.1/32^-") // denotes nothing
	if err != nil {
		t.Fatal(err)
	}
	any, err := ParsePrefixRange("0.0.0.0/0^+")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ a, b PrefixRange }{
		{PrefixRange{}, any}, {any, PrefixRange{}}, {host, any}, {any, host},
		{PrefixRange{}, PrefixRange{}},
	} {
		if got, ok := c.a.Intersect(c.b); ok {
			t.Errorf("%q ∩ %q = %s, want no intersection", c.a, c.b, got)
		}
	}
}

// Contains agrees with All over every range in the universes.
func TestPrefixRangeContainsMatchesOracle(t *testing.T) {
	for _, universe := range universes {
		u, err := netip.ParsePrefix(universe)
		if err != nil {
			t.Fatal(err)
		}
		spread, _ := NewPrefixRange(u, u.Bits(), u.Addr().BitLen())
		var every []netip.Prefix
		for p := range spread.All() {
			every = append(every, p)
		}
		for _, r := range allRanges(t, universe) {
			want := denote(r)
			for _, p := range every {
				if got := r.Contains(p); got != want[p] {
					t.Fatalf("%s.Contains(%s) = %v, want %v", r, p, got, want[p])
				}
			}
		}
	}
}

// Contains ignores host bits, rejects the other family, and rejects invalid input.
func TestPrefixRangeContainsEdges(t *testing.T) {
	r, err := ParsePrefixRange("192.0.2.0/24^25-26")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		in   string
		want bool
	}{
		{"192.0.2.128/25", true},
		{"192.0.2.129/25", true}, // host bits ignored
		{"192.0.2.0/24", false},  // shorter than the window
		{"192.0.2.0/27", false},  // longer than the window
		{"192.0.3.0/25", false},  // outside the base prefix
		{"2001:db8::/25", false}, // other family
	}
	for _, c := range cases {
		p, err := netip.ParsePrefix(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.Contains(p); got != c.want {
			t.Errorf("%s.Contains(%s) = %v, want %v", r, c.in, got, c.want)
		}
	}
	if r.Contains(netip.Prefix{}) {
		t.Error("Contains(invalid prefix) = true, want false")
	}
	if (PrefixRange{}).Contains(netip.MustParsePrefix("192.0.2.0/24")) {
		t.Error("zero range Contains = true, want false")
	}
}
