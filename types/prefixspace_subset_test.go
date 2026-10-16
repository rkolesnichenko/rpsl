package types

import (
	"math/rand/v2"
	"testing"
	"time"
)

// SubsetOfUnion answers as Minus of the union does, and Subset as Minus:
// random expressions from the model generator (both families, ranges
// reaching above the universe, so inherited lengths), up to five right-hand
// spaces, a quarter of the cases completed to contain s and a quarter
// holding s itself (the same nodes).
func TestSubsetOfUnionAgainstMinus(t *testing.T) {
	yes, no := 0, 0
	for seed := uint64(0); seed < 5000; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x50))
		s := randomExpr(r, 3).space(t)
		var ts []PrefixSpace
		var u PrefixSpace
		for k := r.IntN(6); k > 0; k-- {
			x := randomExpr(r, 3).space(t)
			ts = append(ts, x)
			u = u.Union(x)
		}
		switch r.IntN(4) {
		case 0: // the rest of s: now a subset
			rest := s.Minus(u)
			ts = append(ts, rest)
			u = u.Union(rest)
		case 1: // s itself
			ts = append(ts, s)
			u = u.Union(s)
		}
		want := s.Minus(u).IsEmpty()
		if want {
			yes++
		} else {
			no++
		}
		if got := s.SubsetOfUnion(ts...); got != want {
			t.Fatalf("seed %d: %v SubsetOfUnion %v = %v, Minus says %v", seed, s, ts, got, want)
		}
		if got := s.Subset(u); got != want {
			t.Fatalf("seed %d: %v Subset %v = %v, Minus says %v", seed, s, u, got, want)
		}
	}
	if yes < 500 || no < 500 {
		t.Fatalf("%d subsets and %d not in 5000: the test draws too few of one", yes, no)
	}
}

func TestSubsetOfUnionEdges(t *testing.T) {
	v4 := spaceOf(t, "10.0.0.0/24^+")
	v6 := spaceOf(t, "2001:db8::/32")
	both := v4.Union(v6)
	cases := []struct {
		name string
		s    PrefixSpace
		ts   []PrefixSpace
		want bool
	}{
		{"empty in nothing", PrefixSpace{}, nil, true},
		{"empty in something", PrefixSpace{}, []PrefixSpace{v4}, true},
		{"something in nothing", v4, nil, false},
		{"something in empty spaces", v4, []PrefixSpace{{}, {}}, false},
		{"itself", v4, []PrefixSpace{v4}, true},
		{"itself among others", v4, []PrefixSpace{v6, v4}, true},
		{"the other family", v4, []PrefixSpace{v6}, false},
		{"both families, split", both, []PrefixSpace{v6, v4}, true},
		{"both families, one missing", both, []PrefixSpace{v4, {}}, false},
		{"inherited from a shorter range", spaceOf(t, "10.1.0.0/16"), []PrefixSpace{spaceOf(t, "10.0.0.0/8^+")}, true},
		{"inherited on s's side", spaceOf(t, "10.0.0.0/8^+"), []PrefixSpace{spaceOf(t, "10.0.0.0/8^9-32")}, false},
		{"lengths split across two", spaceOf(t, "10.0.0.0/24^24-25"), []PrefixSpace{spaceOf(t, "10.0.0.0/24"), spaceOf(t, "10.0.0.0/24^25")}, true},
		{"a /23 is not its two /24s", spaceOf(t, "10.0.0.0/23"), []PrefixSpace{spaceOf(t, "10.0.0.0/24"), spaceOf(t, "10.0.1.0/24")}, false},
	}
	for _, c := range cases {
		if got := c.s.SubsetOfUnion(c.ts...); got != c.want {
			t.Errorf("%s: %v SubsetOfUnion %v = %v, want %v", c.name, c.s, c.ts, got, c.want)
		}
		var u PrefixSpace
		for _, x := range c.ts {
			u = u.Union(x)
		}
		if got := c.s.Subset(u); got != c.want {
			t.Errorf("%s: %v Subset %v = %v, want %v", c.name, c.s, u, got, c.want)
		}
	}
}

// Subset allocates nothing, whether it answers true or false, on two large
// overlapping spaces (Minus built the whole difference first).
func TestSubsetAllocatesNothing(t *testing.T) {
	x := SpaceOf(benchRanges(20_000, 24, 32)...)
	y := SpaceOf(benchRanges(20_000, 24, 28)...)
	if !y.Subset(x) || x.Subset(y) {
		t.Fatalf("fixture: want y in x and x not in y")
	}
	for _, c := range []struct {
		name string
		f    func()
	}{{"true", func() { _ = y.Subset(x) }}, {"false", func() { _ = x.Subset(y) }}} {
		if n := testing.AllocsPerRun(10, c.f); n != 0 {
			t.Errorf("Subset answering %s: %v allocations, want 0", c.name, n)
		}
	}
}

// Where the other side already holds every prefix below a node, the walks
// stop there rather than visiting the node's whole subtree: an earlier ANY
// beside the cover's kept large spaces made each later clause's test walk
// all of them (64 ms where Subset of the built union took 29 ns).
func TestSubsetStopsWhereCovered(t *testing.T) {
	anyV4 := spaceOf(t, "0.0.0.0/0^+")
	ts := []PrefixSpace{anyV4}
	for k := range 16 {
		ts = append(ts, SpaceOf(benchRanges(40_000, 24, 24+k%8)...))
	}
	wide := spaceOf(t, "0.0.0.0/0^8-24")
	large := SpaceOf(benchRanges(40_000, 24, 26)...)
	for _, c := range []struct {
		name string
		f    func() bool
	}{
		{"SubsetOfUnion, a broad s", func() bool { return wide.SubsetOfUnion(ts...) }},
		{"SubsetOfUnion, a large s", func() bool { return large.SubsetOfUnion(ts...) }},
		{"Subset, a large s in ANY", func() bool { return large.Subset(anyV4) }},
	} {
		best := time.Hour
		for range 3 {
			start := time.Now()
			if !c.f() {
				t.Fatalf("%s: false, want true", c.name)
			}
			best = min(best, time.Since(start))
		}
		// The walk stops at the root: microseconds, even under -race.
		if best > time.Millisecond {
			t.Errorf("%s: took %v, want it to stop where covered (under 1ms)", c.name, best)
		}
	}
}
