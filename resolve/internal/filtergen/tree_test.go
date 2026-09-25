package filtergen

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// treeOf builds a tree of exact prefixes.
func treeOf(t testing.TB, v6 bool, ps []netip.Prefix) *Tree {
	t.Helper()
	tr := NewTree(v6, 0, 1<<20)
	for _, p := range ps {
		r, _ := types.NewPrefixRange(p, p.Bits(), p.Bits())
		if err := tr.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	return tr
}

// denoted is the set of prefixes the entries stand for.
func denoted(es []Entry) map[netip.Prefix]bool {
	out := map[netip.Prefix]bool{}
	for _, e := range es {
		for p := range e.Range().All() {
			out[p] = true
		}
	}
	return out
}

// randomPrefixes draws prefixes packed into a small space, so that halves
// meet and aggregation has something to do.
func randomPrefixes(r *rand.Rand, v6 bool, n int) []netip.Prefix {
	base, lo, hi := netip.MustParsePrefix("10.0.0.0/16"), 16, 24
	if v6 {
		base, lo, hi = netip.MustParsePrefix("2001:db8::/32"), 32, 40
	}
	var out []netip.Prefix
	for range n {
		b := base.Addr().AsSlice()
		for i := base.Bits() / 8; i < len(b); i++ {
			b[i] = byte(r.IntN(256))
		}
		a, _ := netip.AddrFromSlice(b)
		out = append(out, netip.PrefixFrom(a, lo+r.IntN(hi-lo+1)).Masked())
	}
	return out
}

func exactEntries(ps []netip.Prefix) []Entry {
	seen := map[netip.Prefix]bool{}
	var out []Entry
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, Entry{Prefix: p})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Prefix.Addr().Compare(out[j].Prefix.Addr()); c != 0 {
			return c < 0
		}
		return out[i].Prefix.Bits() < out[j].Prefix.Bits()
	})
	return out
}

// Without aggregation the tree holds each prefix once, in address order and
// then by length — the order bgpq4 prints.
func TestTreeEntriesAreSorted(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 1))
		v6 := seed%2 == 1
		ps := randomPrefixes(r, v6, 1+r.IntN(40))
		if got, want := treeOf(t, v6, ps).Entries(), exactEntries(ps); !slices.Equal(got, want) {
			t.Fatalf("seed %d: entries %v, want %v", seed, got, want)
		}
	}
}

// Aggregation only merges halves that are both present, so the list still
// stands for exactly the prefixes put in.
func TestAggregateIsLossless(t *testing.T) {
	for seed := uint64(0); seed < 500; seed++ {
		r := rand.New(rand.NewPCG(seed, 2))
		v6 := seed%2 == 1
		ps := randomPrefixes(r, v6, 1+r.IntN(200))
		tr := treeOf(t, v6, ps)
		tr.Aggregate()
		checkLossless(t, fmt.Sprintf("seed %d", seed), ps, tr.Entries())
	}
}

func checkLossless(t *testing.T, label string, ps []netip.Prefix, es []Entry) {
	t.Helper()
	want := map[netip.Prefix]bool{}
	for _, p := range ps {
		want[p] = true
	}
	got := denoted(es)
	for p := range want {
		if !got[p] {
			t.Fatalf("%s: %s lost; entries %v", label, p, es)
		}
	}
	for p := range got {
		if !want[p] {
			t.Fatalf("%s: %s added; entries %v", label, p, es)
		}
	}
}

func e(p string, lo, hi int) Entry {
	return Entry{Prefix: netip.MustParsePrefix(p), Aggregate: true, Lo: lo, Hi: hi}
}

func x(p string) Entry { return Entry{Prefix: netip.MustParsePrefix(p)} }

// Cases worked through bgpq4's code by hand; the differential below checks
// the rest against bgpq4 itself.
func TestTreeGolden(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	for _, c := range []struct {
		name string
		in   []netip.Prefix
		op   func(*Tree)
		want []Entry
	}{
		{"two halves under glue", pfx("10.0.0.0/25", "10.0.0.128/25"), (*Tree).Aggregate,
			[]Entry{e("10.0.0.0/24", 25, 25)}},
		{"two halves under an entry", pfx("10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25"), (*Tree).Aggregate,
			[]Entry{e("10.0.0.0/24", 24, 25)}},
		{"a half alone", pfx("10.0.0.0/24", "10.0.0.0/25"), (*Tree).Aggregate,
			[]Entry{x("10.0.0.0/24"), x("10.0.0.0/25")}},
		{"four quarters", pfx("10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"), (*Tree).Aggregate,
			[]Entry{e("10.0.0.0/24", 26, 26)}},
		{"quarters under an entry: a son", pfx("10.0.0.0/24", "10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"), (*Tree).Aggregate,
			[]Entry{x("10.0.0.0/24"), e("10.0.0.0/24", 26, 26)}},
		{"-R 26", pfx("10.0.0.0/24", "10.0.0.0/25", "10.0.1.0/27"), func(t *Tree) { t.Refine(26) },
			[]Entry{e("10.0.0.0/24", 24, 26), x("10.0.1.0/27")}},
		{"-r 25", pfx("10.0.0.0/24", "10.0.0.0/25", "10.0.1.0/27"), func(t *Tree) { t.RefineLow(25) },
			[]Entry{e("10.0.0.0/24", 25, 32), x("10.0.1.0/27")}},
		{"-r 32 on a /32", pfx("10.0.0.1/32"), func(t *Tree) { t.RefineLow(32) },
			[]Entry{e("10.0.0.1/32", 32, 32)}},
	} {
		tr := treeOf(t, false, c.in)
		c.op(tr)
		if got := tr.Entries(); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTreeAddRangesAndLimits(t *testing.T) {
	tr := NewTree(false, 26, 1<<20)
	for _, s := range []string{"10.0.0.0/24^+", "10.1.0.0/27", "2001:db8::/32", "10.2.0.0/24^28-30"} {
		r, err := types.ParsePrefixRange(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	// /24^+ up to -m 26 is 1+2+4 prefixes; the /27, the IPv6 prefix and a
	// window wholly past 26 add nothing.
	if got := len(tr.Entries()); got != 7 {
		t.Errorf("%d entries, want 7: %v", got, tr.Entries())
	}
	small := NewTree(false, 0, 100)
	r, _ := types.ParsePrefixRange("10.0.0.0/8^+")
	if err := small.Add(r); err == nil {
		t.Error("a /8^+ fits in 100 nodes")
	}
}

// FuzzAggregate: any set of prefixes, aggregated and refined, stays within
// bgpq4's tree without a panic (bgpq4 aborts on an "unreachable point"), and
// aggregation alone loses and adds nothing.
func FuzzAggregate(f *testing.F) {
	f.Add([]byte{0, 0, 24, 0, 128, 25, 0, 0, 25}, uint8(0), uint8(0))
	f.Add([]byte{1, 2, 26, 1, 66, 26, 1, 130, 26, 1, 194, 26}, uint8(28), uint8(26))
	f.Fuzz(func(t *testing.T, data []byte, refine, refineLow uint8) {
		var ps []netip.Prefix
		for i := 0; i+2 < len(data) && len(ps) < 512; i += 3 {
			a := netip.AddrFrom4([4]byte{10, data[i], data[i+1], 0})
			ps = append(ps, netip.PrefixFrom(a, 16+int(data[i+2])%9).Masked())
		}
		tr := treeOf(t, false, ps)
		tr.Aggregate()
		checkLossless(t, "aggregate", ps, tr.Entries())
		tr = treeOf(t, false, ps)
		if n := int(refine) % 33; n > 0 {
			tr.Refine(n)
		}
		if n := int(refineLow) % 33; n > 0 {
			tr.RefineLow(n)
		}
		tr.Aggregate()
		_ = tr.Entries()
	})
}

// The tree gives bgpq4's entries: the same random prefixes, given to both as
// objects on the command line and printed with a format that shows every
// entry's lengths, under -A, -R and -r.
func TestTreeMatchesBgpq4(t *testing.T) {
	if _, err := exec.LookPath("bgpq4"); err != nil {
		t.Skip("bgpq4 is not installed")
	}
	addr := irrtest.New().IRRd(t)
	const format = `%n/%l %a %A\n`
	for seed := uint64(0); seed < 120; seed++ {
		r := rand.New(rand.NewPCG(seed, 3))
		v6 := seed%2 == 1
		ps := randomPrefixes(r, v6, 1+r.IntN(120))
		full := 32
		fam := "-4"
		if v6 {
			full, fam = 128, "-6"
		}
		base := ps[0].Bits()
		var flags []string
		refine, refineLow := 0, 0
		switch seed % 5 {
		case 1:
			refine = base + 1 + r.IntN(4)
		case 2:
			refineLow = base + r.IntN(4)
		case 3:
			refine = base + 2 + r.IntN(4)
			refineLow = refine - 1 - r.IntN(2)
		case 4:
			refineLow = base + r.IntN(4)
			refine = full
		}
		if refine > 0 {
			flags = append(flags, "-R", fmt.Sprint(refine))
		}
		if refineLow > 0 {
			flags = append(flags, "-r", fmt.Sprint(refineLow))
		}
		for _, aggregate := range []bool{false, true} {
			args := append([]string{"-h", addr, fam, "-F", format}, flags...)
			if aggregate {
				args = append(args, "-A")
			}
			for _, p := range ps {
				args = append(args, p.String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			out, err := exec.CommandContext(ctx, "bgpq4", args...).Output()
			cancel()
			if err != nil {
				t.Fatalf("seed %d: bgpq4 %v: %v", seed, args, err)
			}
			tr := treeOf(t, v6, ps)
			if refineLow > 0 && refine == 0 {
				refine = full // bgpq4's main.c: -r alone implies -R to the full length
			}
			if refine > 0 {
				tr.Refine(refine)
			}
			if refineLow > 0 {
				tr.RefineLow(refineLow)
			}
			if aggregate {
				tr.Aggregate()
			}
			var b strings.Builder
			for _, en := range tr.Entries() {
				lo, hi := en.Prefix.Bits(), en.Prefix.Bits()
				if en.Aggregate {
					hi = en.Hi
					if en.Lo > en.Prefix.Bits() {
						lo = en.Lo
					}
				}
				fmt.Fprintf(&b, "%s/%d %d %d\n", en.Prefix.Addr(), en.Prefix.Bits(), lo, hi)
			}
			if b.String() != string(out) {
				t.Fatalf("seed %d, flags %v, -A %v: tree\n%s\nbgpq4\n%s", seed, flags, aggregate, b.String(), out)
			}
		}
	}
}
