package types

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

// The model: a space is an expression over ranges, and the oracle decides
// membership of any prefix straight from the expression. The universe is
// small enough to enumerate: every IPv4 prefix under 10.0.0.0/24 of length
// 24 to 32, and every IPv6 prefix under 2001:db8::/120 of length 120 to 128
// (511 each). Ranges are drawn inside it and also above its root
// (10.0.0.0/8^24-26), so the spaces reach past it; probes outside it check
// those parts.

var (
	uni4     = netip.MustParsePrefix("10.0.0.0/24")
	uni6     = netip.MustParsePrefix("2001:db8::/120")
	universe = func() []netip.Prefix {
		var out []netip.Prefix
		for _, root := range []netip.Prefix{uni4, uni6} {
			w := root.Addr().BitLen()
			for l := root.Bits(); l <= w; l++ {
				for i := 0; i < 1<<(l-root.Bits()); i++ {
					out = append(out, under(root, l, uint64(i)))
				}
			}
		}
		return out
	}()
	probes = func() []netip.Prefix {
		var out []netip.Prefix
		for _, s := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/23", "10.0.1.0/24", "10.0.1.128/25",
			"11.0.0.0/24", "10.200.0.0/24", "::/0", "2001:db8::/32", "2001:db8::/119", "2001:db8::100/120", "2001:db8::100/128"} {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}()
	// ancestors are the roots a range may be drawn above the universe at.
	ancestors4 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.0.0.0/23")}
	ancestors6 = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:db8::/112"), netip.MustParsePrefix("2001:db8::/119")}
	uniSpace   = SpaceOf(mustRange(uni4, 24, 32), mustRange(uni6, 120, 128))
)

func mustRange(p netip.Prefix, lo, hi int) PrefixRange {
	r, ok := NewPrefixRange(p, lo, hi)
	if !ok {
		panic(fmt.Sprintf("NewPrefixRange(%v, %d, %d)", p, lo, hi))
	}
	return r
}

// under returns the prefix of length l under root whose bits past root's
// are i (the last l-root.Bits() bits of i).
func under(root netip.Prefix, l int, i uint64) netip.Prefix {
	b := root.Addr().As16()
	off := 0
	if root.Addr().Is4() {
		off = 96
	}
	n := l - root.Bits()
	for k := 0; k < n; k++ {
		bit := int(i>>(n-1-k)) & 1
		pos := off + root.Bits() + k
		if bit == 1 {
			b[pos>>3] |= 1 << (7 - pos&7)
		}
	}
	a := netip.AddrFrom16(b)
	if root.Addr().Is4() {
		a = a.Unmap()
	}
	return netip.PrefixFrom(a, l)
}

// canonErr reports the first canonical-form violation (see spaceNode) found
// under n, a node at depth d of a family width bits wide; anc is the lengths
// an ancestor already holds.
func canonErr(n *spaceNode, d, width int, anc lenMask) error {
	if n == nil {
		return nil
	}
	if n.mask.isZero() && n.child[0] == nil && n.child[1] == nil {
		return fmt.Errorf("empty node at depth %d", d)
	}
	if !n.mask.andNot(geMask[d]).isZero() {
		return fmt.Errorf("bit below depth %d", d)
	}
	if !n.mask.and(anc).isZero() {
		return fmt.Errorf("bit an ancestor holds at depth %d", d)
	}
	if n.child[0] != nil && n.child[1] != nil && !n.child[0].mask.and(n.child[1].mask).isZero() {
		return fmt.Errorf("unlifted bit at depth %d", d)
	}
	if d == width && (n.child[0] != nil || n.child[1] != nil) {
		return fmt.Errorf("children past width")
	}
	for _, c := range n.child {
		if err := canonErr(c, d+1, width, anc.or(n.mask)); err != nil {
			return err
		}
	}
	return nil
}

// checkCanonical fails the test if s violates the canonical-form invariants:
// an empty node, a mask bit below the node's depth, a bit an ancestor
// already holds, a bit both children hold (unlifted), or a child beyond the
// family width.
func checkCanonical(t *testing.T, label string, s PrefixSpace) {
	t.Helper()
	if err := canonErr(s.v4, 0, 32, lenMask{}); err != nil {
		t.Fatalf("%s: v4 not canonical: %v", label, err)
	}
	if err := canonErr(s.v6, 0, 128, lenMask{}); err != nil {
		t.Fatalf("%s: v6 not canonical: %v", label, err)
	}
}

type expr struct {
	op   string // "ranges", "union", "intersect", "minus"
	rs   []PrefixRange
	l, r *expr
}

func (e *expr) contains(p netip.Prefix) bool {
	switch e.op {
	case "ranges":
		for _, r := range e.rs {
			if !r.IsEmpty() && r.Contains(p) {
				return true
			}
		}
		return false
	case "union":
		return e.l.contains(p) || e.r.contains(p)
	case "intersect":
		return e.l.contains(p) && e.r.contains(p)
	}
	return e.l.contains(p) && !e.r.contains(p)
}

// space builds e's PrefixSpace, checking every intermediate Union/Intersect/
// Minus result for canonical form as it goes, so a non-canonical result
// anywhere in the tree fails the test rather than being re-canonicalized by
// an operation further up (as intersecting with uniSpace would).
func (e *expr) space(t *testing.T) PrefixSpace {
	t.Helper()
	var s PrefixSpace
	switch e.op {
	case "ranges":
		s = SpaceOf(e.rs...)
	case "union":
		s = e.l.space(t).Union(e.r.space(t))
	case "intersect":
		s = e.l.space(t).Intersect(e.r.space(t))
	default:
		s = e.l.space(t).Minus(e.r.space(t))
	}
	checkCanonical(t, e.String(), s)
	return s
}

func (e *expr) String() string {
	if e.op == "ranges" {
		return fmt.Sprint(e.rs)
	}
	return fmt.Sprintf("(%v %s %v)", e.l, e.op, e.r)
}

// randomRange draws a range in the universe, or (one in four) above its root.
func randomRange(r *rand.Rand) PrefixRange {
	v6 := r.IntN(2) == 1
	root, anc, w := uni4, ancestors4, 32
	if v6 {
		root, anc, w = uni6, ancestors6, 128
	}
	var p netip.Prefix
	if r.IntN(4) == 0 {
		p = anc[r.IntN(len(anc))]
	} else {
		l := root.Bits() + r.IntN(w-root.Bits()+1)
		p = under(root, l, r.Uint64())
	}
	lo := p.Bits() + r.IntN(w-p.Bits()+1)
	if p.Bits() < root.Bits() && r.IntN(2) == 0 {
		lo = root.Bits() + r.IntN(w-root.Bits()+1) // reach into the universe
	}
	hi := lo + r.IntN(w-lo+1)
	return mustRange(p, lo, hi)
}

func randomExpr(r *rand.Rand, depth int) *expr {
	if depth == 0 || r.IntN(3) == 0 {
		e := &expr{op: "ranges"}
		for n := r.IntN(4); n > 0; n-- {
			e.rs = append(e.rs, randomRange(r))
		}
		return e
	}
	return &expr{op: []string{"union", "intersect", "minus"}[r.IntN(3)], l: randomExpr(r, depth-1), r: randomExpr(r, depth-1)}
}

// members returns the universe prefixes e holds, in universe order.
func (e *expr) members() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range universe {
		if e.contains(p) {
			out = append(out, p)
		}
	}
	return out
}

// lessPrefix orders as Example promises: IPv4 first, then shorter, then
// lower address.
func lessPrefix(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Bits() != b.Bits() {
		return a.Bits() < b.Bits()
	}
	return a.Addr().Less(b.Addr())
}

// checkExpr holds e's space to the oracle. other is a second expression for
// the pairwise properties (Equal, Subset).
func checkExpr(t *testing.T, label string, e, other *expr) {
	t.Helper()
	s := e.space(t)
	checkCanonical(t, label, s) // the result itself, not only in (below), which Intersect with uniSpace would re-canonicalize regardless
	for _, p := range append(slices.Clone(universe), probes...) {
		if got, want := s.Contains(p), e.contains(p); got != want {
			t.Fatalf("%s: %v: Contains(%v) = %v, the oracle %v\nspace %v", label, e, p, got, want, s)
		}
	}
	in := s.Intersect(uniSpace) // inside the universe: a set the oracle can enumerate
	want := e.members()
	if in.IsEmpty() != (len(want) == 0) {
		t.Fatalf("%s: %v: IsEmpty %v, the oracle has %d members", label, e, in.IsEmpty(), len(want))
	}
	if len(want) > 0 {
		best := want[0]
		for _, p := range want[1:] {
			if lessPrefix(p, best) {
				best = p
			}
		}
		if got, ok := in.Example(); !ok || got != best {
			t.Fatalf("%s: %v: Example %v %v, want %v", label, e, got, ok, best)
		}
	}
	// The ranges are disjoint and cover exactly the members.
	covered := 0
	var rs []PrefixRange
	for r := range in.Ranges() {
		rs = append(rs, r)
		for _, p := range universe {
			if r.Contains(p) {
				covered++
			}
		}
	}
	if covered != len(want) {
		t.Fatalf("%s: %v: ranges %v cover %d universe prefixes, the oracle has %d members", label, e, rs, covered, len(want))
	}
	if !SpaceOf(rs...).Equal(in) {
		t.Fatalf("%s: %v: SpaceOf(Ranges) is not Equal: %v", label, e, rs)
	}
	// Canonical: the same set built from its members one by one is Equal.
	var singles []PrefixRange
	for _, p := range want {
		singles = append(singles, mustRange(p, p.Bits(), p.Bits()))
	}
	if !SpaceOf(singles...).Equal(in) {
		t.Fatalf("%s: %v: not canonical: %v differs from the same set built from its members, %v", label, e, in, SpaceOf(singles...))
	}
	if !in.Union(in).Equal(in) || !in.Minus(PrefixSpace{}).Equal(in) || !in.Intersect(in).Equal(in) {
		t.Fatalf("%s: %v: an identity operation changed the space", label, e)
	}
	o := other.space(t).Intersect(uniSpace)
	owant := other.members()
	if got, want := in.Equal(o), slices.Equal(want, owant); got != want {
		t.Fatalf("%s: Equal(%v, %v) = %v, the oracle %v", label, e, other, got, want)
	}
	sub := true
	for _, p := range want {
		if !other.contains(p) {
			sub = false
			break
		}
	}
	if got := in.Subset(o); got != sub {
		t.Fatalf("%s: Subset(%v, %v) = %v, the oracle %v", label, e, other, got, sub)
	}
}

func TestSpaceAgainstBruteForce(t *testing.T) {
	for seed := uint64(0); seed < 500; seed++ {
		r := rand.New(rand.NewPCG(seed, 31))
		checkExpr(t, fmt.Sprintf("seed %d", seed), randomExpr(r, 4), randomExpr(r, 3))
	}
}

// FuzzPrefixSpace decodes an expression from bytes and holds it to the
// oracle, as TestSpaceAgainstBruteForce does for random ones.
func FuzzPrefixSpace(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	f.Add([]byte{3, 0, 0, 0, 200, 9, 1, 1, 7, 7, 7, 7, 2, 2, 2, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			return
		}
		seed := uint64(len(data))
		for i := 0; i+8 <= len(data); i += 8 {
			seed ^= binary.LittleEndian.Uint64(data[i:]) + uint64(i)
		}
		r := rand.New(rand.NewPCG(seed, uint64(len(data))))
		depth := 1
		if len(data) > 0 {
			depth = 1 + int(data[0]%5)
		}
		checkExpr(t, "fuzz", randomExpr(r, depth), randomExpr(r, 2))
	})
}

func benchRanges(n int, lo, hi int) []PrefixRange {
	rs := make([]PrefixRange, n)
	for i := range rs {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(i)<<8)
		rs[i] = mustRange(netip.PrefixFrom(netip.AddrFrom4(b), 24), lo, hi)
	}
	return rs
}

func BenchmarkSpaceOf100k(b *testing.B) {
	rs := benchRanges(100_000, 24, 28)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SpaceOf(rs...)
	}
}

func BenchmarkSpaceMinus100k(b *testing.B) {
	x := SpaceOf(benchRanges(100_000, 24, 32)...)
	var half []PrefixRange
	for _, r := range benchRanges(100_000, 25, 25) {
		half = append(half, r)
	}
	y := SpaceOf(half...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Minus(y)
	}
}
