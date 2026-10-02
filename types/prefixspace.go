package types

import (
	"iter"
	"math/bits"
	"net/netip"
	"strings"
)

// PrefixSpace is an exact set of prefixes of both families, closed under
// union, intersection and difference (Union, Intersect, Minus). The zero
// value is the empty set. A PrefixSpace is immutable: operations return new
// spaces that may share structure with their operands, so a value is safe to
// copy and to share between goroutines.
//
// It never enumerates prefixes: ::/0^0-128 is one node, and the cost of an
// operation is bounded by the ranges it was built from times the prefix
// length. Two spaces holding the same set are structurally identical
// (canonical form), so Equal is exact and Ranges is unique.
type PrefixSpace struct{ v4, v6 *spaceNode }

// spaceNode is a node of one family's binary trie. Its position (the path
// from the root) is its prefix; mask bit l, for l at least the node's depth,
// says every prefix of length l under that prefix is in the set.
//
// Canonical form: no node holds a bit below its depth or a bit an ancestor
// holds; no two children of one node hold the same bit (it is held by the
// parent instead); no node is empty. Every exported constructor and
// operation returns canonical spaces; nodes are never mutated once built.
type spaceNode struct {
	mask  lenMask
	child [2]*spaceNode
}

// lenMask is a set of prefix lengths, 0 to 128: bit l of word l/64.
type lenMask [3]uint64

func (m lenMask) has(l int) bool           { return m[l>>6]&(1<<(l&63)) != 0 }
func (m *lenMask) set(l int)               { m[l>>6] |= 1 << (l & 63) }
func (m lenMask) isZero() bool             { return m[0]|m[1]|m[2] == 0 }
func (m lenMask) and(o lenMask) lenMask    { return lenMask{m[0] & o[0], m[1] & o[1], m[2] & o[2]} }
func (m lenMask) or(o lenMask) lenMask     { return lenMask{m[0] | o[0], m[1] | o[1], m[2] | o[2]} }
func (m lenMask) andNot(o lenMask) lenMask { return lenMask{m[0] &^ o[0], m[1] &^ o[1], m[2] &^ o[2]} }
func (m lenMask) equal(o lenMask) bool     { return m == o }

// lowest returns the smallest length in m, or -1 when m is empty.
func (m lenMask) lowest() int {
	for w, x := range m {
		if x != 0 {
			return w*64 + bits.TrailingZeros64(x)
		}
	}
	return -1
}

// geMask[d] holds every length from d to 128; geMask[129] is empty.
var geMask = func() (t [130]lenMask) {
	for d := 0; d <= 129; d++ {
		for l := d; l <= 128; l++ {
			t[d].set(l)
		}
	}
	return t
}()

// window returns the lengths lo..hi.
func window(lo, hi int) lenMask { return geMask[lo].andNot(geMask[hi+1]) }

// one returns the length l alone.
func one(l int) lenMask { return window(l, l) }

// SpaceOf returns the union of rs. An empty range adds nothing.
func SpaceOf(rs ...PrefixRange) PrefixSpace {
	var raw [2]*spaceNode // mutable tries, built here and discarded: IPv4, IPv6
	for _, r := range rs {
		if r.IsEmpty() {
			continue
		}
		p := r.Prefix()
		f := 0
		if !p.Addr().Is4() {
			f = 1
		}
		if raw[f] == nil {
			raw[f] = &spaceNode{}
		}
		n := raw[f]
		for d := 0; d < p.Bits(); d++ {
			b := bitAt(p.Addr(), d)
			if n.child[b] == nil {
				n.child[b] = &spaceNode{}
			}
			n = n.child[b]
		}
		n.mask = n.mask.or(window(max(r.Lo(), p.Bits()), r.Hi()))
	}
	return PrefixSpace{normalize(raw[0], 0, 32, lenMask{}), normalize(raw[1], 0, 128, lenMask{})}
}

// FullSpace returns every prefix of afi: AFIv4 or AFIv6 one family,
// AFIAny and AFIUnspecified both.
func FullSpace(afi AFI) PrefixSpace {
	v4 := &spaceNode{mask: window(0, 32)}
	v6 := &spaceNode{mask: window(0, 128)}
	switch afi {
	case AFIv4:
		return PrefixSpace{v4: v4}
	case AFIv6:
		return PrefixSpace{v6: v6}
	}
	return PrefixSpace{v4: v4, v6: v6}
}

// normalize returns the canonical form of the raw trie n at depth d of a
// family width bits wide. covered holds the lengths an ancestor already
// holds; n's copies of them are dropped.
func normalize(n *spaceNode, d, width int, covered lenMask) *spaceNode {
	if n == nil {
		return nil
	}
	m := n.mask.and(geMask[d]).andNot(covered)
	var c [2]*spaceNode
	if d < width {
		below := covered.or(m).and(geMask[d+1])
		c[0] = normalize(n.child[0], d+1, width, below)
		c[1] = normalize(n.child[1], d+1, width, below)
		m, c = lift(m, c, d)
	}
	return mk(m, c)
}

// lift moves the lengths both children of a node at depth d hold up to the
// node, keeping the canonical form after a node's children were rebuilt.
func lift(m lenMask, c [2]*spaceNode, d int) (lenMask, [2]*spaceNode) {
	if c[0] == nil || c[1] == nil {
		return m, c
	}
	common := c[0].mask.and(c[1].mask).and(geMask[d+1])
	if common.isZero() {
		return m, c
	}
	return m.or(common), [2]*spaceNode{without(c[0], common), without(c[1], common)}
}

// without returns n less the lengths in m, as a new node (n is shared).
func without(n *spaceNode, m lenMask) *spaceNode { return mk(n.mask.andNot(m), n.child) }

// mk returns a node, or nil when it would be empty.
func mk(m lenMask, c [2]*spaceNode) *spaceNode {
	if m.isZero() && c[0] == nil && c[1] == nil {
		return nil
	}
	return &spaceNode{mask: m, child: c}
}

// bitAt returns bit d of a's address, the most significant first.
func bitAt(a netip.Addr, d int) int {
	if a.Is4() {
		b := a.As4()
		return int(b[d>>3]>>(7-d&7)) & 1
	}
	b := a.As16()
	return int(b[d>>3]>>(7-d&7)) & 1
}

// setAddrBit sets bit d of addr to v.
func setAddrBit(addr *[16]byte, d, v int) {
	bit := byte(1) << (7 - d&7)
	if v == 1 {
		addr[d>>3] |= bit
	} else {
		addr[d>>3] &^= bit
	}
}

// prefixAt returns the prefix of length d whose address is addr, of the
// family width bits wide (IPv4: the first four bytes).
func prefixAt(addr *[16]byte, d, width int) netip.Prefix {
	if width == 32 {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte(addr[:4])), d)
	}
	return netip.PrefixFrom(netip.AddrFrom16(*addr), d)
}

// IsEmpty reports whether s holds no prefix.
func (s PrefixSpace) IsEmpty() bool { return s.v4 == nil && s.v6 == nil }

// Equal reports whether s and t hold the same prefixes.
func (s PrefixSpace) Equal(t PrefixSpace) bool { return equalNode(s.v4, t.v4) && equalNode(s.v6, t.v6) }

func equalNode(a, b *spaceNode) bool {
	switch {
	case a == b:
		return true
	case a == nil || b == nil:
		return false
	}
	return a.mask.equal(b.mask) && equalNode(a.child[0], b.child[0]) && equalNode(a.child[1], b.child[1])
}

// Contains reports whether s holds p.
func (s PrefixSpace) Contains(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	p = p.Masked()
	n := s.v6
	if p.Addr().Is4() {
		n = s.v4
	}
	l := p.Bits()
	for d := 0; n != nil; d++ {
		if n.mask.has(l) {
			return true
		}
		if d == l {
			return false
		}
		n = n.child[bitAt(p.Addr(), d)]
	}
	return false
}

// Example returns one prefix of s: when s holds any IPv4 prefix, the
// shortest IPv4 prefix, and among those the lowest address; otherwise the
// same of IPv6. ok is false when s is empty.
func (s PrefixSpace) Example() (p netip.Prefix, ok bool) {
	for _, f := range []struct {
		n     *spaceNode
		width int
	}{{s.v4, 32}, {s.v6, 128}} {
		if f.n == nil {
			continue
		}
		short := shortest(f.n)
		var addr [16]byte
		if p, ok := firstWith(f.n, 0, f.width, short, &addr); ok {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// shortest returns the smallest length any node under n holds.
func shortest(n *spaceNode) int {
	best := n.mask.lowest()
	for _, c := range n.child {
		if c == nil {
			continue
		}
		if l := shortest(c); l >= 0 && (best < 0 || l < best) {
			best = l
		}
	}
	return best
}

// firstWith returns, in address order, the first prefix of length l the
// subtree at n (depth d, address addr) holds. A node's own prefix padded
// with zeros comes before any of its descendants' (pre-order), and a
// 0-child's before a 1-child's, so the first node holding l gives the
// lowest address.
func firstWith(n *spaceNode, d, width, l int, addr *[16]byte) (netip.Prefix, bool) {
	if n.mask.has(l) {
		p, err := prefixAt(addr, d, width).Addr().Prefix(l) // the node's prefix padded with zeros
		return p, err == nil
	}
	for i, c := range n.child {
		if c == nil {
			continue
		}
		setAddrBit(addr, d, i)
		p, ok := firstWith(c, d+1, width, l, addr)
		setAddrBit(addr, d, 0)
		if ok {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// Ranges yields s as disjoint ranges in canonical order: IPv4 before IPv6,
// then by address (a prefix before those under it), then by low length.
// SpaceOf of every range it yields is Equal to s.
func (s PrefixSpace) Ranges() iter.Seq[PrefixRange] {
	return func(yield func(PrefixRange) bool) {
		var addr [16]byte
		if !walkRanges(s.v4, 0, 32, &addr, yield) {
			return
		}
		addr = [16]byte{}
		walkRanges(s.v6, 0, 128, &addr, yield)
	}
}

func walkRanges(n *spaceNode, d, width int, addr *[16]byte, yield func(PrefixRange) bool) bool {
	if n == nil {
		return true
	}
	p := prefixAt(addr, d, width)
	for l := d; l <= width; l++ {
		if !n.mask.has(l) {
			continue
		}
		hi := l
		for hi < width && n.mask.has(hi+1) {
			hi++
		}
		r, _ := NewPrefixRange(p, l, hi) // l..hi lies within d..width: always ok
		if !yield(r) {
			return false
		}
		l = hi
	}
	for i, c := range n.child {
		if c == nil {
			continue
		}
		setAddrBit(addr, d, i)
		ok := walkRanges(c, d+1, width, addr, yield)
		setAddrBit(addr, d, 0)
		if !ok {
			return false
		}
	}
	return true
}

// String renders s as its ranges in braces: "{10.0.0.0/24^+, 2001:db8::/48}".
func (s PrefixSpace) String() string {
	var parts []string
	for r := range s.Ranges() {
		parts = append(parts, r.String())
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
