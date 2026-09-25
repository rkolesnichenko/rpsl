package filtergen

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/types"
)

// Tree is bgpq4's prefix tree (sx_radix_tree in its sx_prefix.c), ported node
// for node: a binary radix tree whose inner nodes are either prefixes of the
// list or glue, with the flags and "son" chains its aggregation (-A) and
// more-specifics (-R, -r) leave behind. The algorithms are bgpq4's own, not a
// minimal aggregation, because a list meant to replace bgpq4's has to hold the
// same entries in the same order.
type Tree struct {
	v6       bool
	maxLen   int // longest prefix inserted (-m)
	maxNodes int
	nodes    int
	head     *node
}

// node is sx_radix_node: a prefix, its two subtrees (l: next bit 0, r: 1), a
// son — the same prefix with another aggregate range — and bgpq4's flags.
type node struct {
	parent, l, r, son *node
	prefix            netip.Prefix
	glue              bool // not an entry of the list: a branch point or merged away
	aggregate         bool // the entry is prefix^lo-hi rather than the prefix alone
	lo, hi            int
}

// Entry is one line of a list: a prefix, or, when Aggregate, the prefixes of
// lengths Lo to Hi within it. An aggregate entry is written with its lengths
// even when they are the prefix's own.
type Entry struct {
	Prefix    netip.Prefix
	Aggregate bool
	Lo, Hi    int
}

// Range is the entry as an RPSL prefix range.
func (e Entry) Range() types.PrefixRange {
	lo, hi := e.Prefix.Bits(), e.Prefix.Bits()
	if e.Aggregate {
		lo, hi = e.Lo, e.Hi
	}
	r, _ := types.NewPrefixRange(e.Prefix, lo, hi)
	return r
}

// ErrTooManyPrefixes reports a tree that would outgrow its node budget.
var ErrTooManyPrefixes = errors.New("filtergen: too many prefixes")

// NewTree returns an empty tree of one family that inserts no prefix longer
// than maxLen (0 means the family's full length) and refuses to grow past
// maxNodes nodes.
func NewTree(v6 bool, maxLen, maxNodes int) *Tree {
	full := 32
	if v6 {
		full = 128
	}
	if maxLen <= 0 || maxLen > full {
		maxLen = full
	}
	return &Tree{v6: v6, maxLen: maxLen, maxNodes: maxNodes}
}

func (t *Tree) full() int {
	if t.v6 {
		return 128
	}
	return 32
}

// Empty reports whether the tree holds no prefix.
func (t *Tree) Empty() bool { return t.head == nil }

// Add inserts every prefix r holds up to the tree's maximum length, as bgpq4
// inserts a prefix range (sx_prefix_range_parse, insert_specifics). A range of
// the other family, or whose prefix is longer than the maximum, adds nothing.
func (t *Tree) Add(r types.PrefixRange) error {
	p := r.Prefix()
	if p.Addr().Is6() != t.v6 || p.Bits() > t.maxLen {
		return nil
	}
	return t.insertSpecifics(p, int(r.Lo()), min(int(r.Hi()), t.maxLen))
}

// insertSpecifics is sx_radix_tree_insert_specifics: p if it is at least lo
// long, then both halves of p, down to hi.
func (t *Tree) insertSpecifics(p netip.Prefix, lo, hi int) error {
	if p.Bits() >= lo {
		if err := t.insert(p); err != nil {
			return err
		}
	}
	if p.Bits()+1 > hi {
		return nil
	}
	left := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	if err := t.insertSpecifics(left, lo, hi); err != nil {
		return err
	}
	return t.insertSpecifics(netip.PrefixFrom(setBit(p.Addr(), p.Bits()+1), p.Bits()+1), lo, hi)
}

func (t *Tree) newNode(p netip.Prefix) (*node, error) {
	if t.nodes >= t.maxNodes {
		return nil, fmt.Errorf("%w: more than %d", ErrTooManyPrefixes, t.maxNodes)
	}
	t.nodes++
	return &node{prefix: p}, nil
}

// insert is sx_radix_tree_insert.
func (t *Tree) insert(p netip.Prefix) error {
	if t.head == nil {
		n, err := t.newNode(p)
		t.head = n
		return err
	}
	candidate, chead := &t.head, t.head
	for {
		eb := eqBits(p, chead.prefix)
		switch {
		case eb < p.Bits() && eb < chead.prefix.Bits():
			// They part ways: a glue node at their common prefix holds both.
			ret, err := t.newNode(p)
			if err != nil {
				return err
			}
			rn, err := t.newNode(netip.PrefixFrom(p.Addr(), eb).Masked())
			if err != nil {
				return err
			}
			if bitSet(p.Addr(), eb+1) {
				rn.l, rn.r = chead, ret
			} else {
				rn.l, rn.r = ret, chead
			}
			rn.parent = chead.parent
			chead.parent, ret.parent = rn, rn
			rn.glue = true
			*candidate = rn
			return nil
		case eb == p.Bits() && eb < chead.prefix.Bits():
			// p covers chead: it takes chead's place, chead below it.
			ret, err := t.newNode(p)
			if err != nil {
				return err
			}
			if bitSet(chead.prefix.Addr(), eb+1) {
				ret.r = chead
			} else {
				ret.l = chead
			}
			ret.parent = chead.parent
			chead.parent = ret
			*candidate = ret
			return nil
		case eb == chead.prefix.Bits() && eb < p.Bits():
			// chead covers p: go down the side p's next bit names.
			next := &chead.l
			if bitSet(p.Addr(), eb+1) {
				next = &chead.r
			}
			if *next != nil {
				candidate, chead = next, *next
				continue
			}
			n, err := t.newNode(p)
			if err != nil {
				return err
			}
			n.parent = chead
			*next = n
			return nil
		default:
			// The same prefix: a glue node becomes an entry.
			chead.glue = false
			return nil
		}
	}
}

// eqBits is sx_prefix_eqbits for masked prefixes: how many leading bits the
// two share, at most the shorter length.
func eqBits(a, b netip.Prefix) int {
	n := min(a.Bits(), b.Bits())
	x, y := a.Addr().AsSlice(), b.Addr().AsSlice()
	for i := 0; i < n; i++ {
		if x[i/8]&(0x80>>(i%8)) != y[i/8]&(0x80>>(i%8)) {
			return i
		}
	}
	return n
}

// bitSet reports bit n of a, counting from 1 at the most significant, as
// sx_prefix_isbitset does; bits past the address are unset.
func bitSet(a netip.Addr, n int) bool {
	if n < 1 || n > a.BitLen() {
		return false
	}
	b := a.AsSlice()
	return b[(n-1)/8]&(0x80>>((n-1)%8)) != 0
}

// setBit returns a with bit n (from 1) set.
func setBit(a netip.Addr, n int) netip.Addr {
	b := a.AsSlice()
	b[(n-1)/8] |= 0x80 >> ((n - 1) % 8)
	out, _ := netip.AddrFromSlice(b)
	return out
}

// Entries returns the list the tree holds, in bgpq4's order: depth first, a
// node before its subtrees (the 0 side first), each followed by its son chain,
// glue left out.
func (t *Tree) Entries() []Entry {
	var out []Entry
	var emit func(n *node)
	emit = func(n *node) {
		if !n.glue {
			e := Entry{Prefix: n.prefix, Aggregate: n.aggregate}
			if n.aggregate {
				e.Lo, e.Hi = n.lo, n.hi
			}
			out = append(out, e)
		}
		if n.son != nil {
			emit(n.son)
		}
	}
	foreach(t.head, emit)
	return out
}

// foreach is sx_radix_node_foreach: n, then its l and r subtrees; sons are not
// visited.
func foreach(n *node, f func(*node)) {
	if n == nil {
		return
	}
	f(n)
	foreach(n.l, f)
	foreach(n.r, f)
}

// son returns a new aggregate son of n with the given lengths. Sons are not
// charged against the node budget: there is at most one per level of a chain,
// and a chain is at most two long.
func sonOf(n *node, lo, hi int) *node {
	return &node{prefix: n.prefix, aggregate: true, lo: lo, hi: hi}
}

// Aggregate is bgpq4's -A (sx_radix_node_aggregate): bottom up, two halves of
// a prefix that are both entries, or aggregates of the same lengths, merge
// into an aggregate of the prefix — kept on the node, or, where the node is
// itself an entry of other lengths, on a son.
func (t *Tree) Aggregate() {
	if t.head != nil {
		aggregate(t.head)
	}
}

func aggregate(n *node) {
	if n.l != nil {
		aggregate(n.l)
	}
	if n.r != nil {
		aggregate(n.r)
	}
	if n.r == nil || n.l == nil {
		return
	}
	l, r, bits := n.l, n.r, n.prefix.Bits()
	halves := l.prefix.Bits() == bits+1 && r.prefix.Bits() == bits+1
	switch {
	case !r.aggregate && !l.aggregate && !r.glue && !l.glue && r.prefix.Bits() == l.prefix.Bits():
		if r.prefix.Bits() == bits+1 {
			n.aggregate = true
			r.glue, l.glue = true, true
			n.hi = r.prefix.Bits()
			if n.glue {
				n.glue = false
				n.lo = r.prefix.Bits()
			} else {
				n.lo = bits
			}
		}
		if r.son != nil && l.son != nil && r.son.aggregate && l.son.aggregate &&
			r.son.hi == l.son.hi && r.son.lo == l.son.lo && halves {
			n.son = sonOf(n, r.son.lo, r.son.hi)
			r.son.glue, l.son.glue = true, true
		}
	case r.aggregate && l.aggregate && r.hi == l.hi && r.lo == l.lo:
		if !halves {
			return
		}
		switch {
		case n.glue:
			r.glue, l.glue = true, true
			n.aggregate, n.glue = true, false
			n.hi, n.lo = r.hi, r.lo
		case r.prefix.Bits() == r.lo:
			r.glue, l.glue = true, true
			n.aggregate = true
			n.hi, n.lo = r.hi, bits
		default:
			n.son = sonOf(n, r.lo, r.hi)
			r.glue, l.glue = true, true
			if r.son != nil && l.son != nil && r.son.hi == l.son.hi && r.son.lo == l.son.lo {
				n.son.son = sonOf(n, r.son.lo, r.son.hi)
				r.son.glue, l.son.glue = true, true
			}
		}
	case l.son != nil && r.aggregate && l.son.aggregate && r.hi == l.son.hi && r.lo == l.son.lo:
		if !halves {
			return
		}
		if n.glue {
			r.glue, l.son.glue = true, true
			n.aggregate, n.glue = true, false
			n.hi, n.lo = r.hi, r.lo
		} else {
			n.son = sonOf(n, r.lo, r.hi)
			r.glue, l.son.glue = true, true
		}
	case r.son != nil && l.aggregate && r.son.aggregate && l.hi == r.son.hi && l.lo == r.son.lo:
		if !halves {
			return
		}
		if n.glue {
			l.glue, r.son.glue = true, true
			n.aggregate, n.glue = true, false
			n.hi, n.lo = l.hi, l.lo
		} else {
			n.son = sonOf(n, l.lo, l.hi)
			l.glue, r.son.glue = true, true
		}
	}
}

// Refine is bgpq4's -R (sx_radix_node_refine): every entry shorter than hi
// becomes an aggregate up to hi, and the entries it then covers, up to hi
// long, are dropped.
func (t *Tree) Refine(hi int) {
	if t.head != nil {
		refine(t.head, hi)
	}
}

func refine(n *node, hi int) {
	glueUpTo := func(m *node) {
		if m.prefix.Bits() <= hi {
			m.glue = true
		}
	}
	switch {
	case !n.glue && n.prefix.Bits() < hi:
		n.aggregate = true
		n.lo, n.hi = n.prefix.Bits(), hi
		for _, c := range []*node{n.l, n.r} {
			if c != nil {
				foreach(c, glueUpTo)
				refine(c, hi)
			}
		}
	case !n.glue && n.prefix.Bits() == hi, n.glue:
		// bgpq4 visits r before l under glue; the order has no effect.
		for _, c := range []*node{n.l, n.r} {
			if c != nil {
				refine(c, hi)
			}
		}
	}
	// Longer entries stay as they are.
}

// RefineLow is bgpq4's -r (sx_radix_node_refineLow): every entry no longer
// than lo becomes an aggregate of its more-specifics from lo to the family's
// full length (or keeps its upper bound if -R made it an aggregate already),
// and the entries it covers, up to lo long, are dropped.
func (t *Tree) RefineLow(lo int) {
	if t.head != nil {
		t.refineLow(t.head, lo)
	}
}

func (t *Tree) refineLow(n *node, lo int) {
	glueUpTo := func(m *node) {
		if m.prefix.Bits() <= lo {
			m.glue = true
		}
	}
	switch {
	case !n.glue && n.prefix.Bits() <= lo:
		if !n.aggregate {
			n.aggregate = true
			n.lo, n.hi = lo, t.full()
		} else {
			n.lo = lo
		}
		for _, c := range []*node{n.l, n.r} {
			if c != nil {
				foreach(c, glueUpTo)
				t.refineLow(c, lo)
			}
		}
	case n.glue:
		for _, c := range []*node{n.l, n.r} {
			if c != nil {
				t.refineLow(c, lo)
			}
		}
	}
}
