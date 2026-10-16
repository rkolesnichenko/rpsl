package types

import "slices"

// setOp is one of the three set operations a merge performs.
type setOp uint8

const (
	opUnion setOp = iota
	opIntersect
	opMinus
)

func (op setOp) apply(a, b lenMask) lenMask {
	switch op {
	case opUnion:
		return a.or(b)
	case opIntersect:
		return a.and(b)
	}
	return a.andNot(b)
}

// Union returns the prefixes in s or t.
func (s PrefixSpace) Union(t PrefixSpace) PrefixSpace { return combine(opUnion, s, t) }

// Intersect returns the prefixes in both s and t.
func (s PrefixSpace) Intersect(t PrefixSpace) PrefixSpace { return combine(opIntersect, s, t) }

// Minus returns the prefixes in s and not in t.
func (s PrefixSpace) Minus(t PrefixSpace) PrefixSpace { return combine(opMinus, s, t) }

// Subset reports whether every prefix in s is in t, as s.Minus(t).IsEmpty()
// would, but stops at the first prefix of s that t lacks and allocates
// nothing.
func (s PrefixSpace) Subset(t PrefixSpace) bool {
	return subsetNode(s.v4, t.v4, 0, 32, lenMask{}, lenMask{}) &&
		subsetNode(s.v6, t.v6, 0, 128, lenMask{}, lenMask{})
}

// SubsetOfUnion reports whether every prefix in s is in at least one of
// ts: s.Subset of their union, without building it. It walks s's trie
// beside all of ts', stops at the first prefix of s none of them holds, and
// allocates only a work list of trie nodes.
func (s PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool {
	if len(ts) == 1 {
		return s.Subset(ts[0])
	}
	var work []*spaceNode
	for _, t := range ts {
		if t.v4 != nil {
			work = append(work, t.v4)
		}
	}
	if !subsetUnion(s.v4, work, 0, 32, lenMask{}, lenMask{}, &work) {
		return false
	}
	work = work[:0]
	for _, t := range ts {
		if t.v6 != nil {
			work = append(work, t.v6)
		}
	}
	return subsetUnion(s.v6, work, 0, 128, lenMask{}, lenMask{}, &work)
}

// subsetNode reports whether merge(opMinus, a, b, d, width, inA, inB) would
// be empty, without building it: false at the first prefix a holds and b
// does not. A canonical node is never empty, so a node of a with nothing
// inherited against nothing at all is a difference.
func subsetNode(a, b *spaceNode, d, width int, inA, inB lenMask) bool {
	if inA.isZero() {
		if a == nil || a == b {
			return true
		}
		if b == nil && inB.isZero() {
			return false
		}
	}
	fa, fb := inA, inB
	if a != nil {
		fa = fa.or(a.mask)
	}
	if b != nil {
		fb = fb.or(b.mask)
	}
	fa, fb = fa.and(geMask[d]), fb.and(geMask[d])
	if covered(a, fa, fb, d, width) {
		return true
	}
	if leaf(a) && leaf(b) {
		return fa.andNot(fb).isZero()
	}
	if !fa.andNot(fb).and(one(d)).isZero() {
		return false
	}
	if d < width {
		ia, ib := fa.and(geMask[d+1]), fb.and(geMask[d+1])
		return subsetNode(kid(a, 0), kid(b, 0), d+1, width, ia, ib) &&
			subsetNode(kid(a, 1), kid(b, 1), d+1, width, ia, ib)
	}
	return true
}

// covered reports whether the other side already holds every prefix a
// can below this node: every length from d to width, or, a being a leaf
// (so the same lengths at every depth below), every length a holds. The
// walks stop there instead of visiting the other side's subtrees.
func covered(a *spaceNode, fa, fb lenMask, d, width int) bool {
	return window(d, width).andNot(fb).isZero() || leaf(a) && fa.andNot(fb).isZero()
}

// subsetUnion is subsetNode against the union of bs, nodes at depth d. bs
// is a window of *work; each child's nodes are appended after it for the
// child's call and dropped on return, so the walk needs one list whatever
// its depth.
func subsetUnion(a *spaceNode, bs []*spaceNode, d, width int, inA, inB lenMask, work *[]*spaceNode) bool {
	if inA.isZero() {
		if a == nil || slices.Contains(bs, a) {
			return true
		}
		if len(bs) == 0 && inB.isZero() {
			return false
		}
	}
	fa, fb := inA, inB
	if a != nil {
		fa = fa.or(a.mask)
	}
	leaves := leaf(a)
	for _, b := range bs {
		fb = fb.or(b.mask)
		leaves = leaves && leaf(b)
	}
	fa, fb = fa.and(geMask[d]), fb.and(geMask[d])
	if covered(a, fa, fb, d, width) {
		return true
	}
	if leaves {
		return fa.andNot(fb).isZero()
	}
	if !fa.andNot(fb).and(one(d)).isZero() {
		return false
	}
	if d < width {
		ia, ib := fa.and(geMask[d+1]), fb.and(geMask[d+1])
		for i := range 2 {
			start := len(*work)
			for _, b := range bs {
				if k := b.child[i]; k != nil {
					*work = append(*work, k)
				}
			}
			end := len(*work)
			ok := subsetUnion(kid(a, i), (*work)[start:end:end], d+1, width, ia, ib, work)
			*work = (*work)[:start]
			if !ok {
				return false
			}
		}
	}
	return true
}

func combine(op setOp, s, t PrefixSpace) PrefixSpace {
	return PrefixSpace{
		v4: merge(op, s.v4, t.v4, 0, 32, lenMask{}, lenMask{}),
		v6: merge(op, s.v6, t.v6, 0, 128, lenMask{}, lenMask{}),
	}
}

// leaf reports whether n has no children (a nil node has none).
func leaf(n *spaceNode) bool { return n == nil || n.child[0] == nil && n.child[1] == nil }

// kid returns n's child i, or nil.
func kid(n *spaceNode, i int) *spaceNode {
	if n == nil {
		return nil
	}
	return n.child[i]
}

// merge applies op to a and b, nodes at depth d of a family width bits
// wide. inA and inB are the lengths an ancestor of a, or of b, holds: every
// prefix of such a length under this node is in that operand. The result is
// canonical (see spaceNode) given canonical operands.
func merge(op setOp, a, b *spaceNode, d, width int, inA, inB lenMask) *spaceNode {
	// Shortcuts that return an operand's subtree as it is: valid only where
	// nothing is inherited, so the subtree means the same here as there.
	if inA.isZero() && inB.isZero() {
		switch {
		case op == opUnion && a == nil:
			return b
		case op == opUnion && b == nil:
			return a
		case op == opIntersect && (a == nil || b == nil):
			return nil
		case op == opMinus && a == nil:
			return nil
		case op == opMinus && b == nil:
			return a
		}
	}
	fa, fb := inA, inB
	if a != nil {
		fa = fa.or(a.mask)
	}
	if b != nil {
		fb = fb.or(b.mask)
	}
	fa, fb = fa.and(geMask[d]), fb.and(geMask[d])
	if leaf(a) && leaf(b) {
		// Below here both operands are the same at every depth: the result
		// is too, and this node holds it whole.
		return mk(op.apply(fa, fb), [2]*spaceNode{})
	}
	m := op.apply(fa, fb).and(one(d)) // this node's own prefix, decided exactly
	var c [2]*spaceNode
	if d < width {
		ia, ib := fa.and(geMask[d+1]), fb.and(geMask[d+1])
		c[0] = merge(op, kid(a, 0), kid(b, 0), d+1, width, ia, ib)
		c[1] = merge(op, kid(a, 1), kid(b, 1), d+1, width, ia, ib)
		m, c = lift(m, c, d)
	}
	return mk(m, c)
}
