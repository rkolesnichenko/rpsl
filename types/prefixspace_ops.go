package types

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

// Subset reports whether every prefix in s is in t: s.Minus(t).IsEmpty().
func (s PrefixSpace) Subset(t PrefixSpace) bool { return s.Minus(t).IsEmpty() }

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
