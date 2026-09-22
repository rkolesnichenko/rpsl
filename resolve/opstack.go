package resolve

import "github.com/rkolesnichenko/rpsl/types"

// deleted marks, in an opStack table, an inner lower bound whose ranges the
// stack deletes (RFC 2622 §5.2: m < max(n,k)).
const deleted = 0xFF

// opStack is a stack of range operators met along a path of set members
// ("RS-A^+" listing "RS-B^24"), identified by what it does rather than how it is
// spelled. Applying operators to a range depends only on the range's lower bound
// k and its address family: the result's lower bound is a function of k, and
// its upper bound is set by the outermost operator. So a stack is the table of
// that function for each family, and equivalent stacks (^+^+ and ^+; ^-^+ and
// ^-) are equal values. Evaluation keys its states on them, so the states are
// finite and cycles through operators reach a fixpoint instead of repeating.
//
// The zero opStack is the empty stack, which leaves ranges unchanged.
type opStack struct {
	set      bool // holds at least one operator
	hi4, hi6 uint8
	lo4      [32 + 1]uint8  // result lower bound for inner lower bound k, or deleted
	lo6      [128 + 1]uint8 // likewise for IPv6
}

// family returns the stack's table and upper bound for one address family.
func (s *opStack) family(v6 bool) (lo []uint8, hi *uint8, maxBits int) {
	if v6 {
		return s.lo6[:], &s.hi6, 128
	}
	return s.lo4[:], &s.hi4, 32
}

// push returns the stack with o added innermost: the result applies o to a
// range first, then s. The zero operator leaves the stack unchanged.
func (s opStack) push(o types.RangeOperator) opStack {
	if o.IsZero() {
		return s
	}
	c := opStack{set: true}
	for _, v6 := range []bool{false, true} {
		plo, phi, maxBits := s.family(v6)
		clo, chi, _ := c.family(v6)
		for k := 0; k <= maxBits; k++ {
			lo, hi := int(o.N), int(o.M)
			switch o.Op {
			case types.RangePlus:
				lo, hi = k, maxBits
			case types.RangeMinus:
				lo, hi = k+1, maxBits
			}
			lo, hi = max(lo, k), min(hi, maxBits)
			switch {
			case lo > hi:
				clo[k] = deleted
			case s.set:
				clo[k] = plo[lo] // s applied to o's result, which s reads by its lower bound
			default:
				clo[k] = uint8(lo)
			}
			if s.set {
				*chi = *phi
			} else {
				*chi = uint8(hi) // o is outermost: its upper bound is the result's
			}
		}
	}
	return c
}

// apply applies the stack to r, reporting false when the operators delete it.
// The result is canonical.
func (s *opStack) apply(r types.PrefixRange) (types.PrefixRange, bool) {
	if r.IsEmpty() {
		return types.PrefixRange{}, false
	}
	if !s.set {
		return r, true
	}
	lo, hi, maxBits := s.family(r.Prefix().Addr().Is6())
	k := r.Lo()
	if k > maxBits || lo[k] == deleted {
		return types.PrefixRange{}, false
	}
	return types.NewPrefixRange(r.Prefix(), int(lo[k]), int(*hi))
}
