package types

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RangeOperator is a prefix-range operator detached from any prefix, as it
// follows a set name or AS number in a route-set member ("RS-FOO^+",
// "AS1^24-32"; RFC 2622 §5.2). The zero value is RangeExact: no operator.
// It is comparable.
type RangeOperator struct {
	Op   RangeOp
	N, M uint8 // RangeLength (N == M) and RangeRange (N <= M); zero otherwise
}

// ParseRangeOperator parses the text after a '^': "+", "-", "n", or "n-m",
// where n <= m <= 128 are plain decimal digits (no sign, no whitespace).
func ParseRangeOperator(s string) (RangeOperator, error) {
	switch s {
	case "+":
		return RangeOperator{Op: RangePlus}, nil
	case "-":
		return RangeOperator{Op: RangeMinus}, nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	n, ok := parseBits(lo)
	if !ok {
		return RangeOperator{}, fmt.Errorf("rpsl/types: invalid range operator %q", s)
	}
	if !isRange {
		return RangeOperator{Op: RangeLength, N: n, M: n}, nil
	}
	m, ok := parseBits(hi)
	if !ok || m < n {
		return RangeOperator{}, fmt.Errorf("rpsl/types: invalid range operator %q", s)
	}
	return RangeOperator{Op: RangeRange, N: n, M: m}, nil
}

// parseBits parses a prefix length: one to three ASCII digits, at most 128.
func parseBits(s string) (uint8, bool) {
	if len(s) == 0 || len(s) > 3 {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int(s[i]-'0')
	}
	if v > 128 {
		return 0, false
	}
	return uint8(v), true
}

// IsZero reports whether o is the absent operator.
func (o RangeOperator) IsZero() bool { return o.Op == RangeExact }

// String renders the operator with its leading '^', or "" when absent.
func (o RangeOperator) String() string {
	switch o.Op {
	case RangePlus:
		return "^+"
	case RangeMinus:
		return "^-"
	case RangeLength:
		return "^" + strconv.Itoa(int(o.N))
	case RangeRange:
		return "^" + strconv.Itoa(int(o.N)) + "-" + strconv.Itoa(int(o.M))
	default:
		return ""
	}
}

// Apply composes o (the outer operator) over r (RFC 2622 §5.2): an outer ^n-m
// distributes over an inner ^k-l and becomes ^max(n,k)-m if m >= max(n,k);
// otherwise the prefix is deleted and ok is false. ^+ and ^- resolve against
// r's own prefix length, and m is clamped to the address family's bit length.
// The zero operator returns r unchanged.
func (o RangeOperator) Apply(r PrefixRange) (_ PrefixRange, ok bool) {
	if o.IsZero() {
		return r, true
	}
	bits, maxBits := r.Prefix.Bits(), r.Prefix.Addr().BitLen()
	n, m := int(o.N), int(o.M)
	switch o.Op {
	case RangePlus:
		n, m = bits, maxBits
	case RangeMinus:
		n, m = bits+1, maxBits
	}
	m = min(m, maxBits)
	lo := max(n, int(r.Lo))
	if lo > m {
		return PrefixRange{}, false
	}
	return normalizedRange(r.Prefix, lo, m), true
}

// normalizedRange builds the PrefixRange covering lengths [lo, hi] of p, using
// the most specific operator spelling that denotes that window.
func normalizedRange(p netip.Prefix, lo, hi int) PrefixRange {
	bits, maxBits := p.Bits(), p.Addr().BitLen()
	r := PrefixRange{Prefix: p, Lo: uint8(lo), Hi: uint8(hi)}
	switch {
	case lo == bits && hi == bits:
		r.Op = RangeExact
	case lo == bits && hi == maxBits:
		r.Op = RangePlus
	case lo == bits+1 && hi == maxBits:
		r.Op = RangeMinus
	case lo == hi:
		r.Op = RangeLength
	default:
		r.Op = RangeRange
	}
	return r
}
