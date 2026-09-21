package types

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"strconv"
	"strings"
)

// RangeOp is the prefix-range operator applied after a '^'.
type RangeOp uint8

const (
	RangeExact  RangeOp = iota // no operator
	RangeMinus                 // ^-  more-specifics, excluding the prefix itself
	RangePlus                  // ^+  more-specifics, including the prefix itself
	RangeLength                // ^n  prefixes of exact length n
	RangeRange                 // ^n-m prefixes with length in [n, m]
)

// ErrTooManyPrefixes is returned by Materialize when enumeration would exceed
// the supplied cap. The cap is enforced during enumeration, never after.
var ErrTooManyPrefixes = errors.New("rpsl/types: prefix range exceeds cap")

// PrefixRange is a prefix with an optional range operator, e.g. "192.0.2.0/24",
// "192.0.2.0/24^+", "^-", "^24", "^24-28". Lo/Hi hold the resolved length window
// for every operator. It is comparable.
type PrefixRange struct {
	Prefix netip.Prefix
	Op     RangeOp
	Lo, Hi uint8
}

// ParsePrefixRange parses a prefix optionally followed by a '^' range operator.
func ParsePrefixRange(s string) (PrefixRange, error) {
	t := strings.TrimSpace(s)
	pfxStr, opStr, hasOp := strings.Cut(t, "^")
	pfx, err := netip.ParsePrefix(strings.TrimSpace(pfxStr))
	if err != nil {
		return PrefixRange{}, fmt.Errorf("rpsl/types: invalid prefix range %q: %w", s, err)
	}
	bits, maxBits := pfx.Bits(), pfx.Addr().BitLen()
	if !hasOp {
		return PrefixRange{Prefix: pfx, Op: RangeExact, Lo: uint8(bits), Hi: uint8(bits)}, nil
	}
	op, err := ParseRangeOperator(opStr)
	if err != nil {
		return PrefixRange{}, err
	}
	switch op.Op {
	case RangePlus:
		return PrefixRange{Prefix: pfx, Op: RangePlus, Lo: uint8(bits), Hi: uint8(maxBits)}, nil
	case RangeMinus:
		return PrefixRange{Prefix: pfx, Op: RangeMinus, Lo: uint8(bits + 1), Hi: uint8(maxBits)}, nil
	}
	if int(op.N) < bits || int(op.M) > maxBits {
		return PrefixRange{}, fmt.Errorf("rpsl/types: invalid range ^%s for /%d prefix", opStr, bits)
	}
	return PrefixRange{Prefix: pfx, Op: op.Op, Lo: op.N, Hi: op.M}, nil
}

// String renders the range back to its canonical text form.
func (r PrefixRange) String() string {
	p := r.Prefix.String()
	switch r.Op {
	case RangePlus:
		return p + "^+"
	case RangeMinus:
		return p + "^-"
	case RangeLength:
		return p + "^" + strconv.Itoa(int(r.Lo))
	case RangeRange:
		return p + "^" + strconv.Itoa(int(r.Lo)) + "-" + strconv.Itoa(int(r.Hi))
	default:
		return p
	}
}

// Materialize enumerates the concrete prefixes the range denotes. The cap is
// checked before anything is allocated: if the count would exceed maxPrefixes
// it returns ErrTooManyPrefixes.
//
// To enforce one budget across many (possibly overlapping) ranges, stream them
// through All into a deduplicating set and stop at the cap, as
// resolve.Expander.ExpandPrefixes does, instead of calling Materialize per range.
func (r PrefixRange) Materialize(maxPrefixes int) ([]netip.Prefix, error) {
	lo, hi, ok := r.window()
	if !ok {
		return nil, nil // invalid prefix, or e.g. ^- on a host prefix: nothing
	}
	total := 0
	for L := lo; L <= hi; L++ {
		w := L - r.Prefix.Bits()
		if w >= 31 { // 2^31 prefixes dwarfs any sane cap
			return nil, ErrTooManyPrefixes
		}
		if total += 1 << uint(w); total > maxPrefixes {
			return nil, ErrTooManyPrefixes
		}
	}
	out := make([]netip.Prefix, 0, total)
	for p := range r.All() {
		out = append(out, p)
	}
	return out, nil
}

// All yields the concrete prefixes the range denotes, shortest first and in
// address order within each length. It is lazy, so a consumer can enforce its
// own budget and stop early even on ranges like ::/0^+ that cannot be
// enumerated in full. The zero PrefixRange yields nothing.
func (r PrefixRange) All() iter.Seq[netip.Prefix] {
	return func(yield func(netip.Prefix) bool) {
		lo, hi, ok := r.window()
		if !ok {
			return
		}
		base := r.Prefix.Masked().Addr()
		baseBits := r.Prefix.Bits()
		for L := lo; L <= hi; L++ {
			b := base.AsSlice()
			for {
				a, _ := netip.AddrFromSlice(b)
				if !yield(netip.PrefixFrom(a, L)) {
					return
				}
				if !increment(b, baseBits, L) {
					break
				}
			}
		}
	}
}

// window returns the prefix-length window [lo, hi] the range covers, clamped to
// the prefix and its family, and false when it is empty or the range is invalid.
func (r PrefixRange) window() (lo, hi int, ok bool) {
	if !r.Prefix.IsValid() {
		return 0, 0, false
	}
	lo = max(int(r.Lo), r.Prefix.Bits())
	hi = min(int(r.Hi), r.Prefix.Addr().BitLen())
	return lo, hi, lo <= hi
}

// increment adds one to the bit field [start, end) of the big-endian address b,
// reporting false when the field wraps back to zero (enumeration is complete).
func increment(b []byte, start, end int) bool {
	for pos := end - 1; pos >= start; pos-- {
		mask := byte(1 << (7 - pos%8))
		if b[pos/8]&mask == 0 {
			b[pos/8] |= mask
			return true
		}
		b[pos/8] &^= mask
	}
	return false
}
