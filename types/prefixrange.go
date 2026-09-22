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

// PrefixRange is a prefix with a window of more-specific lengths, written with
// an optional range operator: "192.0.2.0/24", "192.0.2.0/24^+", "^-", "^24",
// "^24-28" (RFC 2622 §2). It is an opaque, canonical value: the prefix has no
// host bits and the window is stored as lengths, so equivalent spellings
// ("/8^24-24" and "/8^24") are == and can be used as map keys. Build one with
// ParsePrefixRange or NewPrefixRange. The zero PrefixRange is no range.
type PrefixRange struct {
	prefix netip.Prefix
	lo, hi uint8
}

// NewPrefixRange returns the range of prefixes under p with lengths lo..hi,
// clamped to p's length and its family's. Host bits in p are cleared. ok is
// false when p is invalid or the window is empty.
func NewPrefixRange(p netip.Prefix, lo, hi int) (_ PrefixRange, ok bool) {
	if !p.IsValid() {
		return PrefixRange{}, false
	}
	p = p.Masked()
	lo, hi = max(lo, p.Bits()), min(hi, p.Addr().BitLen())
	if lo > hi {
		return PrefixRange{}, false
	}
	return PrefixRange{prefix: p, lo: uint8(lo), hi: uint8(hi)}, true
}

// Prefix returns the range's base prefix.
func (r PrefixRange) Prefix() netip.Prefix { return r.prefix }

// Lo returns the shortest prefix length in the range.
func (r PrefixRange) Lo() int { return int(r.lo) }

// Hi returns the longest prefix length in the range.
func (r PrefixRange) Hi() int { return int(r.hi) }

// IsZero reports whether r is the zero PrefixRange.
func (r PrefixRange) IsZero() bool { return !r.prefix.IsValid() }

// IsEmpty reports whether r denotes no prefixes: the zero PrefixRange, or a
// parsed range such as "192.0.2.1/32^-" (a host route has no more-specifics).
func (r PrefixRange) IsEmpty() bool { return r.IsZero() || r.lo > r.hi }

// Op returns the most specific operator that spells r's window: RangeExact for
// the prefix alone, RangePlus for /n^n-max, RangeMinus for /n^(n+1)-max,
// RangeLength for a single length, otherwise RangeRange.
func (r PrefixRange) Op() RangeOp {
	bits, maxBits := r.prefix.Bits(), r.prefix.Addr().BitLen()
	lo, hi := int(r.lo), int(r.hi)
	switch {
	case lo == bits && hi == bits:
		return RangeExact
	case lo == bits && hi == maxBits:
		return RangePlus
	case lo == bits+1 && hi == maxBits:
		return RangeMinus
	case lo == hi:
		return RangeLength
	}
	return RangeRange
}

// ParsePrefixRange parses a prefix optionally followed by a '^' range operator.
// Host bits are cleared and the result is canonical, so equivalent spellings
// yield the identical value. A range that denotes no prefixes, such as a host
// route with ^-, is kept (see IsEmpty) and prints as written. Callers that must
// report host bits should check the text themselves.
func ParsePrefixRange(s string) (PrefixRange, error) {
	t := strings.Trim(s, " \t")
	pfxStr, opStr, hasOp := strings.Cut(t, "^")
	pfx, err := netip.ParsePrefix(pfxStr)
	if err != nil {
		return PrefixRange{}, fmt.Errorf("rpsl/types: invalid prefix range %q: %w", s, err)
	}
	pfx = pfx.Masked()
	bits, maxBits := pfx.Bits(), pfx.Addr().BitLen()
	lo, hi := bits, bits
	if hasOp {
		op, err := ParseRangeOperator(opStr)
		if err != nil {
			return PrefixRange{}, err
		}
		switch op.Op {
		case RangePlus:
			hi = maxBits
		case RangeMinus:
			lo, hi = bits+1, maxBits
		default:
			if int(op.N) < bits || int(op.M) > maxBits {
				return PrefixRange{}, fmt.Errorf("rpsl/types: invalid range ^%s for /%d prefix", opStr, bits)
			}
			lo, hi = int(op.N), int(op.M)
		}
	}
	return PrefixRange{prefix: pfx, lo: uint8(lo), hi: uint8(hi)}, nil
}

// String renders the range in canonical text form ("" for the zero range).
func (r PrefixRange) String() string {
	if r.IsZero() {
		return ""
	}
	p := r.prefix.String()
	switch r.Op() {
	case RangePlus:
		return p + "^+"
	case RangeMinus:
		return p + "^-"
	case RangeLength:
		return p + "^" + strconv.Itoa(int(r.lo))
	case RangeRange:
		return p + "^" + strconv.Itoa(int(r.lo)) + "-" + strconv.Itoa(int(r.hi))
	default:
		return p
	}
}

// Contains reports whether r denotes p. Host bits in p are ignored: p is
// compared in its masked form, as every prefix this package stores is.
func (r PrefixRange) Contains(p netip.Prefix) bool {
	if r.IsEmpty() || !p.IsValid() {
		return false
	}
	p = p.Masked()
	if p.Bits() < int(r.lo) || p.Bits() > int(r.hi) {
		return false
	}
	// A length inside the window is still only in range when p sits under the
	// base prefix; Contains reports false across address families.
	return r.prefix.Contains(p.Addr())
}

// Intersect returns the range denoting exactly the prefixes both r and s
// denote, and ok is false when they share none. Two ranges overlap only when
// one base prefix contains the other, in which case the more specific base
// bounds the result and the length windows intersect.
func (r PrefixRange) Intersect(s PrefixRange) (_ PrefixRange, ok bool) {
	if r.IsEmpty() || s.IsEmpty() {
		return PrefixRange{}, false
	}
	base := r.prefix
	if s.prefix.Bits() > base.Bits() {
		base = s.prefix
	}
	// Nested, not merely same-family: the wider prefix must contain the base.
	if !r.prefix.Contains(base.Addr()) || !s.prefix.Contains(base.Addr()) {
		return PrefixRange{}, false
	}
	lo := max(int(r.lo), int(s.lo), base.Bits())
	hi := min(int(r.hi), int(s.hi))
	if lo > hi {
		return PrefixRange{}, false
	}
	return PrefixRange{prefix: base, lo: uint8(lo), hi: uint8(hi)}, true
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
		w := L - r.prefix.Bits()
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
		base := r.prefix.Addr()
		baseBits := r.prefix.Bits()
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

// window returns the prefix-length window [lo, hi] the range covers, and false
// when it is empty.
func (r PrefixRange) window() (lo, hi int, ok bool) {
	return int(r.lo), int(r.hi), !r.IsEmpty()
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
