package types

import (
	"errors"
	"fmt"
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
	pfxStr, opStr := t, ""
	if i := strings.IndexByte(t, '^'); i >= 0 {
		pfxStr, opStr = t[:i], t[i+1:]
	}
	pfx, err := netip.ParsePrefix(strings.TrimSpace(pfxStr))
	if err != nil {
		return PrefixRange{}, fmt.Errorf("rpsl/types: invalid prefix range %q: %w", s, err)
	}
	r := PrefixRange{Prefix: pfx}
	bits, maxBits := pfx.Bits(), pfx.Addr().BitLen()

	switch {
	case opStr == "":
		r.Op, r.Lo, r.Hi = RangeExact, uint8(bits), uint8(bits)
	case opStr == "+":
		r.Op, r.Lo, r.Hi = RangePlus, uint8(bits), uint8(maxBits)
	case opStr == "-":
		r.Op, r.Lo, r.Hi = RangeMinus, uint8(bits+1), uint8(maxBits)
	case strings.IndexByte(opStr, '-') >= 0:
		d := strings.IndexByte(opStr, '-')
		n, err1 := strconv.Atoi(opStr[:d])
		m, err2 := strconv.Atoi(opStr[d+1:])
		if err1 != nil || err2 != nil {
			return PrefixRange{}, fmt.Errorf("rpsl/types: invalid range operator %q", opStr)
		}
		if n < bits || m < n || m > maxBits {
			return PrefixRange{}, fmt.Errorf("rpsl/types: invalid range ^%s for /%d prefix", opStr, bits)
		}
		r.Op, r.Lo, r.Hi = RangeRange, uint8(n), uint8(m)
	default:
		n, err := strconv.Atoi(opStr)
		if err != nil {
			return PrefixRange{}, fmt.Errorf("rpsl/types: invalid range operator %q", opStr)
		}
		if n < bits || n > maxBits {
			return PrefixRange{}, fmt.Errorf("rpsl/types: invalid length ^%d for /%d prefix", n, bits)
		}
		r.Op, r.Lo, r.Hi = RangeLength, uint8(n), uint8(n)
	}
	return r, nil
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
// applied during enumeration: if the count would exceed maxPrefixes it returns
// ErrTooManyPrefixes rather than allocating the whole set.
func (r PrefixRange) Materialize(maxPrefixes int) ([]netip.Prefix, error) {
	base := r.Prefix.Masked()
	addr := base.Addr()
	baseBits, maxBits := base.Bits(), addr.BitLen()

	lo, hi := int(r.Lo), int(r.Hi)
	if lo < baseBits {
		lo = baseBits
	}
	if hi > maxBits {
		hi = maxBits
	}
	if lo > hi { // e.g. ^- on a host prefix: no more-specifics
		return nil, nil
	}

	var out []netip.Prefix
	for L := lo; L <= hi; L++ {
		w := L - baseBits
		if w >= 31 { // 2^31 prefixes dwarfs any sane cap
			return nil, ErrTooManyPrefixes
		}
		count := 1 << uint(w)
		if len(out)+count > maxPrefixes {
			return nil, ErrTooManyPrefixes
		}
		for k := 0; k < count; k++ {
			out = append(out, nthSubPrefix(addr, baseBits, L, k))
		}
	}
	return out, nil
}

// nthSubPrefix returns the k-th length-L sub-prefix of a masked base address.
func nthSubPrefix(base netip.Addr, baseBits, L, k int) netip.Prefix {
	width := L - baseBits
	if base.Is4() {
		b := base.As4()
		setBits(b[:], baseBits, width, k)
		return netip.PrefixFrom(netip.AddrFrom4(b), L)
	}
	b := base.As16()
	setBits(b[:], baseBits, width, k)
	return netip.PrefixFrom(netip.AddrFrom16(b), L)
}

// setBits writes the low `width` bits of k into address bits [start, start+width),
// MSB-first.
func setBits(b []byte, start, width, k int) {
	for i := 0; i < width; i++ {
		if (k>>(width-1-i))&1 == 0 {
			continue
		}
		pos := start + i
		b[pos/8] |= byte(1 << (7 - pos%8))
	}
}
