package types

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
)

// LastAddr returns the last address of p: p's network with every host bit
// set, so p need not be masked. An IPv4-mapped IPv6 prefix is IPv6. It
// returns the zero Addr for an invalid p.
func LastAddr(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}
	a := p.Addr()
	return u128Of(a).or(lowOnes(a.BitLen() - p.Bits())).addr(a.Is4())
}

// AddrRangePrefixes returns the fewest prefixes that together hold exactly the
// addresses lo to hi, inclusive, in address order: an inetnum's "lo - hi" as
// prefixes ("192.0.0.0 - 192.0.4.255" is 192.0.0.0/22 and 192.0.4.0/24). lo
// and hi must be valid, zoneless addresses of one family, an IPv4-mapped IPv6
// address being IPv6, with lo no greater than hi; anything else is an error.
// A range is at most 2×bits-2 prefixes: 62 for IPv4, 254 for IPv6.
func AddrRangePrefixes(lo, hi netip.Addr) ([]netip.Prefix, error) {
	switch {
	case !lo.IsValid() || !hi.IsValid():
		return nil, errors.New("rpsl/types: address range with an invalid address")
	case lo.Zone() != "" || hi.Zone() != "":
		return nil, fmt.Errorf("rpsl/types: address range %v - %v has a zone", lo, hi)
	case lo.BitLen() != hi.BitLen():
		return nil, fmt.Errorf("rpsl/types: address range %v - %v mixes address families", lo, hi)
	case lo.Compare(hi) > 0:
		return nil, fmt.Errorf("rpsl/types: address range starts at %v, after its end %v", lo, hi)
	}
	v4, width := lo.Is4(), lo.BitLen()
	cur, end := u128Of(lo), u128Of(hi)
	var out []netip.Prefix
	for {
		// The largest block starting at cur that ends at or before end: cur's
		// alignment bounds it, and so does the count of addresses left (which
		// keeps it within width, even at cur zero).
		k := cur.trailingZeros()
		left := end.sub(cur) // addresses left, less one
		if fit := left.bitLen(); left == lowOnes(fit) {
			k = min(k, fit)
		} else {
			k = min(k, fit-1)
		}
		out = append(out, netip.PrefixFrom(cur.addr(v4), width-k))
		last := cur.or(lowOnes(k))
		if last == end {
			return out, nil
		}
		cur = last.add1()
	}
}

// u128 is an address as an unsigned 128-bit number, IPv4 in its low 32 bits.
type u128 struct{ hi, lo uint64 }

func u128Of(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{lo: uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])}
	}
	b := a.As16()
	var u u128
	for i := 0; i < 8; i++ {
		u.hi = u.hi<<8 | uint64(b[i])
		u.lo = u.lo<<8 | uint64(b[8+i])
	}
	return u
}

func (u u128) addr(v4 bool) netip.Addr {
	if v4 {
		return netip.AddrFrom4([4]byte{byte(u.lo >> 24), byte(u.lo >> 16), byte(u.lo >> 8), byte(u.lo)})
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(u.hi >> (8 * i))
		b[15-i] = byte(u.lo >> (8 * i))
	}
	return netip.AddrFrom16(b)
}

// lowOnes is the number whose low n bits are set (0 <= n <= 128).
func lowOnes(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n < 64:
		return u128{lo: 1<<n - 1}
	case n == 64:
		return u128{lo: ^uint64(0)}
	default:
		return u128{hi: 1<<(n-64) - 1, lo: ^uint64(0)}
	}
}

func (u u128) or(v u128) u128 { return u128{u.hi | v.hi, u.lo | v.lo} }

func (u u128) sub(v u128) u128 {
	lo, borrow := bits.Sub64(u.lo, v.lo, 0)
	hi, _ := bits.Sub64(u.hi, v.hi, borrow)
	return u128{hi, lo}
}

func (u u128) add1() u128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return u128{u.hi + carry, lo}
}

// trailingZeros is the count of low zero bits, 128 for zero.
func (u u128) trailingZeros() int {
	if u.lo != 0 {
		return bits.TrailingZeros64(u.lo)
	}
	return 64 + bits.TrailingZeros64(u.hi)
}

// bitLen is the count of bits needed to write u, 0 for zero.
func (u u128) bitLen() int {
	if u.hi != 0 {
		return 64 + bits.Len64(u.hi)
	}
	return bits.Len64(u.lo)
}
