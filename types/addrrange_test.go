package types

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestLastAddr(t *testing.T) {
	for _, c := range []struct{ p, want string }{
		{"192.0.2.0/24", "192.0.2.255"},
		{"192.0.2.77/24", "192.0.2.255"}, // host bits set: the network's last
		{"192.0.2.7/32", "192.0.2.7"},
		{"0.0.0.0/0", "255.255.255.255"},
		{"10.0.0.0/7", "11.255.255.255"},
		{"2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::1/128", "2001:db8::1"},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::ffff:10.0.0.0/104", "::ffff:10.255.255.255"}, // IPv4-mapped is IPv6
		{"2001:db8:0:0:8000::/65", "2001:db8::ffff:ffff:ffff:ffff"},
	} {
		if got := LastAddr(netip.MustParsePrefix(c.p)); got != netip.MustParseAddr(c.want) {
			t.Errorf("LastAddr(%s) = %v, want %s", c.p, got, c.want)
		}
	}
	if got := LastAddr(netip.Prefix{}); got.IsValid() {
		t.Errorf("LastAddr(invalid) = %v, want the zero Addr", got)
	}
	// Every length, against arithmetic: the network plus 2^(bits-len) - 1.
	for _, base := range []string{"0.0.0.0", "203.0.113.0", "255.255.255.255", "::", "2001:db8::", "ffff::"} {
		a := netip.MustParseAddr(base)
		for l := 0; l <= a.BitLen(); l++ {
			p := netip.PrefixFrom(a, l).Masked()
			want := new(big.Int).SetBytes(p.Addr().AsSlice())
			want.Add(want, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(a.BitLen()-l)), big.NewInt(1)))
			if got := new(big.Int).SetBytes(LastAddr(p).AsSlice()); got.Cmp(want) != 0 {
				t.Errorf("LastAddr(%s) = %v", p, LastAddr(p))
			}
		}
	}
}

func TestAddrRangePrefixes(t *testing.T) {
	for _, c := range []struct {
		lo, hi string
		want   string // fmt.Sprint of the prefixes, or "error"
	}{
		{"192.0.2.0", "192.0.2.255", "[192.0.2.0/24]"},
		{"192.0.2.7", "192.0.2.7", "[192.0.2.7/32]"},
		{"10.0.0.1", "10.0.0.6", "[10.0.0.1/32 10.0.0.2/31 10.0.0.4/31 10.0.0.6/32]"},
		{"192.0.0.0", "192.0.4.255", "[192.0.0.0/22 192.0.4.0/24]"},
		{"0.0.0.0", "255.255.255.255", "[0.0.0.0/0]"},
		{"0.0.0.1", "255.255.255.255", "[0.0.0.1/32 0.0.0.2/31 0.0.0.4/30 0.0.0.8/29 0.0.0.16/28 0.0.0.32/27 0.0.0.64/26 0.0.0.128/25 0.0.1.0/24 0.0.2.0/23 0.0.4.0/22 0.0.8.0/21 0.0.16.0/20 0.0.32.0/19 0.0.64.0/18 0.0.128.0/17 0.1.0.0/16 0.2.0.0/15 0.4.0.0/14 0.8.0.0/13 0.16.0.0/12 0.32.0.0/11 0.64.0.0/10 0.128.0.0/9 1.0.0.0/8 2.0.0.0/7 4.0.0.0/6 8.0.0.0/5 16.0.0.0/4 32.0.0.0/3 64.0.0.0/2 128.0.0.0/1]"},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "[::/0]"},
		{"2001:db8::1", "2001:db8::2", "[2001:db8::1/128 2001:db8::2/128]"},
		{"::ffff:ffff:ffff:ffff", "0:0:0:1::", "[::ffff:ffff:ffff:ffff/128 0:0:0:1::/128]"}, // across the 64-bit halves
		{"2001:db8::", "2001:db8:0:1:ffff:ffff:ffff:ffff", "[2001:db8::/63]"},
		{"192.0.2.9", "192.0.2.1", "error"},
		{"192.0.2.1", "2001:db8::1", "error"},
		{"10.0.0.1", "::ffff:10.0.0.2", "error"}, // IPv4-mapped is IPv6
		{"fe80::1%eth0", "fe80::2%eth0", "error"},
		{"fe80::1%eth0", "fe80::2", "error"},
		{"fe80::1", "fe80::2%eth0", "error"},
		{"::ffff:10.0.0.0", "::ffff:10.0.0.255", "[::ffff:10.0.0.0/120]"}, // IPv6 out: never unmapped
	} {
		got, err := AddrRangePrefixes(netip.MustParseAddr(c.lo), netip.MustParseAddr(c.hi))
		s := fmt.Sprint(got)
		if err != nil {
			s = "error"
		}
		if s != c.want {
			t.Errorf("AddrRangePrefixes(%s, %s) = %v, %v; want %s", c.lo, c.hi, got, err, c.want)
		}
	}
	if _, err := AddrRangePrefixes(netip.Addr{}, netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Error("AddrRangePrefixes(invalid, …): want an error")
	}
	// The most a range takes: all but the first and the last address.
	for _, c := range []struct {
		lo, hi string
		n      int
	}{
		{"0.0.0.1", "255.255.255.254", 62},
		{"::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 254},
	} {
		if ps, err := AddrRangePrefixes(netip.MustParseAddr(c.lo), netip.MustParseAddr(c.hi)); err != nil || len(ps) != c.n {
			t.Errorf("AddrRangePrefixes(%s, %s): %d prefixes, %v; want %d", c.lo, c.hi, len(ps), err, c.n)
		}
	}
}

// The prefixes cover lo - hi exactly, in order, and are the fewest: no
// prefix's parent lies inside the range, so no two could be one.
func TestAddrRangePrefixesExactAndMinimal(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		var lo, hi netip.Addr
		if i%2 == 0 {
			a, b := r.Uint32(), r.Uint32()
			if i%4 == 0 { // short ranges, where the alignment cases are
				b = a + r.Uint32N(600)
				if b < a {
					b = a
				}
			}
			if a > b {
				a, b = b, a
			}
			lo, hi = addr4(a), addr4(b)
		} else {
			var x, y [16]byte
			for j := range x {
				x[j], y[j] = byte(r.UintN(256)), byte(r.UintN(256))
			}
			if i%4 == 1 {
				y = x
				y[15] += byte(r.UintN(200))
				y[14] += byte(r.UintN(3))
			}
			lo, hi = netip.AddrFrom16(x), netip.AddrFrom16(y)
			if lo.Compare(hi) > 0 {
				lo, hi = hi, lo
			}
		}
		ps, err := AddrRangePrefixes(lo, hi)
		if err != nil {
			t.Fatalf("AddrRangePrefixes(%v, %v): %v", lo, hi, err)
		}
		next := lo
		for j, p := range ps {
			if p != p.Masked() || p.Addr() != next {
				t.Fatalf("%v - %v: prefix %d %v does not start at %v", lo, hi, j, p, next)
			}
			if p.Bits() > 0 {
				parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
				if parent.Addr().Compare(lo) >= 0 && LastAddr(parent).Compare(hi) <= 0 {
					t.Fatalf("%v - %v: %v's parent %v lies in the range: not the fewest", lo, hi, p, parent)
				}
			}
			next = LastAddr(p).Next()
		}
		if last := LastAddr(ps[len(ps)-1]); last != hi {
			t.Fatalf("%v - %v: the prefixes end at %v", lo, hi, last)
		}
	}
}

func addr4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
