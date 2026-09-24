package object

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainReverseRange(t *testing.T) {
	for _, c := range []struct{ name, lo, hi string }{
		{"2.0.192.in-addr.arpa", "192.0.2.0", "192.0.2.255"},
		{"2.0.192.IN-ADDR.ARPA.", "192.0.2.0", "192.0.2.255"},
		{"192.in-addr.arpa", "192.0.0.0", "192.255.255.255"},
		{"1.2.0.192.in-addr.arpa", "192.0.2.1", "192.0.2.1"},
		{"0-127.2.0.192.in-addr.arpa", "192.0.2.0", "192.0.2.127"}, // RIPE's range form
		{"8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"1.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8:1000::", "2001:db8:1fff:ffff:ffff:ffff:ffff:ffff"},
	} {
		lo, hi, ok := Domain{Name: c.name}.ReverseRange()
		if !ok || lo.String() != c.lo || hi.String() != c.hi {
			t.Errorf("%s: %s - %s, %v; want %s - %s", c.name, lo, hi, ok, c.lo, c.hi)
		}
	}
	for _, name := range []string{
		"", "example.com", "4.4.e164.arpa", "in-addr.arpa", "256.0.192.in-addr.arpa",
		"1.2.3.4.5.in-addr.arpa", "2.0.192.in-addr", "x.0.192.in-addr.arpa",
		"128-127.2.0.192.in-addr.arpa", "0-127.0.192.in-addr.arpa", // a range needs all four octets
		"g.8.b.d.0.1.0.0.2.ip6.arpa", "ab.8.b.d.0.1.0.0.2.ip6.arpa", "ip6.arpa",
		"01.0.192.in-addr.arpa",
	} {
		if lo, hi, ok := (Domain{Name: name}).ReverseRange(); ok {
			t.Errorf("%q: %s - %s, want not a reverse zone", name, lo, hi)
		}
	}
}

// A reverse zone written for a prefix on an octet or nibble boundary reads
// back as that prefix.
func TestDomainReverseRangeRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 1000; i++ {
		var p netip.Prefix
		var labels []string
		if r.IntN(2) == 0 {
			var a [4]byte
			for j := range a {
				a[j] = byte(r.IntN(256))
			}
			n := 1 + r.IntN(4)
			p = netip.PrefixFrom(netip.AddrFrom4(a), 8*n).Masked()
			for j := n - 1; j >= 0; j-- {
				labels = append(labels, fmt.Sprint(p.Addr().As4()[j]))
			}
			labels = append(labels, "in-addr", "arpa")
		} else {
			var a [16]byte
			for j := range a {
				a[j] = byte(r.IntN(256))
			}
			n := 1 + r.IntN(32)
			p = netip.PrefixFrom(netip.AddrFrom16(a), 4*n).Masked()
			hex := fmt.Sprintf("%032x", p.Addr().As16())
			for j := n - 1; j >= 0; j-- {
				labels = append(labels, hex[j:j+1])
			}
			labels = append(labels, "ip6", "arpa")
		}
		name := strings.Join(labels, ".")
		lo, hi, ok := Domain{Name: name}.ReverseRange()
		want := netipRangeOf(p)
		if !ok || lo != want[0] || hi != want[1] {
			t.Fatalf("%s (%s): %s - %s, %v", name, p, lo, hi, ok)
		}
	}
}

func netipRangeOf(p netip.Prefix) [2]netip.Addr {
	a := p.Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	hi, _ := netip.AddrFromSlice(a)
	return [2]netip.Addr{p.Addr(), hi}
}
