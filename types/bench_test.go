package types

import (
	"net/netip"
	"testing"
)

// An inetnum's range as prefixes: aligned (one), unaligned v4, and v6.
func BenchmarkAddrRangePrefixes(b *testing.B) {
	in := [][2]netip.Addr{
		{netip.MustParseAddr("193.0.0.0"), netip.MustParseAddr("193.0.7.255")},
		{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.9.254")},
		{netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8:0:2:ffff:ffff:ffff:fffe")},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := in[i%len(in)]
		if _, err := AddrRangePrefixes(r[0], r[1]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePrefixRange(b *testing.B) {
	in := []string{"192.0.2.0/24^+", "10.0.0.0/8^16-24", "2001:db8::/32^48", "192.0.2.0/24", "2001:db8::/32^-"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParsePrefixRange(in[i%len(in)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSetName(b *testing.B) {
	in := []string{"AS-FOO", "as-foo", "AS1:AS-CUSTOMERS:AS2", "RS-BAR", "AS65000:RS-EXAMPLE-V6"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSetName(in[i%len(in)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRangeOperatorApply(b *testing.B) {
	var ops []RangeOperator
	for _, s := range []string{"+", "-", "24", "16-24"} { // written without the "^"
		op, err := ParseRangeOperator(s)
		if err != nil {
			b.Fatal(err)
		}
		ops = append(ops, op)
	}
	var ranges []PrefixRange
	for _, s := range []string{"10.0.0.0/8", "192.0.2.0/24^+", "2001:db8::/32^40-48"} {
		r, err := ParsePrefixRange(s)
		if err != nil {
			b.Fatal(err)
		}
		ranges = append(ranges, r)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ops[i%len(ops)].Apply(ranges[i%len(ranges)])
	}
}

// BenchmarkPrefixRangeAll enumerates the 65,280 prefixes of 10.0.0.0/8^16-23.
func BenchmarkPrefixRangeAll(b *testing.B) {
	r, err := ParsePrefixRange("10.0.0.0/8^16-23")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for range r.All() {
			n++
		}
		if n != 65280 {
			b.Fatalf("enumerated %d prefixes, want 65280", n)
		}
	}
}
