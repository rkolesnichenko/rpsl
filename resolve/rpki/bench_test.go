package rpki

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// benchVRPs is shaped like a real VRP set: about 700,000 VRPs, five in six
// IPv4, from /8 to /24 and /19 to /48.
func benchVRPs(n int) []VRP {
	r := rand.New(rand.NewSource(1))
	vs := make([]VRP, n)
	for i := range vs {
		var p netip.Prefix
		if r.Intn(6) > 0 {
			l := 8 + r.Intn(17)
			p = netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + r.Intn(222)), byte(r.Intn(256)), byte(r.Intn(256))}), l).Masked()
		} else {
			l := 19 + r.Intn(30)
			p = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, byte(r.Intn(16)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))}), l).Masked()
		}
		maxLen := p.Bits() + r.Intn(3)
		if maxLen > p.Addr().BitLen() {
			maxLen = p.Addr().BitLen()
		}
		vs[i] = VRP{Prefix: p, MaxLength: uint8(maxLen), ASN: types.ASN(1 + r.Intn(70000)), TA: "bench"}
	}
	return vs
}

func BenchmarkValidate(b *testing.B) {
	vs := benchVRPs(700_000)
	v, err := NewVRPs(vs)
	if err != nil {
		b.Fatal(err)
	}
	r := rand.New(rand.NewSource(2))
	routes := make([]VRP, 1<<16)
	for i := range routes {
		x := vs[r.Intn(len(vs))]
		bits := x.Prefix.Bits() + r.Intn(4)
		if bits > x.Prefix.Addr().BitLen() {
			bits = x.Prefix.Addr().BitLen()
		}
		x.Prefix = netip.PrefixFrom(x.Prefix.Addr(), bits)
		routes[i] = x
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := routes[i%len(routes)]
		v.Validate(x.Prefix, x.ASN)
	}
}

func BenchmarkReadJSON(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"roas": [`)
	for i, x := range benchVRPs(100_000) {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"asn": %d, "prefix": "%s", "maxLength": %d, "ta": "%s", "expires": 1790000000}`, uint32(x.ASN), x.Prefix, x.MaxLength, x.TA)
	}
	sb.WriteString(`]}`)
	in := sb.String()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReadJSON(strings.NewReader(in)); err != nil {
			b.Fatal(err)
		}
	}
}
