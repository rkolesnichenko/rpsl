package rpki

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
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

// BenchmarkFilterExpand expands a customer cone through Filter: AS-CONE lists
// 100 as-sets of 100 ASNs, each originating 5 routes (50,000 prefixes), and
// VRPs cover every route, a fifth of them for another AS, so 10,000 are
// suppressed. Compare with resolve's BenchmarkExpandPrefixes, the same cone
// unfiltered.
func BenchmarkFilterExpand(b *testing.B) {
	var texts, top []string
	var vs []VRP
	n := 0
	for i := 0; i < 100; i++ {
		top = append(top, fmt.Sprintf("AS-CUST-%d", i))
		var members []string
		for j := 0; j < 100; j++ {
			as := 100000 + i*100 + j
			members = append(members, fmt.Sprintf("AS%d", as))
			for k := 0; k < 5; k++ {
				p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(n / 256), byte(n % 256), 0}), 24)
				texts = append(texts, fmt.Sprintf("route: %s\norigin: AS%d\nsource: TEST\n", p, as))
				owner := types.ASN(as)
				if k == 0 {
					owner = 64496 // the ROA names another AS: the route is Invalid
				}
				vs = append(vs, VRP{Prefix: p, MaxLength: 24, ASN: owner, TA: "bench"})
				n++
			}
		}
		texts = append(texts, fmt.Sprintf("as-set: AS-CUST-%d\nmembers: %s\nsource: TEST\n", i, strings.Join(members, ", ")))
	}
	texts = append(texts, "as-set: AS-CONE\nmembers: "+strings.Join(top, ", ")+"\nsource: TEST\n")
	v, err := NewVRPs(vs)
	if err != nil {
		b.Fatal(err)
	}
	e := &resolve.Expander{Src: &Filter{Src: resolve.NewMemSource(decode(b, texts...)), VRPs: v}, AFI: types.AFIv4}
	name, _ := types.ParseSetName("AS-CONE")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.ExpandPrefixes(ctx, types.Ref(name))
		if err != nil || got.Len() != 40000 {
			b.Fatalf("ExpandPrefixes: %d prefixes, %v; want 40000", got.Len(), err)
		}
	}
}
