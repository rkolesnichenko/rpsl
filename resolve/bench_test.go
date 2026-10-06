package resolve

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// benchDecode parses and decodes objects for the benchmark graphs.
func benchDecode(texts []string) []object.Object {
	out := make([]object.Object, 0, len(texts))
	for _, t := range texts {
		o, _ := rpsl.ParseObject(t)
		d, _ := object.Decode(o)
		out = append(out, d)
	}
	return out
}

// coneObjects is a customer cone the size of a large transit network's: AS-CONE
// lists 100 as-sets, each lists 100 ASNs, and each ASN originates 5 routes —
// 10,000 ASNs and 50,000 prefixes.
var coneObjects = sync.OnceValue(func() []object.Object {
	var texts []string
	var top []string
	n := 0
	for i := 0; i < 100; i++ {
		top = append(top, fmt.Sprintf("AS-CUST-%d", i))
		var members []string
		for j := 0; j < 100; j++ {
			as := 100000 + i*100 + j
			members = append(members, fmt.Sprintf("AS%d", as))
			for k := 0; k < 5; k++ {
				texts = append(texts, fmt.Sprintf("route: 10.%d.%d.0/24\norigin: AS%d\nsource: TEST\n", n/256, n%256, as))
				n++
			}
		}
		texts = append(texts, fmt.Sprintf("as-set: AS-CUST-%d\nmembers: %s\nsource: TEST\n", i, strings.Join(members, ", ")))
	}
	texts = append(texts, "as-set: AS-CONE\nmembers: "+strings.Join(top, ", ")+"\nsource: TEST\n")
	return benchDecode(texts)
})

// coneSource serves coneObjects.
var coneSource = sync.OnceValue(func() *MemSource { return NewMemSource(coneObjects()) })

// operatorSource is a ring of 30 route-sets, within the default MaxDepth, with
// range operators on every nested reference, AS members with their own
// operators, and back edges every tenth set, so evaluation walks (set,
// operator stack) states around cycles.
var operatorSource = sync.OnceValue(func() *MemSource {
	var texts []string
	for i := 0; i < 30; i++ {
		as := 65000 + i
		members := []string{
			fmt.Sprintf("10.%d.0.0/16^20-24", i),
			fmt.Sprintf("RS-OP-%d^+", (i+1)%30),
			fmt.Sprintf("AS%d^26", as),
		}
		if i%10 == 9 {
			members = append(members, "RS-OP-0^24-28")
		}
		texts = append(texts,
			fmt.Sprintf("route-set: RS-OP-%d\nmembers: %s\nsource: TEST\n", i, strings.Join(members, ", ")),
			fmt.Sprintf("route: 172.%d.0.0/16\norigin: AS%d\nsource: TEST\n", 16+i%16, as))
	}
	return NewMemSource(benchDecode(texts))
})

func benchName(b *testing.B, s string) types.SetName {
	b.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		b.Fatal(err)
	}
	return n
}

func BenchmarkExpandAS(b *testing.B) {
	e := &Expander{Src: coneSource()}
	name, ctx := benchName(b, "AS-CONE"), context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.ExpandAS(ctx, types.Ref(name))
		if err != nil || got.Len() != 10000 {
			b.Fatalf("ExpandAS: %d ASNs, %v; want 10000", got.Len(), err)
		}
	}
}

func BenchmarkExpandPrefixes(b *testing.B) {
	e := &Expander{Src: coneSource(), AFI: types.AFIv4}
	name, ctx := benchName(b, "AS-CONE"), context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.ExpandPrefixes(ctx, types.Ref(name))
		if err != nil || got.Len() != 50000 {
			b.Fatalf("ExpandPrefixes: %d prefixes, %v; want 50000", got.Len(), err)
		}
	}
}

func BenchmarkExpandPrefixRanges(b *testing.B) {
	e := &Expander{Src: operatorSource(), AFI: types.AFIv4}
	name, ctx := benchName(b, "RS-OP-0"), context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.ExpandPrefixRanges(ctx, types.Ref(name))
		if err != nil || got.Len() == 0 {
			b.Fatalf("ExpandPrefixRanges: %d ranges, %v", got.Len(), err)
		}
	}
}

// BenchmarkCorpusSource is the rebuild an NRTMv4 mirror (resolve/nrtm4) and
// rpsld do for each new version: a MemSource from a Corpus holding the cone.
func BenchmarkCorpusSource(b *testing.B) {
	var c Corpus
	for _, o := range coneObjects() {
		c.Put(o)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := c.Source()
		if ps, err := src.OriginatedRoutes(ctx, 100000, types.AFIv4); err != nil || len(ps) != 5 {
			b.Fatalf("OriginatedRoutes(AS100000): %v, %v; want 5 prefixes", ps, err)
		}
	}
}

// benchFilter parses a filter for the filter benchmarks.
func benchFilter(b *testing.B, s string) policy.Filter {
	b.Helper()
	f, diags := policy.ParseFilter(s)
	if len(diags) > 0 {
		b.Fatalf("ParseFilter(%q): %v", s, diags)
	}
	return f
}

// BenchmarkEvalFilter evaluates the cone intersected with a prefix list, OR
// one of its as-sets under a range operator.
func BenchmarkEvalFilter(b *testing.B) {
	e := &Expander{Src: coneSource(), AFI: types.AFIv4}
	f := benchFilter(b, "(AS-CONE AND {10.0.0.0/10^+, 10.128.0.0/9^24}) OR AS-CUST-7^25")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.EvalFilter(ctx, f)
		if err != nil || got.Len() == 0 {
			b.Fatalf("EvalFilter: %d ranges, %v", got.Len(), err)
		}
	}
}

// BenchmarkNormalizeFilter normalizes a filter EvalFilter refuses: the cone
// less a prefix list, with AS-path and community tests kept symbolic, so NOT
// is pushed to the leaves and the OR multiplies conjuncts.
func BenchmarkNormalizeFilter(b *testing.B) {
	e := &Expander{Src: coneSource(), AFI: types.AFIv4}
	f := benchFilter(b, "AS-CONE AND NOT {10.0.0.0/12^+} AND (<^AS-CUST-1+$> OR community(65000:1) OR NOT <AS100000$>)")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := e.NormalizeFilter(ctx, f)
		if err != nil || len(got.Conjuncts) != 3 {
			b.Fatalf("NormalizeFilter: %d conjuncts, %v; want 3", len(got.Conjuncts), err)
		}
	}
}
