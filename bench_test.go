package rpsl

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// benchDump is about 1 MB of valid RPSL in the mix a routing registry holds:
// aut-nums with policies, routes and route6s, as-sets and route-sets, with
// continuation lines and comments. It is generated from a fixed pattern, so the
// benchmarks need no data files and every run sees the same input.
var benchDump = sync.OnceValue(func() string {
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		as := 64512 + i
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "aut-num:        AS%d\nas-name:        EXAMPLE-%d\ndescr:          Example network %d\n", as, i, i)
			fmt.Fprintf(&b, "import:         from AS%d action pref=100; accept AS-PEER-%d  # a peer\n", 65000+i%500, i)
			fmt.Fprintf(&b, "mp-import:      afi ipv6.unicast from AS%d accept ANY\n", 65000+i%500)
			fmt.Fprintf(&b, "export:         to AS%d\n                announce AS%d AND NOT {0.0.0.0/0}\n", 65000+i%500, as)
			b.WriteString("remarks:        first line\n+\n                continued\n")
			fmt.Fprintf(&b, "mnt-by:         MNT-%d\nsource:         RIPE\n\n", i%97)
		case 1:
			fmt.Fprintf(&b, "# routes of AS%d\nroute:          10.%d.%d.0/24\ndescr:          a route\norigin:         AS%d\nmnt-by:         MNT-%d\nsource:         RIPE\n\n",
				as, i/256%256, i%256, as, i%97)
			fmt.Fprintf(&b, "route6:         2001:db8:%x::/48\norigin:         AS%d\nmnt-by:         MNT-%d\nsource:         RIPE\n\n", i%65536, as, i%97)
		case 2:
			fmt.Fprintf(&b, "as-set:         AS-SET-%d\nmembers:        AS%d, AS%d, AS-SET-%d\nmembers:        AS%d:AS-CUSTOMERS\nmbrs-by-ref:    MNT-%d\nmnt-by:         MNT-%d\nsource:         RIPE\n\n",
				i, as, as+1, i+1, as, i%97, i%97)
		case 3:
			fmt.Fprintf(&b, "route-set:      RS-SET-%d\nmembers:        10.%d.0.0/16^+, 192.0.2.0/24^25-28, RS-SET-%d^24\nmp-members:     2001:db8:%x::/48^-\nmnt-by:         MNT-%d\nsource:         RIPE\n\n",
				i, i%256, i+1, i%65536, i%97)
		}
	}
	return b.String()
})

// benchObjects is benchDump parsed, for the benchmarks that start from objects.
var benchObjects = sync.OnceValue(func() []*ast.Object {
	var out []*ast.Object
	for o := range Parse(strings.NewReader(benchDump())) {
		out = append(out, o)
	}
	return out
})

func BenchmarkParseStream(b *testing.B) {
	src := benchDump()
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for range Parse(strings.NewReader(src)) {
			n++
		}
		if n == 0 {
			b.Fatal("no objects")
		}
	}
}

func BenchmarkParseObject(b *testing.B) {
	src := "aut-num:   AS64512\nas-name:   EXAMPLE\ndescr:     Example network\n" +
		strings.Repeat("import:    from AS65000 action pref=100; accept AS-PEER\nexport:    to AS65000 announce AS64512\n", 20) +
		"remarks:   first line\n+\n           continued\nmnt-by:    MNT-EXAMPLE\nsource:    RIPE\n"
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ds := ParseObject(src); len(ds) != 0 {
			b.Fatal(ds)
		}
	}
}

// BenchmarkDecode decodes every object of benchDump into its typed form,
// policies included.
func BenchmarkDecode(b *testing.B) {
	objs := benchObjects()
	b.SetBytes(int64(len(benchDump())))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, o := range objs {
			if _, ds := Decode(o); len(ds) != 0 {
				b.Fatalf("%s: %v", o.Key(), ds)
			}
		}
	}
}

// BenchmarkValidate checks every object of benchDump against the RIPE profile.
func BenchmarkValidate(b *testing.B) {
	objs := benchObjects()
	b.SetBytes(int64(len(benchDump())))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, o := range objs {
			Validate(o, RIPE)
		}
	}
}
