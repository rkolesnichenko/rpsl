package consist

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// lintDump is a RIPE dump of AS1 with one import and one export toward each
// of n peers (AS2..AS(n+1)), and each peer's aut-num importing from AS1.
func lintDump(n int) string {
	var b strings.Builder
	b.WriteString("aut-num: AS1\nas-name: BIG\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "import: from AS%d accept AS%d\nexport: to AS%d announce AS1\n", i, i, i)
	}
	b.WriteString("source: RIPE\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "\naut-num: AS%d\nas-name: PEER\nimport: from AS1 accept AS1\nexport: to AS1 announce AS%d\nsource: RIPE\n", i, i)
	}
	return b.String()
}

// BenchmarkLint lints an aut-num with N peers, one import and one export
// each: each session evaluates the whole aut-num, so a lint without a memo
// is quadratic in N.
func BenchmarkLint(b *testing.B) {
	for _, n := range []int{250, 500, 1000} {
		dump := lintDump(n)
		var objs []object.Object
		for _, text := range strings.Split(dump, "\n\n") {
			raw, _ := rpsl.ParseObject(text)
			o, _ := rpsl.Decode(raw)
			objs = append(objs, o)
		}
		l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
		if err := l.Read(strings.NewReader(dump)); err != nil {
			b.Fatal(err)
		}
		for _, src := range []struct {
			name string
			src  resolve.PolicySource
		}{{"MemSource", resolve.NewMemSource(objs)}, {"KeepPolicy", l.Source()}} {
			b.Run(fmt.Sprintf("%s/N=%d", src.name, n), func(b *testing.B) {
				c := &Checker{Eval: peval.Evaluator{Src: src.src}}
				for range b.N {
					if _, err := c.Lint(context.Background(), 1); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// providerDump is AS1 exporting one customer as-set to each of n peers and
// importing each peer's routes; each peer imports the set from AS1. The
// set has 100 member ASes with a route each.
func providerDump(n int) string {
	var b strings.Builder
	b.WriteString("as-set: AS-CUST\nmembers: ")
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "AS%d", 10000+i)
	}
	b.WriteString("\nsource: RIPE\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "\nroute: 10.%d.%d.0/24\norigin: AS%d\nsource: RIPE\n", i/250, i%250, 10000+i)
	}
	b.WriteString("\naut-num: AS1\nas-name: PROVIDER\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "import: from AS%d accept AS%d\nexport: to AS%d announce AS-CUST\n", i, i, i)
	}
	b.WriteString("source: RIPE\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "\naut-num: AS%d\nas-name: PEER\nimport: from AS1 accept AS-CUST\nexport: to AS1 announce AS%d\nsource: RIPE\n", i, i)
	}
	return b.String()
}

// BenchmarkCheckProvider checks every pair of a provider with N peers, as
// rpslcheck's sweep does, with and without a Memo.
func BenchmarkCheckProvider(b *testing.B) {
	const n = 200
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(providerDump(n))); err != nil {
		b.Fatal(err)
	}
	af := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	for _, memo := range []bool{false, true} {
		b.Run(fmt.Sprintf("memo=%v", memo), func(b *testing.B) {
			for range b.N {
				c := &Checker{Eval: peval.Evaluator{Src: l.Source()}}
				if memo {
					c.Memo = NewMemo()
				}
				for peer := types.ASN(2); peer < n+2; peer++ {
					if _, err := c.Check(context.Background(), Pair{A: 1, B: peer, AF: af}); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
