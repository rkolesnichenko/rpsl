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
