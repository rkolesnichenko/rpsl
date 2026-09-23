package lexer

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// benchDump is about 1 MB of RPSL in the shapes a real dump holds: attribute
// lines, the three kinds of continuation line, inline and full-line comments,
// and blank separators. It is generated, so the benchmark needs no data files.
var benchDump = sync.OnceValue(func() string {
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		fmt.Fprintf(&b, "aut-num:        AS%d\nas-name:        EXAMPLE-%d\ndescr:          Example network %d\n", 64512+i, i, i)
		fmt.Fprintf(&b, "import:         from AS%d accept AS-PEER-%d  # a peer\n", 65000+i%500, i)
		fmt.Fprintf(&b, "export:         to AS%d\n                announce AS%d\n", 65000+i%500, 64512+i)
		b.WriteString("remarks:        first line\n+\n                continued with a space\n\tcontinued with a tab\n")
		fmt.Fprintf(&b, "mnt-by:         MNT-%d\nsource:         RIPE\n\n", i%97)
		fmt.Fprintf(&b, "# route objects of AS%d\nroute:          10.%d.%d.0/24\norigin:         AS%d\nsource:         RIPE\n\n",
			64512+i, i/256%256, i%256, 64512+i)
	}
	return b.String()
})

func BenchmarkTokenize(b *testing.B) {
	src := benchDump()
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if toks := Tokenize(src); len(toks) == 0 {
			b.Fatal("no tokens")
		}
	}
}
