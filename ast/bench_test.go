package ast

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// benchObject is an aut-num with 200 policy lines, the size of a well-peered
// network's object.
func benchObject(b *testing.B) *Object {
	b.Helper()
	var s strings.Builder
	s.WriteString("aut-num:        AS64512\nas-name:        EXAMPLE\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&s, "import:         from AS%d accept AS-PEER-%d\nexport:         to AS%d announce AS64512\n", 65000+i, i, 65000+i)
	}
	s.WriteString("mnt-by:         MNT-EXAMPLE\nsource:         RIPE\n")
	return New(lexer.Tokenize(s.String()))
}

func BenchmarkObjectString(b *testing.B) {
	o := benchObject(b)
	b.SetBytes(int64(len(o.String())))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(o.String()) == 0 {
			b.Fatal("empty rendering")
		}
	}
}

// BenchmarkObjectSet replaces one attribute in place, alternating its value so
// every call changes the object.
func BenchmarkObjectSet(b *testing.B) {
	o := benchObject(b)
	values := []string{"MNT-A", "MNT-B"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := o.Set("mnt-by", values[i%2]); err != nil {
			b.Fatal(err)
		}
	}
}
