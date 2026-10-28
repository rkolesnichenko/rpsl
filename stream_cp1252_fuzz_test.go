package rpsl

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// FuzzParseStreamWindows1252: with NonUTF8AsWindows1252 the stream is the
// stream of the input transcoded line by line — the same objects, attributes,
// spans and diagnostics — plus, on each object holding a transcoded line, one
// rpsl/not-utf8 Warning that counts them, at the first; and it is UTF-8.
func FuzzParseStreamWindows1252(f *testing.F) {
	for _, s := range []string{"a: \xe9\n", "a: 1\n\n# \x96\n\nb: \xc3\n+ é\n", "\xe9: 1\n", "a: \xe2\x80\r\n\r\n\xff\n", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// The reference: each line ("\n" ends one) that is not UTF-8 decoded
		// byte by byte, 0x80-0x9F from Windows-1252's characters as written.
		hi := []rune("€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008dŽ\u008f\u0090‘’“”•–—˜™š›œ\u009džŸ")
		var ref strings.Builder
		var recodedAt []int // the reference's byte offset of each transcoded line
		line := 1
		var recodedLine []int
		for rest := s; rest != ""; line++ {
			l := rest
			if i := strings.IndexByte(rest, '\n'); i >= 0 {
				l = rest[:i+1]
			}
			rest = rest[len(l):]
			if utf8.ValidString(l) {
				ref.WriteString(l)
				continue
			}
			recodedAt, recodedLine = append(recodedAt, ref.Len()), append(recodedLine, line)
			for i := 0; i < len(l); i++ {
				switch c := l[i]; {
				case c < 0x80:
					ref.WriteByte(c)
				case c < 0xA0:
					ref.WriteRune(hi[c-0x80])
				default:
					ref.WriteRune(rune(c))
				}
			}
		}
		want := ref.String()

		opts := ParseOptions{MaxObjectBytes: -1, MaxObjectLines: -1}
		plain := collectStream(want, opts)
		opts.NonUTF8AsWindows1252 = true
		got := collectStream(s, opts)
		if len(got) != len(plain) {
			t.Fatalf("%q: %d objects, the transcoded input's %d", s, len(got), len(plain))
		}
		off, k := 0, 0
		for i := range got {
			text := got[i].obj.String()
			if text != plain[i].obj.String() || !utf8.ValidString(text) {
				t.Fatalf("%q: object %d is %q, the transcoded input's %q", s, i, text, plain[i].obj.String())
			}
			if a, b := attrKeys(got[i].obj, lexer.Span{}), attrKeys(plain[i].obj, lexer.Span{}); !reflect.DeepEqual(a, b) {
				t.Fatalf("%q: object %d attributes %v, the transcoded input's %v", s, i, a, b)
			}
			var warned []Diagnostic
			var rest []Diagnostic
			for _, d := range got[i].diags {
				if d.Rule == "rpsl/not-utf8" {
					warned = append(warned, d)
				} else {
					rest = append(rest, d)
				}
			}
			if a, b := diagKeys(rest, lexer.Span{}), diagKeys(plain[i].diags, lexer.Span{}); !reflect.DeepEqual(a, b) {
				t.Fatalf("%q: object %d diagnostics %v, the transcoded input's %v", s, i, a, b)
			}
			n, first := 0, 0
			for ; k < len(recodedAt) && recodedAt[k] < off+len(text); k++ {
				if n == 0 {
					first = recodedLine[k]
				}
				n++
			}
			switch {
			case n == 0 && len(warned) != 0:
				t.Fatalf("%q: object %d holds no transcoded line but has %v", s, i, warned)
			case n > 0 && (len(warned) != 1 || warned[0].Severity != Warning || warned[0].Span.StartLine != first ||
				!strings.HasPrefix(warned[0].Message, fmt.Sprintf("%d line", n))):
				t.Fatalf("%q: object %d holds %d transcoded lines from line %d, has %v", s, i, n, first, warned)
			}
			off += len(text)
		}
		if off != len(want) || k != len(recodedAt) {
			t.Fatalf("%q: the stream yielded %d of %d bytes, %d of %d transcoded lines", s, off, len(want), k, len(recodedAt))
		}
	})
}
