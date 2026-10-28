package rpsl

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
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
		// byte by byte.
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
			ref.WriteString(windows1252Ref(l))
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

// FuzzParseStreamWindows1252Caps: under small caps too, the stream read as
// Windows-1252 is the stream of the input transcoded line by line, but for a
// line over MaxObjectBytes as read, discarded unread, which counts as read;
// and each object carries one rpsl/not-utf8 Warning counting the transcoded
// lines it holds, at the first. The input is built from tagged lines, each
// naming its line number, so every line an object holds can be traced.
func FuzzParseStreamWindows1252Caps(f *testing.F) {
	f.Add([]byte{0, 0x41, 4, 0x45, 0, 0x82, 5, 0, 1, 0xc3, 2, 0x4f, 3, 0x07, 6, 0x60}, uint8(20), uint8(3))
	f.Add([]byte{4, 0x4f, 4, 0x4f, 0, 0x01, 5, 0, 0, 0xcf, 1, 0x8f, 2, 0x22}, uint8(8), uint8(1))
	f.Add([]byte{0, 0x4a, 0, 0x0f, 0, 0x0f, 5, 1, 4, 0xc2}, uint8(255), uint8(255))
	tag := regexp.MustCompile(`@(\d+)@`)
	f.Fuzz(func(t *testing.T, prog []byte, capBytes, capLines uint8) {
		opts := ParseOptions{MaxObjectBytes: int64(capBytes%64) + 8, MaxObjectLines: int(capLines%6) + 1}
		if capBytes == 255 {
			opts.MaxObjectBytes = -1
		}
		// One line per two bytes: its kind, then its payload and terminator.
		var in, ref strings.Builder
		recoded := map[int]int{} // the reference's byte offset of each transcoded line
		line := 1
		for i := 0; i+1 < len(prog) && line <= 64; i, line = i+2, line+1 {
			kind, arg := prog[i], prog[i+1]
			payload := strings.Repeat([]string{"x", "\xe9", "é", "\x80\x96"}[arg>>6], int(arg%16))
			term := "\n"
			if arg&0x20 != 0 {
				term = "\r\n"
			}
			l := fmt.Sprintf("@%d@", line)
			switch kind % 7 {
			case 0, 1:
				l = "a" + l + ": " + payload + term
			case 2:
				l = " " + l + payload + term
			case 3:
				l = "+" + l + payload + term
			case 4:
				l = "#" + l + payload + term
			case 5:
				l = []string{"", " \t"}[arg&1] + term // blank: untagged
			case 6:
				l += payload + term
			}
			if i+3 >= len(prog) && kind&0x80 != 0 {
				l = strings.TrimSuffix(strings.TrimSuffix(l, "\n"), "\r") // the last line unterminated
			}
			in.WriteString(l)
			if utf8.ValidString(l) || opts.MaxObjectBytes >= 0 && int64(len(l)) > opts.MaxObjectBytes {
				ref.WriteString(l)
				continue
			}
			recoded[line] = ref.Len()
			ref.WriteString(windows1252Ref(l))
		}
		s := in.String()

		plain := collectStream(ref.String(), opts)
		opts.NonUTF8AsWindows1252 = true
		got := collectStream(s, opts)
		if len(got) != len(plain) {
			t.Fatalf("%q %+v: %d objects, the transcoded input's %d", s, opts, len(got), len(plain))
		}
		seen := map[int]bool{}
		for i := range got {
			text := got[i].obj.String()
			if text != plain[i].obj.String() {
				t.Fatalf("%q %+v: object %d is %q, the transcoded input's %q", s, opts, i, text, plain[i].obj.String())
			}
			if a, b := attrKeys(got[i].obj, lexer.Span{}), attrKeys(plain[i].obj, lexer.Span{}); !reflect.DeepEqual(a, b) {
				t.Fatalf("%q %+v: object %d attributes %v, the transcoded input's %v", s, opts, i, a, b)
			}
			var warned, rest []Diagnostic
			for _, d := range got[i].diags {
				if d.Rule == "rpsl/not-utf8" {
					warned = append(warned, d)
				} else {
					rest = append(rest, d)
				}
			}
			if a, b := diagKeys(rest, lexer.Span{}), diagKeys(plain[i].diags, lexer.Span{}); !reflect.DeepEqual(a, b) {
				t.Fatalf("%q %+v: object %d diagnostics %v, the transcoded input's %v", s, opts, i, a, b)
			}
			n, first := 0, 0
			for _, m := range tag.FindAllStringSubmatch(text, -1) {
				ln, _ := strconv.Atoi(m[1])
				if seen[ln] {
					t.Fatalf("%q %+v: line %d yielded twice", s, opts, ln)
				}
				seen[ln] = true
				if _, ok := recoded[ln]; ok {
					if n++; n == 1 || ln < first {
						first = ln
					}
				}
			}
			switch {
			case n == 0 && len(warned) != 0:
				t.Fatalf("%q %+v: object %d holds no transcoded line but has %v", s, opts, i, warned)
			case n > 0 && (len(warned) != 1 || warned[0].Severity != Warning || warned[0].Span.StartLine != first ||
				warned[0].Span.StartByte != recoded[first] || !strings.HasPrefix(warned[0].Message, fmt.Sprintf("%d line", n))):
				t.Fatalf("%q %+v: object %d holds %d transcoded lines from line %d (byte %d), has %v", s, opts, i, n, first, recoded[first], warned)
			}
		}
	})
}

// windows1252Ref decodes l byte by byte, 0x80-0x9F from Windows-1252's
// characters as written, independently of the table in stream.go.
func windows1252Ref(l string) string {
	hi := []rune("€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008dŽ\u008f\u0090‘’“”•–—˜™š›œ\u009džŸ")
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c < 0x80:
			b.WriteByte(c)
		case c < 0xA0:
			b.WriteRune(hi[c-0x80])
		default:
			b.WriteRune(rune(c))
		}
	}
	return b.String()
}
