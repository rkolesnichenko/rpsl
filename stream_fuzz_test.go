package rpsl

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// FuzzParseStream: the stream never panics, is lossless, splits objects where
// the lexer sees them end, and says the same as ParseObject; resuming after a
// break loses nothing; and caps only ever remove whole, diagnosed objects,
// leaving the others byte- and position-identical.
func FuzzParseStream(f *testing.F) {
	for _, s := range []string{"a: 1\n\nb: 2\n", "# c\n\n\n", "a: 1\r\n\r\n", " x\n\na:\n+\n", "",
		"a: 1\n\n\rb: 2\n\nc: 3\n", "a: 1\n bad\n\n\x00: 2\n", "a: 1\n+\n# c\n\n\nb: 2", "a: 1\n\r\r\nb: 2\n"} {
		f.Add(s, uint16(7), uint8(2), uint8(1))
	}
	files, _ := filepath.Glob(filepath.Join(corpusDir, "*.txt"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(string(b), uint16(64), uint8(3), uint8(2))
		}
	}
	f.Fuzz(func(t *testing.T, s string, capBytes uint16, capLines uint8, breakAt uint8) {
		full := collectStream(s, ParseOptions{MaxObjectBytes: -1, MaxObjectLines: -1})

		// Lossless, and each object is what ParseObject makes of its own text,
		// shifted to where that text sits in the stream.
		off := 0
		for i, it := range full {
			text := it.obj.String()
			if !strings.HasPrefix(s[off:], text) {
				t.Fatalf("object %d %q is not the input at byte %d", i, text, off)
			}
			shift := lexer.Span{StartLine: strings.Count(s[:off], "\n"), StartByte: off}
			alone, ds := ParseObject(text)
			if a, b := attrKeys(it.obj, lexer.Span{}), attrKeys(alone, shift); !reflect.DeepEqual(a, b) {
				t.Fatalf("object %d: streamed attributes %v, ParseObject's shifted %v", i, a, b)
			}
			if a, b := diagKeys(it.diags, lexer.Span{}), diagKeys(ds, shift); !reflect.DeepEqual(a, b) {
				t.Fatalf("object %d: streamed diagnostics %v, ParseObject's shifted %v", i, a, b)
			}
			off += len(text)
		}
		if off != len(s) {
			t.Fatalf("the stream yielded %d of %d bytes", off, len(s))
		}

		// Objects end exactly where the lexer sees a blank line between two
		// attributes: the stream splits the input as the lexer reads it.
		var want, got [][]string
		var cur []string
		blank := false
		for _, tk := range lexer.Tokenize(s) {
			switch tk.Kind {
			case lexer.KindAttribute:
				if blank && cur != nil {
					want, cur = append(want, cur), nil
				}
				cur, blank = append(cur, fmt.Sprintf("%d:%q", tk.Span.StartByte, tk.Raw)), false
			case lexer.KindBlank:
				blank = true
			}
		}
		if cur != nil {
			want = append(want, cur)
		}
		for _, it := range full {
			var attrs []string
			for _, a := range it.obj.Attributes() {
				attrs = append(attrs, fmt.Sprintf("%d:%q", a.Span.StartByte, a.Raw))
			}
			if attrs != nil {
				got = append(got, attrs)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: the stream splits the attributes into %v, the lexer into %v", s, got, want)
		}

		// Ranging again after a break continues where it stopped.
		seq := ParseWith(strings.NewReader(s), ParseOptions{MaxObjectBytes: -1, MaxObjectLines: -1})
		var resumed []string
		for k := 0; k < 3; k++ {
			n := 0
			for o := range seq {
				resumed = append(resumed, o.String())
				if n++; n > int(breakAt)%4 {
					break
				}
			}
		}
		for o := range seq {
			resumed = append(resumed, o.String())
		}
		if len(resumed) != len(full) || strings.Join(resumed, "") != s {
			t.Fatalf("resuming after breaks yielded %d objects %q, want %d", len(resumed), resumed, len(full))
		}

		// Caps drop whole objects, each with one diagnostic, and change nothing else.
		maxBytes, maxLines := int(capBytes%512)+1, int(capLines%16)+1
		capped := collectStream(s, ParseOptions{MaxObjectBytes: int64(maxBytes), MaxObjectLines: maxLines})
		var kept []streamed
		tooLarge, capDiags := 0, 0
		for _, it := range capped {
			for _, d := range it.diags {
				switch d.Rule {
				case "rpsl/object-too-large":
					tooLarge++
					capDiags++
				case "rpsl/trivia-too-large":
					capDiags++
				}
			}
			if attrs := it.obj.Attributes(); len(attrs) > 0 {
				first, last := attrs[0].Span, attrs[len(attrs)-1].Span
				if last.EndByte-first.StartByte > maxBytes || last.EndLine-first.StartLine+1 > maxLines {
					t.Fatalf("object %q is over the caps (%d bytes, %d lines)", it.obj.String(), maxBytes, maxLines)
				}
				kept = append(kept, it)
			}
		}
		j := 0
		for _, it := range kept {
			for j < len(full) && !reflect.DeepEqual(attrKeys(full[j].obj, lexer.Span{}), attrKeys(it.obj, lexer.Span{})) {
				j++
			}
			if j == len(full) {
				t.Fatalf("capped object %q is not an object of the uncapped stream, in order", it.obj.String())
			}
			j++
		}
		dropped := -len(kept)
		for _, it := range full {
			if len(it.obj.Attributes()) > 0 {
				dropped++
			}
		}
		if dropped != tooLarge {
			t.Fatalf("caps dropped %d objects but reported %d rpsl/object-too-large", dropped, tooLarge)
		}
		if capDiags == 0 {
			var got strings.Builder
			for _, it := range capped {
				got.WriteString(it.obj.String())
			}
			if got.String() != s {
				t.Fatalf("no cap was reported, but the capped stream is not lossless: %q", got.String())
			}
		}
	})
}

type streamed struct {
	obj   *ast.Object
	diags []Diagnostic
}

func collectStream(s string, opts ParseOptions) []streamed {
	var out []streamed
	for o, ds := range ParseWith(strings.NewReader(s), opts) {
		out = append(out, streamed{o, ds})
	}
	return out
}

// attrKeys renders an object's attributes with their spans and segments moved
// by shift, for comparing an object across parses.
func attrKeys(o *ast.Object, shift lexer.Span) []string {
	var out []string
	for _, a := range o.Attributes() {
		sp := a.Span
		k := fmt.Sprintf("%s|%q|%q|%d:%d-%d:%d|%d-%d", a.Name, a.Value, a.Raw, sp.StartLine+shift.StartLine, sp.StartCol,
			sp.EndLine+shift.StartLine, sp.EndCol, sp.StartByte+shift.StartByte, sp.EndByte+shift.StartByte)
		for _, g := range a.Segments {
			k += fmt.Sprintf("|%d-%d@%d:%d/%d", g.ValStart, g.ValEnd, g.SrcLine+shift.StartLine, g.SrcCol, g.SrcByte+shift.StartByte)
		}
		out = append(out, k)
	}
	return out
}

// diagKeys renders diagnostics with their spans moved by shift.
func diagKeys(ds []Diagnostic, shift lexer.Span) []string {
	var out []string
	for _, d := range ds {
		sp := d.Span
		out = append(out, fmt.Sprintf("%s|%v|%d:%d-%d:%d|%d-%d", d.Rule, d.Severity, sp.StartLine+shift.StartLine, sp.StartCol,
			sp.EndLine+shift.StartLine, sp.EndCol, sp.StartByte+shift.StartByte, sp.EndByte+shift.StartByte))
	}
	return out
}
