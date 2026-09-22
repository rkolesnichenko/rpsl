package lexer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzTokenize asserts the lexer never panics and always preserves the partition
// invariant (concatenating token Raws reproduces the input) on arbitrary bytes.
func FuzzTokenize(f *testing.F) {
	seeds := []string{
		"",
		"route: 192.0.2.0/24\n",
		"remarks: a\n+\n b\n",
		"x: y\r\n\r\nz: w",
		"# comment\n\tnot an attr\n",
		"key:#only-comment\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	// The root module's corpus of real objects, when present.
	files, _ := filepath.Glob(filepath.Join("..", "testdata", "corpus", "*.txt"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(string(b))
		}
	}
	f.Fuzz(func(t *testing.T, src string) {
		toks := Tokenize(src)
		var got string
		for _, tk := range toks {
			got += tk.Raw
		}
		if got != src {
			t.Fatalf("partition invariant violated: input %q rejoined to %q", src, got)
		}
		// TokenizeAt reports the same tokens, shifted into stream coordinates.
		at := TokenizeAt(src, 7, 50)
		if len(at) != len(toks) {
			t.Fatalf("TokenizeAt gave %d tokens, Tokenize %d", len(at), len(toks))
		}
		for i, tk := range at {
			b := toks[i]
			if tk.Raw != b.Raw || tk.Value != b.Value || tk.Span.StartLine != b.Span.StartLine+6 ||
				tk.Span.EndByte != b.Span.EndByte+50 || len(tk.Segments) != len(b.Segments) {
				t.Fatalf("token %d: TokenizeAt %+v is not Tokenize %+v shifted by (6 lines, 50 bytes)", i, tk, b)
			}
		}
		for i, tk := range toks {
			checkToken(t, src, i, tk)
		}
	})
}

// position returns the 1-based line and column of byte b of src.
func position(src string, b int) (line, col int) {
	return 1 + strings.Count(src[:b], "\n"), b - strings.LastIndexByte(src[:b], '\n')
}

// checkToken asserts that a token says where it is truthfully: its span holds
// its Raw, every segment maps its slice of Value to the same bytes in src, and
// its kind follows the line rules the streaming parser shares.
func checkToken(t *testing.T, src string, i int, tk Token) {
	t.Helper()
	sp := tk.Span
	if sp.StartByte < 0 || sp.EndByte > len(src) || src[sp.StartByte:sp.EndByte] != tk.Raw {
		t.Fatalf("token %d: span %+v does not hold its Raw %q", i, sp, tk.Raw)
	}
	if l, c := position(src, sp.StartByte); l != sp.StartLine || c != sp.StartCol {
		t.Fatalf("token %d: span starts at %d:%d, its first byte is at %d:%d", i, sp.StartLine, sp.StartCol, l, c)
	}
	first := strings.TrimSuffix(strings.TrimSuffix(strings.SplitN(tk.Raw, "\n", 2)[0], "\n"), "\r")
	switch tk.Kind {
	case KindBlank:
		if !IsBlankLine(first) {
			t.Fatalf("token %d: blank token %q is not a blank line", i, tk.Raw)
		}
		return
	case KindAttribute:
	default:
		return
	}
	if !StartsAttribute(first) {
		t.Fatalf("token %d: attribute token %q does not start an attribute", i, tk.Raw)
	}
	if name := CanonicalName(first[:strings.IndexByte(first, ':')]); name != tk.Name {
		t.Fatalf("token %d: name %q, but its line names %q", i, tk.Name, name)
	}
	if len(tk.Segments) == 0 || tk.Segments[0].ValStart != 0 || tk.Segments[len(tk.Segments)-1].ValEnd != len(tk.Value) {
		t.Fatalf("token %d: segments %+v do not cover value %q", i, tk.Segments, tk.Value)
	}
	for j, sg := range tk.Segments {
		if j > 0 && sg.ValStart != tk.Segments[j-1].ValEnd+1 {
			t.Fatalf("token %d: segment %d starts at %d, want %d (after the joining newline)", i, j, sg.ValStart, tk.Segments[j-1].ValEnd+1)
		}
		n := sg.ValEnd - sg.ValStart
		if sg.ValStart > sg.ValEnd || sg.SrcByte < 0 || sg.SrcByte+n > len(src) ||
			src[sg.SrcByte:sg.SrcByte+n] != tk.Value[sg.ValStart:sg.ValEnd] {
			t.Fatalf("token %d: segment %d %+v does not map value %q to src", i, j, sg, tk.Value)
		}
		if l, c := position(src, sg.SrcByte); l != sg.SrcLine || c != sg.SrcCol {
			t.Fatalf("token %d: segment %d says %d:%d, its byte is at %d:%d", i, j, sg.SrcLine, sg.SrcCol, l, c)
		}
	}
}
