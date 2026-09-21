package lexer

import "testing"

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
	})
}
