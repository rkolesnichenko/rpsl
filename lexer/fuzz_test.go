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
	})
}
