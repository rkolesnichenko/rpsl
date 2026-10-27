package lexer

import (
	"strings"
	"testing"
)

// Registries write '#' as text in free-form attributes ("Shaw Tower # 16-02/03",
// "netname: DATA#LIMITED"); ValueWithComments keeps it.
func TestValueWithComments(t *testing.T) {
	cases := []struct {
		src, value, with string
	}{
		{"descr: Shaw Tower # 16-02/03\n", "Shaw Tower", "Shaw Tower # 16-02/03"},
		{"netname: DATA#LIMITED\n", "DATA", "DATA#LIMITED"},
		{"descr:\t a # b \t\n", "a", "a # b"},
		{"descr: no comment\n", "no comment", "no comment"},
		{"descr: a\n # only a comment\n", "a\n", "a\n# only a comment"},
		{"descr: a\n+ b # c\n+\n", "a\nb\n", "a\nb # c\n"},
		{"descr: x # y\r\n z\r\n", "x\nz", "x # y\nz"},
		{"descr: x # y\r", "x", "x # y"},
		{"descr: x # y", "x", "x # y"},
		{"key:#only-comment\n", "", "#only-comment"},
		{"remarks: see http://example.net/#top\n", "see http://example.net/", "see http://example.net/#top"},
	}
	for _, c := range cases {
		toks := Tokenize(c.src)
		if len(toks) != 1 || toks[0].Kind != KindAttribute {
			t.Fatalf("%q: want one attribute token, got %+v", c.src, toks)
		}
		if toks[0].Value != c.value {
			t.Errorf("%q: Value = %q, want %q", c.src, toks[0].Value, c.value)
		}
		if got := ValueWithComments(toks[0].Raw); got != c.with {
			t.Errorf("%q: ValueWithComments = %q, want %q", c.src, got, c.with)
		}
	}
}

// stripComments removes what the lexer treats as a comment from each line of
// a ValueWithComments result, which must give back Value.
func stripComments(v string) string {
	lines := strings.Split(v, "\n")
	for i, l := range lines {
		if h := strings.IndexByte(l, '#'); h >= 0 {
			lines[i] = strings.TrimRight(l[:h], " \t")
		}
	}
	return strings.Join(lines, "\n")
}
