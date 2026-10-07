package ast

import "testing"

// TestText: an object's text runs from its first attribute line to its last
// attribute or continuation line. Leading and trailing blank, comment and
// malformed lines are dropped; one between attributes stays. Lines are read as
// the lexer reads them: a line led by a space, a tab or '+' continues an
// attribute only right after an attribute or continuation line.
func TestText(t *testing.T) {
	const obj = "aut-num: AS1\nsource: RIPE\n"
	for _, c := range []struct{ text, want string }{
		{"# head\n\nroute: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n\n# tail\nEOF\n\n",
			"route: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n"},
		{"aut-num: AS1\nas-name: A\n\nimport: from AS2 accept ANY\nsource: RIPE\n# trailing\nEOF\n\n",
			"aut-num: AS1\nas-name: A\n\nimport: from AS2 accept ANY\nsource: RIPE\n"},
		{"# aut-num: AS1\naut-num: AS1\nsource: RIPE\n", obj}, // a comment quoting the first line is still trivia
		{obj + "\n stray\n", obj},
		{obj + "\n+\n", obj},
		{obj + "\n  # c\n", obj},
		{obj + "# c\n stray\n", obj},
		{obj + "EOF\n\tstray\n", obj},
		{"aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n\r\n  # c\r\n", "aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n"},
		{"aut-num: AS1\n\n stray\nsource: RIPE\n\n stray\n", "aut-num: AS1\n\n stray\nsource: RIPE\n"},
		{"aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n", "aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n"},
		{"# only trivia\n\n", "# only trivia\n\n"}, // no attribute line: the text unchanged
	} {
		if got := parse(c.text).Text(); got != c.want {
			t.Errorf("Text(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}
