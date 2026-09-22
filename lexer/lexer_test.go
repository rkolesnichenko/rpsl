package lexer

import (
	"strings"
	"testing"
)

// rawConcat is the partition invariant: re-joining every token's Raw must equal src.
func rawConcat(toks []Token) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(t.Raw)
	}
	return b.String()
}

func TestPartitionInvariant(t *testing.T) {
	inputs := []string{
		"",
		"\n",
		"\n\n\n",
		"route: 192.0.2.0/24\n",
		"route: 192.0.2.0/24",                    // no trailing newline
		"route: 192.0.2.0/24\r\norigin: AS1\r\n", // CRLF
		"a: 1\n\nb: 2\n",                         // two objects
		"# comment only\n",
		"remarks: x\n+\n y\n", // lone-+ blank in value
		"orphan continuation\n garbage\n",
		"no-colon-line\n",
		"   \t  \n", // whitespace-only blank
	}
	for _, in := range inputs {
		if got := rawConcat(Tokenize(in)); got != in {
			t.Errorf("partition broken for %q: rejoined to %q", in, got)
		}
	}
}

func TestAttributeFolding(t *testing.T) {
	src := "descr: line one\n more\n+\n+plus-text\n"
	toks := Tokenize(src)
	if len(toks) != 1 {
		t.Fatalf("want 1 folded token, got %d", len(toks))
	}
	tok := toks[0]
	if tok.Kind != KindAttribute || tok.Name != "descr" {
		t.Fatalf("unexpected token: %+v", tok)
	}
	want := "line one\nmore\n\nplus-text"
	if tok.Value != want {
		t.Errorf("value = %q, want %q", tok.Value, want)
	}
	if tok.Raw != src {
		t.Errorf("raw = %q, want %q", tok.Raw, src)
	}
	if tok.Span.StartLine != 1 || tok.Span.EndLine != 4 {
		t.Errorf("span lines = %d..%d, want 1..4", tok.Span.StartLine, tok.Span.EndLine)
	}
}

func TestCommentStripping(t *testing.T) {
	toks := Tokenize("origin: AS65001  # primary origin\n")
	if len(toks) != 1 {
		t.Fatalf("want 1 token, got %d", len(toks))
	}
	if toks[0].Value != "AS65001" {
		t.Errorf("value = %q, want %q", toks[0].Value, "AS65001")
	}
	if !strings.Contains(toks[0].Raw, "# primary origin") {
		t.Errorf("raw should retain the comment, got %q", toks[0].Raw)
	}
}

func TestNameCanonicalization(t *testing.T) {
	toks := Tokenize("AS-Name:   FOO\n")
	if toks[0].Name != "as-name" {
		t.Errorf("name = %q, want %q", toks[0].Name, "as-name")
	}
}

func TestKinds(t *testing.T) {
	toks := Tokenize("key: val\n\n# c\nbad line\n garbage\n")
	want := []Kind{KindAttribute, KindBlank, KindComment, KindMalformed, KindMalformed}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}
	for i, k := range want {
		if toks[i].Kind != k {
			t.Errorf("token %d kind = %d, want %d", i, toks[i].Kind, k)
		}
	}
}

// TestSegmentSourceMap verifies that value offsets translate back to accurate
// source positions across a folded multi-line value with a '+' continuation and
// an inline comment.
func TestSegmentSourceMap(t *testing.T) {
	src := "descr: first # c\n+ second\n        third\n"
	toks := Tokenize(src)
	if len(toks) != 1 || toks[0].Kind != KindAttribute {
		t.Fatalf("tokens = %+v, want one attribute", toks)
	}
	tok := toks[0]
	if tok.Value != "first\nsecond\nthird" {
		t.Fatalf("Value = %q, want %q", tok.Value, "first\nsecond\nthird")
	}
	// Each fragment's first byte must map back to the right source byte.
	for _, c := range []struct {
		name string
		off  int // offset within Value
		want byte
		line int
	}{
		{"first", 0, 'f', 1},
		{"second", 6, 's', 2}, // after "first\n"
		{"third", 13, 't', 3}, // after "first\nsecond\n"
	} {
		line, _, byteoff := tok.SourceAt(c.off)
		if byteoff >= len(src) || src[byteoff] != c.want {
			t.Errorf("%s: SourceAt(%d) byte %d = %q, want %q", c.name, c.off, byteoff, safeIdx(src, byteoff), string(c.want))
		}
		if line != c.line {
			t.Errorf("%s: SourceAt(%d) line = %d, want %d", c.name, c.off, line, c.line)
		}
	}
}

func safeIdx(s string, i int) string {
	if i < 0 || i >= len(s) {
		return "<oob>"
	}
	return string(s[i])
}

// Attribute names are canonicalized with ASCII rules only: lower-cased, with
// spaces and tabs trimmed. Anything else stays in the name (so the façade
// reports it as invalid) instead of being folded into a valid-looking one.
func TestCanonicalNameIsASCII(t *testing.T) {
	for in, want := range map[string]string{
		"AS-Name":     "as-name",
		" \tdescr \t": "descr",
		"route ":      "route ", // no-break space is not trimmed
		"\vroute":     "\vroute",
		"Key":         "Key", // Kelvin sign: not lowered to ASCII 'k'
		"MNT-BY":      "mnt-by",
		"Ä-attr":      "Ä-attr",
	} {
		if got := CanonicalName(in); got != want {
			t.Errorf("CanonicalName(%q) = %q, want %q", in, got, want)
		}
	}
	if toks := Tokenize("Key: x\n"); toks[0].Name != "Key" {
		t.Errorf("Tokenize name = %q", toks[0].Name)
	}
}
