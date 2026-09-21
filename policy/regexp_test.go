package policy

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestParseASPathRegexpBasic(t *testing.T) {
	re, err := ParseASPathRegexp("^AS1+ AS2*$")
	if err != nil {
		t.Fatalf("ParseASPathRegexp: %v", err)
	}
	// Anchors are atoms of the sequence (RFC 2622 §5.4), not flags.
	seq, ok := re.Body.(ASPathSeq)
	if !ok || len(seq.Terms) != 4 {
		t.Fatalf("body = %T %+v, want 4-term ASPathSeq", re.Body, re.Body)
	}
	if _, ok := seq.Terms[0].(ASPathStart); !ok {
		t.Errorf("term0 = %T, want ASPathStart", seq.Terms[0])
	}
	r0, ok := seq.Terms[1].(ASPathRepeat)
	if !ok || r0.Op != RepeatPlus {
		t.Fatalf("term1 = %+v, want Plus repeat", seq.Terms[1])
	}
	if a, ok := r0.Inner.(ASPathASN); !ok || a.AS != 1 {
		t.Errorf("term1 inner = %+v, want AS1", r0.Inner)
	}
	r1, ok := seq.Terms[2].(ASPathRepeat)
	if !ok || r1.Op != RepeatStar {
		t.Fatalf("term2 = %+v, want Star repeat", seq.Terms[2])
	}
	if a, ok := r1.Inner.(ASPathASN); !ok || a.AS != 2 {
		t.Errorf("term2 inner = %+v, want AS2", r1.Inner)
	}
	if _, ok := seq.Terms[3].(ASPathEnd); !ok {
		t.Errorf("term3 = %T, want ASPathEnd", seq.Terms[3])
	}
}

func TestParseASPathRegexpForms(t *testing.T) {
	t.Run("any", func(t *testing.T) {
		re, err := ParseASPathRegexp(".")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := re.Body.(ASPathAny); !ok {
			t.Errorf("body = %T, want ASPathAny", re.Body)
		}
	})
	t.Run("as-set", func(t *testing.T) {
		re, err := ParseASPathRegexp("AS-FOO")
		if err != nil {
			t.Fatal(err)
		}
		s, ok := re.Body.(ASPathSet)
		if !ok || s.Name.Canonical() != "AS-FOO" {
			t.Errorf("body = %+v, want ASPathSet AS-FOO", re.Body)
		}
	})
	t.Run("alternation", func(t *testing.T) {
		re, err := ParseASPathRegexp("AS1 | AS2")
		if err != nil {
			t.Fatal(err)
		}
		alt, ok := re.Body.(ASPathAlt)
		if !ok || len(alt.Alts) != 2 {
			t.Fatalf("body = %T %+v, want 2-branch ASPathAlt", re.Body, re.Body)
		}
	})
	t.Run("grouped-repeat", func(t *testing.T) {
		re, err := ParseASPathRegexp("(AS1 AS2)+")
		if err != nil {
			t.Fatal(err)
		}
		rep, ok := re.Body.(ASPathRepeat)
		if !ok || rep.Op != RepeatPlus {
			t.Fatalf("body = %T %+v, want Plus repeat", re.Body, re.Body)
		}
		if _, ok := rep.Inner.(ASPathSeq); !ok {
			t.Errorf("repeat inner = %T, want ASPathSeq", rep.Inner)
		}
	})
	t.Run("range-mn", func(t *testing.T) {
		re, _ := ParseASPathRegexp("AS1{2,4}")
		rep := re.Body.(ASPathRepeat)
		if rep.Op != RepeatRange || rep.Min != 2 || rep.Max != 4 {
			t.Errorf("range = %+v, want {2,4}", rep)
		}
	})
	t.Run("range-open", func(t *testing.T) {
		re, _ := ParseASPathRegexp("AS1{2,}")
		rep := re.Body.(ASPathRepeat)
		if rep.Min != 2 || rep.Max != -1 {
			t.Errorf("open range = %+v, want min 2 max -1", rep)
		}
	})
	t.Run("plain-asn", func(t *testing.T) {
		re, _ := ParseASPathRegexp("3333")
		if a, ok := re.Body.(ASPathASN); !ok || a.AS != 3333 {
			t.Errorf("body = %+v, want AS3333", re.Body)
		}
	})
}

// TestParseASPathRegexpRFC covers the full RFC 2622 §5.4 operator set. Each
// expectation is the hand-written rendering of the intended AST (see renderRE).
func TestParseASPathRegexpRFC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"^AS1+ AS2*$", "seq(^ +(AS1) *(AS2) $)"},
		{"^.* AS1$", "seq(^ *(.) AS1 $)"},
		{"[^AS1]", "[^ AS1]"},                                        // was silently read as ^AS1
		{"[AS1 AS2]", "[AS1 AS2]"},                                   // was silently read as a sequence
		{"[AS1 - AS10]", "[AS1-AS10]"},                               // range, spaced
		{"[AS1-AS10 AS-FOO . PeerAS]", "[AS1-AS10 AS-FOO . PeerAS]"}, // range, joined
		{"AS-FOO~*", "~*(AS-FOO)"},                                   // was silently read as AS-FOO*
		{"AS1~+", "~+(AS1)"},
		{"AS1~{2,3}", "~{2,3}(AS1)"},
		{"AS1{2}", "{2,2}(AS1)"},
		{"AS1{2,}", "{2,}(AS1)"},
		{"^PeerAS+ AS-FOO*$", "seq(^ +(PeerAS) *(AS-FOO) $)"},
		{"AS1$|AS2$", "alt(seq(AS1 $) seq(AS2 $))"}, // anchors inside branches
		{"(^AS1|AS2)", "alt(seq(^ AS1) AS2)"},
		{"AS8726:AS-PEERING:PeerAS$", "seq(tpl:AS8726:AS-PEERING:PeerAS $)"},
		{"3333 AS1.10", "seq(AS3333 AS65546)"},
		{"", "seq()"},
	}
	for _, c := range cases {
		re, err := ParseASPathRegexp(c.in)
		if err != nil {
			t.Errorf("ParseASPathRegexp(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got := renderRE(re.Body); got != c.want {
			t.Errorf("ParseASPathRegexp(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestParseASPathRegexpErrors(t *testing.T) {
	for _, in := range []string{
		"((", "AS1{", "AS1{x}", ")",
		"AS1 # AS2", // unknown byte: was silently skipped
		"[]", "[^]", "[AS1", "[(AS1)]", "[AS1 $]",
		"[AS10-AS1]", "[AS10 - AS1]", "[AS-FOO - AS2]", // bad ranges
		"AS1 - AS2",     // a range outside [...]
		"AS1~", "AS1~?", // ~ needs *, + or {m,n}
		"AS1{5,2}", // min > max
		"^*", "$+", // quantified anchor
		"PeerAS:PeerAS",
	} {
		if re, err := ParseASPathRegexp(in); err == nil {
			t.Errorf("ParseASPathRegexp(%q) = %s, want error", in, renderRE(re.Body))
		}
	}
}

// renderRE writes an AS-path regexp AST as a compact S-expression so tests can
// compare against hand-written literals.
func renderRE(e ASPathExpr) string {
	join := func(es []ASPathExpr) string {
		parts := make([]string, len(es))
		for i, x := range es {
			parts[i] = renderRE(x)
		}
		return strings.Join(parts, " ")
	}
	switch x := e.(type) {
	case ASPathSeq:
		return "seq(" + join(x.Terms) + ")"
	case ASPathAlt:
		return "alt(" + join(x.Alts) + ")"
	case ASPathRepeat:
		op := map[RepeatOp]string{RepeatStar: "*", RepeatPlus: "+", RepeatQuest: "?"}[x.Op]
		if x.Op == RepeatRange {
			op = "{" + strconv.Itoa(x.Min) + ","
			if x.Max >= 0 {
				op += strconv.Itoa(x.Max)
			}
			op += "}"
		}
		if x.Same {
			op = "~" + op
		}
		return op + "(" + renderRE(x.Inner) + ")"
	case ASPathClass:
		neg := ""
		if x.Negated {
			neg = "^ "
		}
		return "[" + neg + join(x.Items) + "]"
	case ASPathASNRange:
		return x.Lo.String() + "-" + x.Hi.String()
	case ASPathASN:
		return x.AS.String()
	case ASPathSet:
		return x.Name.Canonical()
	case ASPathSetTemplate:
		return "tpl:" + x.Template.String()
	case ASPathPeerAS:
		return "PeerAS"
	case ASPathAny:
		return "."
	case ASPathStart:
		return "^"
	case ASPathEnd:
		return "$"
	case nil:
		return "<nil>"
	default:
		return fmt.Sprintf("<%T>", e)
	}
}

// The policy parser attaches the parsed regexp and still preserves Raw.
func TestFilterPathREIntegration(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept <^AS1+ AS2*$>")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	re, ok := f.Filter.(FilterPathRE)
	if !ok {
		t.Fatalf("filter = %T, want FilterPathRE", f.Filter)
	}
	if re.Raw != "^AS1+ AS2*$" {
		t.Errorf("Raw = %q", re.Raw)
	}
	if re.Regexp == nil || renderRE(re.Regexp.Body) != "seq(^ +(AS1) *(AS2) $)" {
		t.Errorf("Regexp = %+v, want seq(^ +(AS1) *(AS2) $)", re.Regexp)
	}
}

// A malformed regexp body yields a non-fatal diagnostic but keeps Raw.
func TestFilterPathREMalformed(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept <((>")
	f := factor(t, imp.Expr)
	re := f.Filter.(FilterPathRE)
	if re.Raw != "((" {
		t.Errorf("Raw = %q, want ((", re.Raw)
	}
	if re.Regexp != nil {
		t.Errorf("Regexp = %+v, want nil on parse failure", re.Regexp)
	}
	if len(diags) != 1 || diags[0].Rule != "policy/as-path-regexp" {
		t.Errorf("diags = %+v, want one policy/as-path-regexp", diags)
	}
}

func FuzzParseASPathRegexp(f *testing.F) {
	for _, s := range []string{
		"^AS1+ AS2*$", ".", "AS-FOO", "AS1|AS2", "(AS1 AS2)+",
		"AS1{2,4}", "AS1{2,}", "3333", "", "((", "{}", "|||", "AS1.10",
		strings.Repeat("(", 2000) + "AS1" + strings.Repeat(")", 2000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Nothing may be skipped: an accepted regexp consists only of bytes the
		// grammar gives meaning to.
		if _, err := ParseASPathRegexp(s); err == nil {
			if rest := strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:_-.^$*+?|(){}[],~ \t\r\n"); rest != "" {
				t.Fatalf("ParseASPathRegexp(%q) accepted meaningless bytes %q", s, rest)
			}
		}
	})
}
