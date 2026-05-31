package policy

import (
	"strings"
	"testing"
)

func TestParseASPathRegexpBasic(t *testing.T) {
	re, err := ParseASPathRegexp("^AS1+ AS2*$")
	if err != nil {
		t.Fatalf("ParseASPathRegexp: %v", err)
	}
	if !re.AnchorStart || !re.AnchorEnd {
		t.Errorf("anchors = (%v,%v), want (true,true)", re.AnchorStart, re.AnchorEnd)
	}
	seq, ok := re.Body.(ASPathSeq)
	if !ok || len(seq.Terms) != 2 {
		t.Fatalf("body = %T %+v, want 2-term ASPathSeq", re.Body, re.Body)
	}
	r0, ok := seq.Terms[0].(ASPathRepeat)
	if !ok || r0.Op != RepeatPlus {
		t.Fatalf("term0 = %+v, want Plus repeat", seq.Terms[0])
	}
	if a, ok := r0.Inner.(ASPathASN); !ok || a.AS != 1 {
		t.Errorf("term0 inner = %+v, want AS1", r0.Inner)
	}
	r1, ok := seq.Terms[1].(ASPathRepeat)
	if !ok || r1.Op != RepeatStar {
		t.Fatalf("term1 = %+v, want Star repeat", seq.Terms[1])
	}
	if a, ok := r1.Inner.(ASPathASN); !ok || a.AS != 2 {
		t.Errorf("term1 inner = %+v, want AS2", r1.Inner)
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

func TestParseASPathRegexpErrors(t *testing.T) {
	for _, in := range []string{"((", "AS1{", "AS1{x}", ")"} {
		if _, err := ParseASPathRegexp(in); err == nil {
			t.Errorf("ParseASPathRegexp(%q) = nil err, want error", in)
		}
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
	if re.Regexp == nil || !re.Regexp.AnchorStart || !re.Regexp.AnchorEnd {
		t.Errorf("Regexp not parsed with anchors: %+v", re.Regexp)
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
		_, _ = ParseASPathRegexp(s)
	})
}
