package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// String is canonical: one spelling per meaning, with parentheses only where
// precedence needs them.
func TestFilterString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ANY", "ANY"},
		{"PeerAS", "PeerAS"},
		{"PeerAS^+", "PeerAS^+"},
		{"AS65000", "AS65000"},
		{"as-foo", "AS-FOO"},      // set names canonicalize
		{"AS1 AS2", "AS1 OR AS2"}, // implicit OR is written out
		{"AS1 OR AS2", "AS1 OR AS2"},
		{"as1 or AS2 or aS3", "AS1 OR AS2 OR AS3"}, // a chain stays flat
		{"AS1 AND AS2 AND AS3", "AS1 AND AS2 AND AS3"},
		{"AS1 AND AS2 OR AS3", "AS1 AND AS2 OR AS3"}, // AND binds tighter
		{"(AS1 OR AS2) AND AS3", "(AS1 OR AS2) AND AS3"},
		{"NOT AS1", "NOT AS1"},
		{"NOT (AS1 OR AS2)", "NOT (AS1 OR AS2)"},
		{"NOT AS1 AND AS2", "NOT AS1 AND AS2"},
		{"{ 5.0.0.0/8, 6.0.0.0/8 }", "{5.0.0.0/8, 6.0.0.0/8}"},
		{"{}", "{}"},
		{"{1.0.0.0/8}^+", "{1.0.0.0/8^+}"}, // an outer operator composes in
		{"AS1^24", "AS1^24"},
		{"AS1^24-28", "AS1^24-28"},
		{"rs-foo^+", "RS-FOO^+"},
		{"community(65000:1)", "community(65000:1)"},
		{"community.contains(65000:1)", "community(65000:1)"},
		{"community == {65000:1}", "community == {65000:1}"},
		{"<^AS1+$>", "<^AS1+$>"},
		{"AS1:AS-CUSTOMERS:PeerAS", "AS1:AS-CUSTOMERS:PeerAS"},
	}
	for _, c := range cases {
		f, ds := ParseFilter(c.in)
		clean(t, "ParseFilter("+c.in+")", ds)
		if got := exprText(f); got != c.want {
			t.Errorf("ParseFilter(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPeeringAndExprString(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"AS65000", "AS65000"},
		{"as1 or as2", "AS1 OR AS2"},
		{"AS1 AND AS2 OR AS3", "AS1 AND AS2 OR AS3"},
		{"(AS1 OR AS2) EXCEPT AS3", "(AS1 OR AS2) EXCEPT AS3"},
		{"AS1 192.0.2.1", "AS1 192.0.2.1"},
		{"AS1 at 192.0.2.1", "AS1 at 192.0.2.1"},
		{"AS1 rtr.example.net at 192.0.2.1", "AS1 rtr.example.net at 192.0.2.1"},
		{"AS1 rtrs-foo", "AS1 RTRS-FOO"},
		{"prng-example", "PRNG-EXAMPLE"},
		{"<^AS1$>", "<^AS1$>"},
	} {
		pe, ds := ParsePeering(c.in)
		clean(t, "ParsePeering("+c.in+")", ds)
		if got := exprText(pe); got != c.want {
			t.Errorf("ParsePeering(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestActionString(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"pref = 10", "pref = 10"},
		{"pref=10", "pref = 10"},
		{"PREF   =   10", "pref = 10"},
		{"community .= {1:2}", "community .= {1:2}"},
		{"community.append(1:2)", "community.append(1:2)"},
		{"community.append(1:2, 3:4)", "community.append(1:2, 3:4)"},
		{"aspath.prepend(AS1, AS2)", "aspath.prepend(AS1, AS2)"},
		{"med += 5", "med += 5"},
		{"med <<= 5", "med <<= 5"},
	} {
		a, msg := parseAction(c.in)
		if msg != "" {
			t.Fatalf("parseAction(%q): %s", c.in, msg)
		}
		if got := a.String(); got != c.want {
			t.Errorf("parseAction(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestInjectCondString(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"upon STATIC", "STATIC"},
		{"upon HAVE-COMPONENTS {10.0.0.0/8}", "HAVE-COMPONENTS {10.0.0.0/8}"},
		{"upon EXCLUDE {10.0.0.0/8, 11.0.0.0/8}", "EXCLUDE {10.0.0.0/8, 11.0.0.0/8}"},
		{"upon STATIC AND NOT STATIC", "STATIC AND NOT STATIC"},
		{"upon STATIC OR STATIC AND STATIC", "STATIC OR STATIC AND STATIC"},
		{"upon (STATIC OR STATIC) AND STATIC", "(STATIC OR STATIC) AND STATIC"},
		{"upon NOT (STATIC OR STATIC)", "NOT (STATIC OR STATIC)"},
	} {
		in, ds := ParseInject(c.in)
		clean(t, "ParseInject("+c.in+")", ds)
		if got := exprText(in.Upon); got != c.want {
			t.Errorf("ParseInject(%q).Upon.String() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIfaddrAndPeerOptionString(t *testing.T) {
	v, ds := ParseIfaddr("1.1.1.1   masklen   30   action   mtu=1500;")
	clean(t, "ifaddr", ds)
	if got, want := v.String(), "1.1.1.1 masklen 30 action mtu = 1500;"; got != want {
		t.Errorf("Ifaddr.String() = %q, want %q", got, want)
	}
	p, ds := ParsePeer("BGP4 192.0.2.1 asno( AS2 ), flap_damp()")
	clean(t, "peer", ds)
	if got, want := p.Options[0].String(), "asno(AS2)"; got != want {
		t.Errorf("PeerOption.String() = %q, want %q", got, want)
	}
	if got, want := p.Options[1].String(), "flap_damp()"; got != want {
		t.Errorf("PeerOption.String() = %q, want %q", got, want)
	}
}

// Rendering is a fixpoint: parsing a rendered value gives the same AST, and
// rendering it again gives the same text. Checked over every policy example the
// RFCs contain, so the property is exercised on real grammar rather than on
// shapes chosen to pass.
func TestStringRoundTripsOverRFCExamples(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rfc-examples.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type parsed struct {
		value any
		diags []ast.Diagnostic
	}
	parsers := map[string]func(string) parsed{
		"filter":     func(v string) parsed { x, d := ParseFilter(v); return parsed{x, d} },
		"mp-filter":  func(v string) parsed { x, d := ParseFilter(v); return parsed{x, d} },
		"peering":    func(v string) parsed { x, d := ParsePeering(v); return parsed{x, d} },
		"mp-peering": func(v string) parsed { x, d := ParsePeering(v); return parsed{x, d} },
		"import":     func(v string) parsed { x, d := ParseImport(v); return parsed{x, d} },
		"export":     func(v string) parsed { x, d := ParseExport(v); return parsed{x, d} },
		"default":    func(v string) parsed { x, d := ParseDefault(v); return parsed{x, d} },
		"mp-import":  func(v string) parsed { x, d := ParseMPImport(v); return parsed{x, d} },
		"mp-export":  func(v string) parsed { x, d := ParseMPExport(v); return parsed{x, d} },
		"mp-default": func(v string) parsed { x, d := ParseMPDefault(v); return parsed{x, d} },
	}
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		example, _, _ := strings.Cut(line, " ## expect:")
		attr, value, _ := strings.Cut(example, ":")
		parse := parsers[attr]
		if parse == nil {
			continue
		}
		first := parse(strings.TrimSpace(value))
		if len(first.diags) != 0 {
			continue // the parser rejects it on purpose; nothing to render
		}
		text := exprText(first.value)
		again := parse(text)
		if len(again.diags) != 0 {
			t.Errorf("%s: rendered as %q, which does not re-parse: %v", example, text, again.diags)
			continue
		}
		if got := exprText(again.value); got != text {
			t.Errorf("%s: rendered as %q, re-rendered as %q", example, text, got)
			continue
		}
		if a, b := render(first.value), render(again.value); a != b {
			t.Errorf("%s: re-parsing %q changed the AST:\n %s\n %s", example, text, a, b)
		}
		n++
	}
	if n < 100 {
		t.Errorf("only %d examples round-tripped", n)
	}
}

// FuzzFilterString: whatever a filter parses to, rendering it and parsing that
// again is a fixpoint — the second parse is clean and renders identically.
func FuzzFilterString(f *testing.F) {
	for _, s := range []string{
		"ANY", "AS1 AS2", "AS1 AND NOT AS2", "(AS1 OR AS2) AND AS3",
		"{1.0.0.0/8^+}", "community(1:2)", "<^AS1$>", "rs-foo^24-28",
		"NOT NOT AS1", "AS1:AS-X:PeerAS^+",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, ds := ParseFilter(s)
		if len(ds) != 0 || flt == nil {
			return // only clean parses have a meaning to preserve
		}
		text := exprText(flt)
		again, ds2 := ParseFilter(text)
		if len(ds2) != 0 {
			t.Fatalf("ParseFilter(%q) rendered %q, which does not re-parse: %v", s, text, ds2)
		}
		if got := exprText(again); got != text {
			t.Fatalf("ParseFilter(%q) rendered %q, re-rendered %q", s, text, got)
		}
		if a, b := render(flt), render(again); a != b {
			t.Fatalf("ParseFilter(%q): re-parsing %q changed the AST:\n %s\n %s", s, text, a, b)
		}
	})
}
