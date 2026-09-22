package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Input the RFC grammar does not allow is diagnosed rather than accepted; each
// of these parsed clean before.
func TestPolicyStrictness(t *testing.T) {
	cases := []struct {
		name  string
		parse func() []ast.Diagnostic
		want  []string // diagnostic rules, in order
	}{
		// AS-path regexp delimiters.
		{"unterminated-regexp", imp("from AS1 accept <^AS1 AS2"), []string{"policy/as-path-regexp"}},
		{"stray-gt", imp("from AS1 accept AS1 > AS2"), []string{"policy/as-path-regexp"}},
		{"stray-gt-peering", func() []ast.Diagnostic { _, d := ParsePeering("AS1 >"); return d },
			[]string{"policy/as-path-regexp"}},

		// Actions: attr = value, attr .= value, or attr.method(args), one per ';'.
		{"two-assignments", imp("from AS1 action pref=10 med=20; accept ANY"), []string{"policy/action"}},
		{"two-calls", imp("from AS1 action community.append(1:2) aspath.prepend(AS1); accept ANY"),
			[]string{"policy/action"}},
		{"comparison", imp("from AS1 action pref==10; accept ANY"), []string{"policy/action"}},
		{"bare-word", imp("from AS1 action foo; accept ANY"), []string{"policy/action"}},
		{"no-value", imp("from AS1 action pref = ; accept ANY"), []string{"policy/action"}},
		{"call-without-method", imp("from AS1 action community(1:2); accept ANY"), []string{"policy/action"}},
		{"bad-attr", imp("from AS1 action 9pref = 1; accept ANY"), []string{"policy/action"}},
		{"bad-action-keeps-good-ones", imp("from AS1 action pref = 1; foo; med = 2; accept ANY"),
			[]string{"policy/action"}},
	}
	for _, c := range cases {
		if got := diagRules(c.parse()); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: diagnostics = %v, want %v", c.name, got, c.want)
		}
	}
}

// The action forms of RFC 2622 §6.1.1 and §7 parse clean, the Figure 25
// operators other than = and .= as the operator methods they are.
func TestActionForms(t *testing.T) {
	as := actions(t, "from AS1 action pref = 10; med=igp_cost; community .= { 70 }; community={1:2,3:4};"+
		" community.append(10250, 3561:10); aspath.prepend (AS1, AS1); med += 5; next-hop = 192.0.2.1 accept ANY")
	want := []Action{
		{Attr: "pref", Op: ActionAssign, Value: "10", Raw: "pref = 10"},
		{Attr: "med", Op: ActionAssign, Value: "igp_cost", Raw: "med=igp_cost"},
		{Attr: "community", Op: ActionAppend, Value: "{ 70 }", Raw: "community .= { 70 }"},
		{Attr: "community", Op: ActionAssign, Value: "{1:2,3:4}", Raw: "community={1:2,3:4}"},
		{Attr: "community", Method: "append", Op: ActionMethod, Args: []string{"10250", "3561:10"},
			Raw: "community.append(10250, 3561:10)"},
		{Attr: "aspath", Method: "prepend", Op: ActionMethod, Args: []string{"AS1", "AS1"},
			Raw: "aspath.prepend (AS1, AS1)"},
		{Attr: "med", Method: "operator+=", Op: ActionMethod, Args: []string{"5"}, Raw: "med += 5"},
		{Attr: "next-hop", Op: ActionAssign, Value: "192.0.2.1", Raw: "next-hop = 192.0.2.1"},
	}
	if !reflect.DeepEqual(as, want) {
		t.Errorf("actions =\n%+v\nwant\n%+v", as, want)
	}
	imp, _ := ParseImport("from AS1 action pref = 1; foo; med = 2; accept ANY")
	if got := factor(t, imp.Expr).Peers[0].Actions; len(got) != 2 || got[0].Attr != "pref" || got[1].Attr != "med" {
		t.Errorf("actions around a bad one = %+v, want pref and med", got)
	}
}

// Past the diagnostic cap in the delimiter check the parser stays in bounds.
func TestManyStrayDelimiters(t *testing.T) {
	_, diags := ParseImport("from AS1 accept ANY " + strings.Repeat("> ", 500))
	if n := len(diags); n != maxDiagnostics+1 || diags[n-1].Rule != "policy/too-many-errors" {
		t.Errorf("%d diagnostics, last %v; want %d ending in policy/too-many-errors", n, diagRules(diags[n-1:]), maxDiagnostics+1)
	}
}

// An action diagnostic says what is wrong.
func TestActionMessages(t *testing.T) {
	for in, want := range map[string]string{
		"pref==10":                 `"==" compares`,
		"pref=10 med=20":           `expected ';' before "med=20"`,
		"community.append(1) x(2)": `expected ';' after "community.append(1)"`,
		"foo":                      "expected 'attr = value'",
		"pref =":                   "action has no value",
		"med <<= 1":                "",
	} {
		_, diags := ParseImport("from AS1 action " + in + "; accept ANY")
		switch {
		case want == "" && len(diags) != 0:
			t.Errorf("%q: diagnostics %+v, want none", in, diags)
		case want != "" && (len(diags) != 1 || !strings.Contains(diags[0].Message, want)):
			t.Errorf("%q: diagnostics %+v, want one containing %q", in, diags, want)
		}
	}
}

// community == {…} (RFC 2622 §7, operator==) matches routes carrying exactly
// those communities.
func TestCommunityEquals(t *testing.T) {
	for _, in := range []string{"community == {3561:70, NO_EXPORT}", "community=={3561:70,NO_EXPORT}",
		"COMMUNITY == { 3561:70, NO_EXPORT }"} {
		f, diags := ParseFilter(in)
		c, ok := f.(FilterCommunity)
		if len(diags) != 0 || !ok || c.Op != CommunityEquals ||
			!reflect.DeepEqual(c.Values, []string{"3561:70", "NO_EXPORT"}) || c.Raw != in {
			t.Errorf("ParseFilter(%q) = %+v, %v; want CommunityEquals [3561:70 NO_EXPORT]", in, f, diagRules(diags))
		}
	}
	f, diags := ParseFilter("AS1 AND NOT community == {70}")
	if a, ok := f.(FilterAnd); len(diags) != 0 || !ok || len(a.Terms) != 2 {
		t.Errorf("combined filter = %+v, %v", f, diagRules(diags))
	}
	for _, in := range []string{"community == 70", "community == {70", "community = {70}", "community == {70} ^+"} {
		if _, diags := ParseFilter(in); len(diags) == 0 {
			t.Errorf("ParseFilter(%q): no diagnostic", in)
		}
	}
}

// An AS-path regexp term is an AS number, an as-set (or as-set template) or
// PeerAS (RFC 2622 §5.4); any other set is an error.
func TestASPathTerms(t *testing.T) {
	for _, ok := range []string{"AS1", "AS-FOO", "AS1:AS-X:PeerAS", "PeerAS", "[AS1 AS-FOO PeerAS]", "^$"} {
		if _, err := ParseASPathRegexp(ok); err != nil {
			t.Errorf("ParseASPathRegexp(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"RS-FOO", "FLTR-X", "AS1:RS-X:PeerAS", "[AS1 RTRS-X]", "", "  "} {
		if _, err := ParseASPathRegexp(bad); err == nil {
			t.Errorf("ParseASPathRegexp(%q): no error", bad)
		}
	}
	if got := diagRules(imp("from AS1 accept <>")()); !reflect.DeepEqual(got, []string{"policy/as-path-regexp"}) {
		t.Errorf("empty regexp: diagnostics = %v", got)
	}
}

// A regexp diagnostic points at the offending token, not the whole <…>; a
// bare number, which RFC 2622 writes AS3333, is read as that AS with a Warning.
func TestASPathDiagnosticSpans(t *testing.T) {
	for _, c := range []struct {
		in         string
		sev        ast.Severity
		start, end int
	}{
		{"from AS1 accept <AS1 RS-FOO>", ast.Error, 21, 27},
		{"from AS1 accept <AS1 ~ AS2>", ast.Error, 21, 22},
		{"from AS1 accept <^3333$>", ast.Warning, 18, 22},
		{"from AS1 accept <[AS1 - AS2 3333]>", ast.Warning, 28, 32},
		{"from AS1 accept <(AS1>", ast.Error, 21, 22}, // the missing ')' is due at the '>'
	} {
		_, diags := ParseImport(c.in)
		if len(diags) != 1 || diags[0].Rule != "policy/as-path-regexp" || diags[0].Severity != c.sev ||
			diags[0].Span.StartByte != c.start || diags[0].Span.EndByte != c.end {
			t.Errorf("%q: diagnostics = %+v, want one %v policy/as-path-regexp at bytes %d-%d",
				c.in, diags, c.sev, c.start, c.end)
		}
	}
	f, _ := ParseFilter("<^3333$>")
	if re := f.(FilterPathRE).Regexp; re == nil || !reflect.DeepEqual(re.Body,
		ASPathSeq{Terms: []ASPathExpr{ASPathStart{}, ASPathASN{AS: 3333}, ASPathEnd{}}}) {
		t.Errorf("<^3333$> = %+v, want ^ AS3333 $", re)
	}
}

// The remaining gaps: each input is diagnosed with the given rules and
// severities, in order.
func TestPolicyLeftovers(t *testing.T) {
	type d struct {
		rule string
		sev  ast.Severity
	}
	E, W := ast.Error, ast.Warning
	dflt := func(s string) func() []ast.Diagnostic {
		return func() []ast.Diagnostic { _, d := ParseDefault(s); return d }
	}
	mpImp := func(s string) func() []ast.Diagnostic {
		return func() []ast.Diagnostic { _, d := ParseMPImport(s); return d }
	}
	for _, c := range []struct {
		name  string
		parse func() []ast.Diagnostic
		want  []d
	}{
		{"empty-braces", imp("{ }"), []d{{"policy/empty", W}}},
		{"empty-braces-except", imp("from AS1 accept ANY except { }"), []d{{"policy/empty", W}}},
		{"legacy-afi", imp("afi ipv6.unicast from AS1 accept ANY"), []d{{"policy/afi", E}}},
		{"legacy-afi-except", imp("from AS1 accept ANY except afi ipv4 from AS2 accept ANY"), []d{{"policy/afi", E}}},
		{"legacy-afi-default", dflt("afi ipv4.unicast to AS1"), []d{{"policy/afi", E}}},
		{"mp-afi-ok", mpImp("afi ipv6.unicast from AS1 accept ANY except afi ipv6 from AS2 accept ANY"), nil},
		{"prefix-list-no-comma", imp("from AS1 accept {192.0.2.0/24 198.51.100.0/24}"), []d{{"policy/prefix-list", E}}},
		{"prefix-list-empty-item", imp("from AS1 accept {192.0.2.0/24,,198.51.100.0/24}"), []d{{"policy/prefix-list", W}}},
		{"prefix-list-trailing-comma", imp("from AS1 accept {192.0.2.0/24,}"), []d{{"policy/prefix-list", W}}},
		{"prefix-list-empty-ok", imp("from AS1 accept {}"), nil},
		{"protocol-without-name", imp("protocol from AS1 accept ANY"), []d{{"policy/protocol", E}}},
		{"into-without-name", imp("protocol BGP4 into from AS1 accept ANY"), []d{{"policy/protocol", E}}},
		{"not-in-as-expr", imp("from AS-FOO and not AS2 accept ANY"), []d{{"policy/as-expr", E}}},
		{"not-in-router-expr", imp("from AS1 at not 7.7.7.1 accept ANY"), []d{{"policy/router", E}}},
	} {
		var got []d
		for _, x := range c.parse() {
			got = append(got, d{x.Rule, x.Severity})
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: diagnostics = %v, want %v", c.name, got, c.want)
		}
	}
	// The messages point to what to write instead.
	for in, want := range map[string]string{
		"from AS-FOO and not AS2 accept ANY":        "EXCEPT",
		"from AS1 at not 7.7.7.1 accept ANY":        "EXCEPT",
		"afi ipv6.unicast from AS1 accept ANY":      "mp-import",
		"protocol from AS1 accept ANY":              "protocol name",
		"from AS1 accept {192.0.2.0/24 10.0.0.0/8}": "','",
	} {
		if _, diags := ParseImport(in); len(diags) != 1 || !strings.Contains(diags[0].Message, want) {
			t.Errorf("%q: diagnostics %+v, want a message mentioning %q", in, diags, want)
		}
	}
	// A legacy import with an afi clause applies to IPv4 unicast, as without it.
	if im, _ := ParseImport("afi ipv6.unicast from AS1 accept ANY"); len(im.AFIs) != 0 {
		t.Errorf("legacy import kept afi %v", im.AFIs)
	}
}
