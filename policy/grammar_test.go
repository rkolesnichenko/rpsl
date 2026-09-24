package policy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// The tests in this file compare parsed ASTs against hand-written renderings
// (see renderExpr and friends) so every expectation is an independent literal.

func TestPolicyGrammar(t *testing.T) {
	cases := []struct {
		name     string
		parse    func(string) (Import, []ast.Diagnostic)
		in, want string
	}{
		// Structured policy (RFC 2622 §6.6): the factor-terminating ';' before
		// except/refine, and right-to-left evaluation.
		{"rfc2622-6.6-example", ParseImport,
			"from AS1 action pref = 1; accept as-foo; except { from AS2 action pref = 2; accept AS226; " +
				"except { from AS3 action pref = 3; accept {128.9.0.0/16}; } }",
			"except(F[AS1{pref} : AS-FOO], {except(F[AS2{pref} : AS226], {F[AS3{pref} : {128.9.0.0/16}]})})"},
		{"right-assoc", ParseImport,
			"from AS1 accept ANY except {from AS2 accept AS2} refine {from AS3 accept AS3}",
			"except(F[AS1 : ANY], refine({F[AS2 : AS2]}, {F[AS3 : AS3]}))"},
		{"rfc4012-afi-except", ParseMPImport,
			"afi any.unicast from AS1 accept ANY; except afi ipv6.unicast { from AS2 accept AS2; }",
			"except[ipv6.unicast](F[AS1 : ANY], {F[AS2 : AS2]})"},
		{"brace-list", ParseImport, "{ from AS1 accept AS1; from AS2 accept AS2 }", "{F[AS1 : AS1]; F[AS2 : AS2]}"},
		{"trailing-semicolon", ParseImport, "from AS1 accept ANY;", "F[AS1 : ANY]"},
		{"multi-peering", ParseImport, "from AS1 action pref=100; from AS2 accept AS-FOO", "F[AS1{pref}; AS2 : AS-FOO]"},

		// Implicit OR (RFC 2622 §5.4): "x y" is "x OR y", at OR precedence.
		{"implicit-or", ParseImport, "from AS1 accept AS226 AS227 OR AS228", "F[AS1 : or(AS226 AS227 AS228)]"},
		{"implicit-or-vs-and", ParseImport, "from AS1 accept AS1 AS2 AND AS3", "F[AS1 : or(AS1 and(AS2 AS3))]"},
		{"implicit-or-parens", ParseImport, "from AS1 accept (AS1 AS2)", "F[AS1 : or(AS1 AS2)]"},
		{"implicit-or-not", ParseImport, "from AS1 accept NOT (AS20965 AS1299)", "F[AS1 : not(or(AS20965 AS1299))]"},
		{"implicit-or-prefixes", ParseImport, "from AS1 accept ANY {0.0.0.0/0^25-32}", "F[AS1 : or(ANY {0.0.0.0/0^25-32})]"},
		{"explicit-precedence", ParseImport, "from AS1 accept AS1 AND AS2 OR AS3", "F[AS1 : or(and(AS1 AS2) AS3)]"},
		// A term followed by '(' is an implicit OR with a group, never a method call.
		{"implicit-or-group", ParseImport, "from AS1 accept AS1 (AS2 OR AS3)", "F[AS1 : or(AS1 or(AS2 AS3))]"},
		{"implicit-or-set-group", ParseImport, "from AS1 accept AS-FOO (AS1)", "F[AS1 : or(AS-FOO AS1)]"},
		{"implicit-or-peeras-group", ParseImport, "from AS1 accept PeerAS (AS2)", "F[AS1 : or(PeerAS AS2)]"},
		{"implicit-or-asdot-group", ParseImport, "from AS1 accept AS1.10 (AS2)", "F[AS1 : or(AS65546 AS2)]"},
		{"ripe-filter-set", ParseImport,
			"from AS1 accept AS25229:AS-CUST AS25229:RS-DOMESTIC (AS-PACO-TO-UAIX AND <^AS8207>) (AS-SET-DCS AND <^AS35412>)",
			"F[AS1 : or(AS25229:AS-CUST AS25229:RS-DOMESTIC and(AS-PACO-TO-UAIX <seq(^ AS8207)>) " +
				"and(AS-SET-DCS <seq(^ AS35412)>))]"},
		// The filter methods of RFC 2622 §7: community(...) and community.contains(...).
		{"community", ParseImport, "from AS1 accept community(65000:1) AND AS1",
			"F[AS1 : and(community(65000:1) AS1)]"},
		{"community-contains", ParseImport, "from AS1 accept NOT Community.contains(65000:1, 65000:2)",
			"F[AS1 : not(Community.contains(65000:1, 65000:2))]"},

		// Range operators on filter terms (RFC 2622 §5.4) and prefix-list
		// composition (RFC 2622 §5.2 examples).
		{"op-as-set", ParseImport, "from AS1 accept AS-FOO^+", "F[AS1 : AS-FOO^+]"},
		{"op-mixed", ParseImport, "from AS1 accept RS-X^24 OR AS1^- OR PeerAS^0-32",
			"F[AS1 : or(RS-X^24 AS1^- PeerAS^0-32)]"},
		{"op-prefix-list", ParseImport, "from AS1 accept {10.0.0.0/8, 11.0.0.0/8}^+",
			"F[AS1 : {10.0.0.0/8^+, 11.0.0.0/8^+}]"},
		{"op-compose-range", ParseImport, "from AS1 accept {128.9.0.0/16^20-24}^26-28", "F[AS1 : {128.9.0.0/16^26-28}]"},
		{"op-compose-minus", ParseImport, "from AS1 accept {128.9.0.0/16^+}^-", "F[AS1 : {128.9.0.0/16^-}]"},
		// {10.0.0.0/8^24}^16, which deletes the range, is in TestPrefixListOpEmptyWarns.

		// PeerAS inside set names (decision 1).
		{"tpl-filter", ParseImport, "from AS8821:AS-CUSTOMERS accept AS8821:AS-CUSTOMERS:PeerAS",
			"F[AS8821:AS-CUSTOMERS : tpl:AS8821:AS-CUSTOMERS:PeerAS]"},
		{"tpl-filter-op", ParseImport, "from AS1 accept PeerAS:AS-TO-GRNET^0-32", "F[AS1 : tpl:PeerAS:AS-TO-GRNET^0-32]"},
		{"tpl-route-set", ParseImport, "from AS1 accept AS1:RS-X:PeerAS", "F[AS1 : settpl:AS1:RS-X:PeerAS]"},
		{"tpl-peering", ParseImport, "from AS-ARAX:AS-TRANSIT:PeerAS accept ANY", "F[tpl:AS-ARAX:AS-TRANSIT:PeerAS : ANY]"},
		{"tpl-regexp", ParseImport, "from AS1 accept <AS8726:AS-PEERING:PeerAS$>",
			"F[AS1 : <seq(tpl:AS8726:AS-PEERING:PeerAS $)>]"},

		// Peering AS-expressions (RFC 2622 §5.6): EXCEPT binds like AND, OR lowest.
		{"as-and", ParseImport, "from AS-FOO AND AS2 accept ANY", "F[and(AS-FOO AS2) : ANY]"},
		{"as-parens-lower", ParseImport, "from (AS42 or AS3856) action pref=100; accept AS-PCH",
			"F[or(AS42 AS3856){pref} : AS-PCH]"},
		{"as-precedence", ParseImport, "from AS1 OR AS2 AND AS3 accept ANY", "F[or(AS1 and(AS2 AS3)) : ANY]"},
		{"as-except-precedence", ParseImport, "from AS1 EXCEPT AS2 OR AS3 accept ANY", "F[or(except(AS1 AS2) AS3) : ANY]"},
		{"as-except", ParseImport, "from AS-FOO EXCEPT AS3 accept ANY", "F[except(AS-FOO AS3) : ANY]"},
		{"routers", ParseImport, "from AS1 192.0.2.1 at 192.0.2.2 accept ANY", "F[AS1 192.0.2.1 at 192.0.2.2 : ANY]"},
		{"router-exprs", ParseImport, "from AS1 rtrs-a AND rtrs-b at 1.1.1.1 EXCEPT 1.1.1.2 accept ANY",
			"F[AS1 and(RTRS-A RTRS-B) at except(1.1.1.1 1.1.1.2) : ANY]"},
		{"at-only", ParseImport, "from AS1 at rtrs-foo accept ANY", "F[AS1 at RTRS-FOO : ANY]"},
		{"peering-set", ParseImport, "from prng-foo accept ANY", "F[PRNG-FOO : ANY]"},
	}
	for _, c := range cases {
		imp, diags := c.parse(c.in)
		if len(diags) != 0 {
			t.Errorf("%s: unexpected diagnostics %s", c.name, diagRules(diags))
		}
		if got := renderExpr(imp.Expr); got != c.want {
			t.Errorf("%s: %q\n  got  %s\n  want %s", c.name, c.in, got, c.want)
		}
	}
}

func TestExportAndDefaultGrammar(t *testing.T) {
	exp, diags := ParseExport("to AS1 announce AS-FOO AS-BAR")
	if len(diags) != 0 || renderExpr(exp.Expr) != "F[AS1 : or(AS-FOO AS-BAR)]" {
		t.Errorf("export = %s %s", renderExpr(exp.Expr), diagRules(diags))
	}
	d, diags := ParseDefault("to AS1 action pref=10; networks ANY {10.0.0.0/8}")
	if len(diags) != 0 || renderFilter(d.Networks) != "or(ANY {10.0.0.0/8})" {
		t.Errorf("default networks = %s %s", renderFilter(d.Networks), diagRules(diags))
	}
}

// Every value that is not fully understood must produce a diagnostic: nothing
// may be dropped silently. Each input here parsed "cleanly" before.
func TestPolicyDiagnosesUnparsedInput(t *testing.T) {
	cases := []struct {
		name  string
		parse func() []ast.Diagnostic
		want  []string // diagnostic rules, in order
	}{
		{"trailing-junk", imp("from AS1 accept ANY junk"), []string{"policy/filter"}},
		{"two-bare-factors", imp("from AS1 accept ANY; from AS2 accept ANY"), []string{"policy/trailing"}},
		{"no-filter", imp("from AS1"), []string{"policy/expect-filter"}},
		{"empty", imp(""), []string{"policy/empty"}},
		{"no-peering", imp("accept ANY"), []string{"policy/expect-peering"}},
		{"empty-afi", func() []ast.Diagnostic { _, d := ParseMPImport("afi from AS1 accept ANY"); return d },
			[]string{"policy/afi"}},
		{"dangling-except", imp("from AS1 accept ANY except"), []string{"policy/expect-peering"}},
		{"bad-range-op", imp("from AS1 accept AS-FOO^+24"), []string{"policy/range-op"}},
		{"unclosed-as-paren", imp("from (AS1 OR AS2 accept ANY"), []string{"policy/as-expr"}},
		{"missing-semicolon", imp("{ from AS1 accept AS1 from AS2 accept AS2 }"), []string{"policy/missing-semicolon"}},
		{"default-junk", func() []ast.Diagnostic { _, d := ParseDefault("to AS1 networks ANY junk"); return d },
			[]string{"policy/filter"}},
		{"filter-junk", func() []ast.Diagnostic { _, d := ParseFilter("ANY )"); return d }, []string{"policy/trailing"}},
		{"peering-trailing", func() []ast.Diagnostic { _, d := ParsePeering("AS1 accept"); return d },
			[]string{"policy/trailing"}},
		{"peering-dangling-at", func() []ast.Diagnostic { _, d := ParsePeering("AS1 at"); return d },
			[]string{"policy/peering"}},
		// Methods that modify a route are actions, not filters.
		{"action-method-as-filter", imp("from AS1 accept AS48450 aspath.prepend(AS48450)"),
			[]string{"policy/filter-method"}},
		{"community-append-as-filter", imp("from AS1 accept community.append(65000:1)"),
			[]string{"policy/filter-method"}},
		{"unknown-method", imp("from AS1 accept foo(1)"), []string{"policy/filter-method"}},
		// An unterminated call must not swallow the rest of the value silently.
		{"unterminated-method", imp("from AS1 accept community.contains(1:2 from AS2 accept ANY"),
			[]string{"policy/filter-paren"}},
		{"unterminated-community", imp("from AS1 accept community(1:2"), []string{"policy/filter-paren"}},
		// Host bits are cleared when the prefix is parsed; say so.
		{"prefix-host-bits", imp("from AS1 accept {45.146.49.0/22^24}"), []string{"policy/host-bits"}},
	}
	for _, c := range cases {
		if got := diagRules(c.parse()); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: diagnostics = %v, want %v", c.name, got, c.want)
		}
	}
}

// Missing ';' between structured factors is a Warning (the meaning is clear),
// and both factors are kept.
func TestMissingSemicolonKeepsFactors(t *testing.T) {
	imp, diags := ParseImport("{ from AS1 accept AS1 from AS2 accept AS2 }")
	if len(diags) != 1 || diags[0].Severity != ast.Warning {
		t.Fatalf("diags = %+v, want one warning", diags)
	}
	if got := renderExpr(imp.Expr); got != "{F[AS1 : AS1]; F[AS2 : AS2]}" {
		t.Errorf("expr = %s", got)
	}
}

// Diagnostic columns are 1-based (like every other layer); byte offsets stay
// 0-based so object can rebase them onto the attribute.
func TestPolicyDiagnosticColumns(t *testing.T) {
	_, diags := ParseImport("from AS1 accept garbage!!")
	if len(diags) != 1 {
		t.Fatalf("diags = %+v", diags)
	}
	sp := diags[0].Span
	if sp.StartCol != 17 || sp.EndCol != 26 || sp.StartByte != 16 || sp.EndByte != 25 {
		t.Errorf("span = col %d-%d byte %d-%d, want col 17-26 byte 16-25", sp.StartCol, sp.EndCol, sp.StartByte, sp.EndByte)
	}
}

// Hostile nesting yields exactly one diagnostic, not one per level.
func TestPolicyNestingReportedOnce(t *testing.T) {
	for name, in := range map[string]string{
		"braces":    strings.Repeat("{", 100000) + "from AS1 accept ANY",
		"parens":    "from AS1 accept " + strings.Repeat("(", 100000) + "ANY",
		"nots":      "from AS1 accept " + strings.Repeat("not ", 100000) + "ANY",
		"as-parens": "from " + strings.Repeat("(", 100000) + "AS1 accept ANY",
	} {
		_, diags := ParseImport(in)
		if len(diags) != 1 || diags[0].Rule != "policy/nesting" {
			t.Errorf("%s: %d diagnostics %v, want exactly one policy/nesting", name, len(diags), diagRules(diags)[:min(3, len(diags))])
		}
	}
}

// ---- test helpers ----

func imp(s string) func() []ast.Diagnostic {
	return func() []ast.Diagnostic { _, d := ParseImport(s); return d }
}

func diagRules(ds []ast.Diagnostic) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Rule)
	}
	return out
}

func renderExpr(e Expr) string {
	switch x := e.(type) {
	case Factor:
		peers := make([]string, len(x.Peers))
		for i, pa := range x.Peers {
			peers[i] = renderPeering(pa.Peering)
			if len(pa.Actions) > 0 {
				var attrs []string
				for _, a := range pa.Actions {
					attrs = append(attrs, a.Attr)
				}
				peers[i] += "{" + strings.Join(attrs, ",") + "}"
			}
		}
		return "F[" + strings.Join(peers, "; ") + " : " + renderFilter(x.Filter) + "]"
	case ExprList:
		parts := make([]string, len(x.Exprs))
		for i, s := range x.Exprs {
			parts[i] = renderExpr(s)
		}
		return "{" + strings.Join(parts, "; ") + "}"
	case Except:
		return "except" + renderAFIs(x.AFIs) + "(" + renderExpr(x.Left) + ", " + renderExpr(x.Right) + ")"
	case Refine:
		return "refine" + renderAFIs(x.AFIs) + "(" + renderExpr(x.Left) + ", " + renderExpr(x.Right) + ")"
	case nil:
		return "<nil>"
	}
	return fmt.Sprintf("<%T>", e)
}

func renderAFIs(afis []types.AddrFamily) string {
	if len(afis) == 0 {
		return ""
	}
	parts := make([]string, len(afis))
	for i, a := range afis {
		parts[i] = a.String()
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func renderPeering(p Peering) string {
	switch x := p.(type) {
	case PeeringAS:
		s := renderAS(x.AS)
		if x.Router != nil {
			s += " " + renderRouter(x.Router)
		}
		if x.AtRouter != nil {
			s += " at " + renderRouter(x.AtRouter)
		}
		return s
	case PeeringSetRef:
		return x.Name.String()
	case PeeringRegexp:
		return "<" + x.Raw + ">"
	case nil:
		return "<nil>"
	}
	return fmt.Sprintf("<%T>", p)
}

func renderRouter(r RouterExpr) string {
	switch x := r.(type) {
	case RouterAddr:
		return x.Addr.String()
	case RouterName:
		return x.Name
	case RouterSetRef:
		return x.Name.String()
	case RouterExprBinary:
		return [...]string{"and", "or", "except"}[x.Op] + "(" + renderRouter(x.L) + " " + renderRouter(x.R) + ")"
	}
	return fmt.Sprintf("<%T>", r)
}

func renderAS(a ASExpr) string {
	switch x := a.(type) {
	case ASNum:
		return x.AS.String()
	case ASSetRef:
		return x.Name.String()
	case ASSetTemplate:
		return "tpl:" + x.Template.String()
	case ASExprBinary:
		op := map[ASOp]string{ASAnd: "and", ASOr: "or", ASExcept: "except"}[x.Op]
		return op + "(" + renderAS(x.L) + " " + renderAS(x.R) + ")"
	case nil:
		return "<nil>"
	}
	return fmt.Sprintf("<%T>", a)
}

func renderFilters(fs []Filter) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = renderFilter(f)
	}
	return strings.Join(parts, " ")
}

func renderFilter(f Filter) string {
	switch x := f.(type) {
	case FilterAny:
		return "ANY"
	case FilterPeerAS:
		return "PeerAS" + x.Op.String()
	case FilterPrefixList:
		parts := make([]string, len(x.Ranges))
		for i, r := range x.Ranges {
			parts[i] = r.String()
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case FilterASExpr:
		return renderAS(x.AS) + x.Op.String()
	case FilterSetRef:
		return x.Name.String() + x.Op.String()
	case FilterSetTemplate:
		return "settpl:" + x.Template.String() + x.Op.String()
	case FilterPathRE:
		if x.Regexp == nil {
			return "<!" + x.Raw + ">"
		}
		return "<" + renderRE(x.Regexp.Body) + ">"
	case FilterCommunity:
		return x.Raw
	case FilterAnd:
		return "and(" + renderFilters(x.Terms) + ")"
	case FilterOr:
		return "or(" + renderFilters(x.Terms) + ")"
	case FilterNot:
		return "not(" + renderFilter(x.Inner) + ")"
	case nil:
		return "<nil>"
	}
	return fmt.Sprintf("<%T>", f)
}
