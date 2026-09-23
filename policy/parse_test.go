package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// factor extracts the Factor from an Expr, failing the test otherwise.
func factor(t *testing.T, e Expr) Factor {
	t.Helper()
	f, ok := e.(Factor)
	if !ok {
		t.Fatalf("Expr = %T, want Factor", e)
	}
	return f
}

func TestParseImportSimple(t *testing.T) {
	imp, diags := ParseImport("from AS64500 accept ANY")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	if len(f.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(f.Peers))
	}
	pas, ok := f.Peers[0].Peering.(PeeringAS)
	if !ok {
		t.Fatalf("peering = %T, want PeeringAS", f.Peers[0].Peering)
	}
	if n, ok := pas.AS.(ASNum); !ok || n.AS != 64500 {
		t.Errorf("peering AS = %+v, want AS64500", pas.AS)
	}
	if _, ok := f.Filter.(FilterAny); !ok {
		t.Errorf("filter = %T, want FilterAny", f.Filter)
	}
}

func TestParseImportMultiPeeringAction(t *testing.T) {
	imp, diags := ParseImport("from AS1 action pref=100; from AS2 accept AS-FOO")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	if len(f.Peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(f.Peers))
	}
	if len(f.Peers[0].Actions) != 1 {
		t.Fatalf("peer0 actions = %v", f.Peers[0].Actions)
	}
	a := f.Peers[0].Actions[0]
	if a.Attr != "pref" || a.Op != ActionAssign || a.Value != "100" {
		t.Errorf("action = %+v, want pref=100 assign", a)
	}
	if len(f.Peers[1].Actions) != 0 {
		t.Errorf("peer1 actions = %v, want none", f.Peers[1].Actions)
	}
	fa, ok := f.Filter.(FilterASExpr)
	if !ok {
		t.Fatalf("filter = %T, want FilterASExpr", f.Filter)
	}
	if sr, ok := fa.AS.(ASSetRef); !ok || sr.Name.String() != "AS-FOO" {
		t.Errorf("filter AS = %+v, want AS-FOO", fa.AS)
	}
}

func TestParseExport(t *testing.T) {
	exp, diags := ParseExport("to AS64500 announce AS65001")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, exp.Expr)
	if n, ok := f.Peers[0].Peering.(PeeringAS).AS.(ASNum); !ok || n.AS != 64500 {
		t.Errorf("peering = %+v", f.Peers[0].Peering)
	}
	fa, ok := f.Filter.(FilterASExpr)
	if !ok {
		t.Fatalf("filter = %T, want FilterASExpr", f.Filter)
	}
	if n, ok := fa.AS.(ASNum); !ok || n.AS != 65001 {
		t.Errorf("announce AS = %+v, want AS65001", fa.AS)
	}
}

func TestParsePrefixListFilter(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept {192.0.2.0/24, 10.0.0.0/8^+}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	pl, ok := f.Filter.(FilterPrefixList)
	if !ok {
		t.Fatalf("filter = %T, want FilterPrefixList", f.Filter)
	}
	if len(pl.Ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(pl.Ranges))
	}
	if pl.Ranges[1].Op() != types.RangePlus {
		t.Errorf("range1 op = %v, want RangePlus", pl.Ranges[1].Op())
	}
}

func TestParseBooleanFilter(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept AS1 AND NOT {192.0.2.0/24}")
	f := factor(t, imp.Expr)
	and, ok := f.Filter.(FilterAnd)
	if !ok || len(and.Terms) != 2 {
		t.Fatalf("filter = %#v, want a two-term FilterAnd", f.Filter)
	}
	if _, ok := and.Terms[0].(FilterASExpr); !ok {
		t.Errorf("and.Terms[0] = %T, want FilterASExpr", and.Terms[0])
	}
	not, ok := and.Terms[1].(FilterNot)
	if !ok {
		t.Fatalf("and.Terms[1] = %T, want FilterNot", and.Terms[1])
	}
	if _, ok := not.Inner.(FilterPrefixList); !ok {
		t.Errorf("not.Inner = %T, want FilterPrefixList", not.Inner)
	}
}

func TestFilterOrPrecedence(t *testing.T) {
	// AS1 AND AS2 OR AS3  ==  (AS1 AND AS2) OR AS3
	imp, _ := ParseImport("from AS1 accept AS1 AND AS2 OR AS3")
	f := factor(t, imp.Expr)
	or, ok := f.Filter.(FilterOr)
	if !ok || len(or.Terms) != 2 {
		t.Fatalf("top filter = %#v, want a two-term FilterOr", f.Filter)
	}
	if _, ok := or.Terms[0].(FilterAnd); !ok {
		t.Errorf("or.Terms[0] = %T, want FilterAnd", or.Terms[0])
	}
	if _, ok := or.Terms[1].(FilterASExpr); !ok {
		t.Errorf("or.Terms[1] = %T, want FilterASExpr", or.Terms[1])
	}
}

func TestParseDefault(t *testing.T) {
	d, diags := ParseDefault("to AS1 action pref=10; networks ANY")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if n, ok := d.Peering.(PeeringAS).AS.(ASNum); !ok || n.AS != 1 {
		t.Errorf("peering = %+v", d.Peering)
	}
	if len(d.Actions) != 1 || d.Actions[0].Attr != "pref" {
		t.Errorf("actions = %+v", d.Actions)
	}
	if _, ok := d.Networks.(FilterAny); !ok {
		t.Errorf("networks = %T, want FilterAny", d.Networks)
	}
}

func TestParseDefaultBare(t *testing.T) {
	d, diags := ParseDefault("to AS1")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if d.Networks != nil {
		t.Errorf("networks = %v, want nil", d.Networks)
	}
}

func TestParseASPathRegexp(t *testing.T) {
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
		t.Errorf("regexp = %q", re.Raw)
	}
}

func TestParseCommunityFilter(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept community(65000:888)")
	f := factor(t, imp.Expr)
	c, ok := f.Filter.(FilterCommunity)
	if !ok {
		t.Fatalf("filter = %T, want FilterCommunity", f.Filter)
	}
	if c.Raw != "community(65000:888)" {
		t.Errorf("community raw = %q", c.Raw)
	}
}

func TestParseProtocolPrefixes(t *testing.T) {
	imp, diags := ParseImport("protocol BGP4 into BGP4 from AS1 accept ANY")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if imp.Protocol != "BGP4" || imp.IntoProtocol != "BGP4" {
		t.Errorf("protocol=%q into=%q", imp.Protocol, imp.IntoProtocol)
	}
}

func TestParseAppendAction(t *testing.T) {
	imp, _ := ParseImport("from AS1 action community.append(65000:1); accept ANY")
	f := factor(t, imp.Expr)
	a := f.Peers[0].Actions[0]
	if a.Op != ActionMethod || a.Attr != "community" || a.Method != "append" {
		t.Errorf("action = %+v, want community.append", a)
	}
}

// TestRecovery: a malformed peering yields one diagnostic but the filter still
// parses — per-attribute resilience at the policy layer.
func TestRecovery(t *testing.T) {
	imp, diags := ParseImport("from @@@ accept ANY")
	if len(diags) != 1 || diags[0].Rule != "policy/peering" {
		t.Fatalf("diags = %+v, want one policy/peering", diags)
	}
	f := factor(t, imp.Expr)
	if _, ok := f.Filter.(FilterAny); !ok {
		t.Errorf("filter = %T, want FilterAny despite bad peering", f.Filter)
	}
}

func TestParseMpImportAFI(t *testing.T) {
	imp, diags := ParseMPImport("afi ipv6.unicast from AS1 accept ANY")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if len(imp.AFIs) != 1 || imp.AFIs[0].String() != "ipv6.unicast" {
		t.Fatalf("AFIs = %v, want [ipv6.unicast]", imp.AFIs)
	}
	f := factor(t, imp.Expr)
	if _, ok := f.Filter.(FilterAny); !ok {
		t.Errorf("filter = %T, want FilterAny", f.Filter)
	}
}

func TestParseAFIList(t *testing.T) {
	imp, diags := ParseMPImport("afi ipv4.unicast, ipv6.unicast from AS1 accept ANY")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if len(imp.AFIs) != 2 {
		t.Fatalf("AFIs = %v, want 2", imp.AFIs)
	}
	if imp.AFIs[0].String() != "ipv4.unicast" || imp.AFIs[1].String() != "ipv6.unicast" {
		t.Errorf("AFIs = %v", imp.AFIs)
	}
}

func TestParseExcept(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept ANY except {from AS2 accept AS2}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	ex, ok := imp.Expr.(Except)
	if !ok {
		t.Fatalf("Expr = %T, want Except", imp.Expr)
	}
	if _, ok := ex.Left.(Factor); !ok {
		t.Errorf("Except.Left = %T, want Factor", ex.Left)
	}
	list, ok := ex.Right.(ExprList)
	if !ok {
		t.Fatalf("Except.Right = %T, want ExprList", ex.Right)
	}
	if len(list.Exprs) != 1 {
		t.Errorf("ExprList = %d exprs, want 1", len(list.Exprs))
	}
}

func TestParseRefine(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept ANY refine {from AS2 accept AS2}")
	if _, ok := imp.Expr.(Refine); !ok {
		t.Fatalf("Expr = %T, want Refine", imp.Expr)
	}
}

func TestParseBraceList(t *testing.T) {
	imp, diags := ParseImport("{ from AS1 accept AS1; from AS2 accept AS2 }")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	list, ok := imp.Expr.(ExprList)
	if !ok {
		t.Fatalf("Expr = %T, want ExprList", imp.Expr)
	}
	if len(list.Exprs) != 2 {
		t.Fatalf("ExprList = %d exprs, want 2", len(list.Exprs))
	}
	for i, e := range list.Exprs {
		if _, ok := e.(Factor); !ok {
			t.Errorf("expr %d = %T, want Factor", i, e)
		}
	}
}

func TestParseMpFilterIPv6(t *testing.T) {
	imp, diags := ParseMPImport("afi ipv6.unicast from AS1 accept {2001:db8::/32^+}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	pl, ok := f.Filter.(FilterPrefixList)
	if !ok || len(pl.Ranges) != 1 {
		t.Fatalf("filter = %T %+v, want one-range FilterPrefixList", f.Filter, f.Filter)
	}
	if !pl.Ranges[0].Prefix().Addr().Is6() {
		t.Errorf("range not IPv6: %v", pl.Ranges[0])
	}
}

// FuzzParseImport asserts the parser never panics on arbitrary input, read as
// every policy attribute: import:, mp-export:, default:, import-via: and
// export-via:.
func FuzzParseImport(f *testing.F) {
	for _, s := range []string{
		"from AS1 accept ANY",
		"from AS1 action pref=100; from AS2 accept AS-FOO",
		"to AS1 announce {1.0.0.0/8^+}",
		"from AS1 accept <^AS1+$>",
		"protocol BGP4 from AS1 accept (AS1 AND NOT AS2) OR PeerAS",
		"afi ipv6.unicast from AS1 accept {2001:db8::/32^+}",
		"afi ipv4.unicast, ipv6.unicast from AS1 accept ANY",
		"from AS1 accept ANY except {from AS2 accept AS2}",
		"from AS1 accept AS1 (AS2 OR AS3) AND community(1:2)",
		"{ from AS1 accept AS1; from AS2 accept AS2 }",
		"",
		"{{{",
		"from action accept",
		"<unterminated",
		"afi refine except {}",
		"from AS1 accept " + strings.Repeat("(", 2000) + "ANY" + strings.Repeat(")", 2000),
		"from AS1 accept " + strings.Repeat("not ", 2000) + "ANY",
		strings.Repeat("{", 2000) + "from AS1 accept ANY",
		// import-via: and export-via: (draft-ietf-grow-rpsl-via)
		"AS6777 from AS15562 action pref = 2; accept AS-SNIJDERS",
		"AS6777 195.69.144.255 to AS-AMS-IX-RS announce AS-SNIJDERS",
		"afi ipv4.unicast, ipv6.unicast AS8631 from AS-MSKROUTESERVER action pref=100; accept AS-MSKROUTESERVER",
		"afi ipv6.unicast AS47498 at ( 2001:7f8:ca:1::111 OR 2001:7f8:ca:1::222 ) to AS-FOGIXP announce { 2001:67c:2ea8::/48 }",
		"AS6777 from AS-ANY accept ANY refine AS8631 from AS1 accept AS1",
		"{ AS6777 from AS1 accept AS1; from AS2 accept AS2 }",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		imp, pi := parseImport(s, false)
		exp, pe := parseExport(s, true)
		def, pd := parseDefault(s, false)
		iv, piv := parseImportVia(s, Options{})
		ev, pev := parseExportVia(s, Options{})
		for _, p := range []*parser{pi, pe, pd, piv, pev} {
			assertNothingDropped(t, s, p)
		}
		checkParse(t, s, imp, pi.diags, func(v string) (any, []ast.Diagnostic) { return ParseImport(v) })
		checkParse(t, s, exp, pe.diags, func(v string) (any, []ast.Diagnostic) { return ParseMPExport(v) })
		checkParse(t, s, def, pd.diags, func(v string) (any, []ast.Diagnostic) { return ParseDefault(v) })
		checkParse(t, s, iv, piv.diags, func(v string) (any, []ast.Diagnostic) { return ParseImportVia(v) })
		checkParse(t, s, ev, pev.diags, func(v string) (any, []ast.Diagnostic) { return ParseExportVia(v) })
		// A clean via policy renders to text that parses back to the same policy.
		if len(piv.diags) == 0 {
			if again, ds := ParseImportVia(iv.String()); len(ds) != 0 || again.String() != iv.String() {
				t.Fatalf("%q renders as %q, which parses back as %q %v", s, iv.String(), again.String(), diagRules(ds))
			}
		}
		if len(pev.diags) == 0 {
			if again, ds := ParseExportVia(ev.String()); len(ds) != 0 || again.String() != ev.String() {
				t.Fatalf("%q renders as %q, which parses back as %q %v", s, ev.String(), again.String(), diagRules(ds))
			}
		}
	})
}

// assertNothingDropped is the "never drop input" property: a parse that
// reports no diagnostics must have consumed every token of the value.
func assertNothingDropped(t *testing.T, s string, p *parser) {
	t.Helper()
	if len(p.diags) == 0 && !p.atEOF() {
		t.Fatalf("%q: no diagnostics, but parsing stopped at %q", s, p.cur().text)
	}
}
