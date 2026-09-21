package policy

import (
	"strings"
	"testing"

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
	if sr, ok := fa.AS.(ASSetRef); !ok || sr.Name.Canonical() != "AS-FOO" {
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
	if pl.Ranges[1].Op != types.RangePlus {
		t.Errorf("range1 op = %v, want RangePlus", pl.Ranges[1].Op)
	}
}

func TestParseBooleanFilter(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept AS1 AND NOT {192.0.2.0/24}")
	f := factor(t, imp.Expr)
	and, ok := f.Filter.(FilterAnd)
	if !ok {
		t.Fatalf("filter = %T, want FilterAnd", f.Filter)
	}
	if _, ok := and.L.(FilterASExpr); !ok {
		t.Errorf("and.L = %T, want FilterASExpr", and.L)
	}
	not, ok := and.R.(FilterNot)
	if !ok {
		t.Fatalf("and.R = %T, want FilterNot", and.R)
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
	if !ok {
		t.Fatalf("top filter = %T, want FilterOr", f.Filter)
	}
	if _, ok := or.L.(FilterAnd); !ok {
		t.Errorf("or.L = %T, want FilterAnd", or.L)
	}
	if _, ok := or.R.(FilterASExpr); !ok {
		t.Errorf("or.R = %T, want FilterASExpr", or.R)
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
	if a.Op != ActionMethod || a.Attr != "community.append" {
		t.Errorf("action = %+v, want method community.append", a)
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
	imp, diags := ParseImport("afi ipv6.unicast from AS1 accept ANY")
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
	imp, diags := ParseImport("afi ipv4.unicast, ipv6.unicast from AS1 accept ANY")
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
	imp, diags := ParseImport("afi ipv6.unicast from AS1 accept {2001:db8::/32^+}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	f := factor(t, imp.Expr)
	pl, ok := f.Filter.(FilterPrefixList)
	if !ok || len(pl.Ranges) != 1 {
		t.Fatalf("filter = %T %+v, want one-range FilterPrefixList", f.Filter, f.Filter)
	}
	if !pl.Ranges[0].Prefix.Addr().Is6() {
		t.Errorf("range not IPv6: %v", pl.Ranges[0])
	}
}

// FuzzParseImport asserts the parser never panics on arbitrary input.
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
		"{ from AS1 accept AS1; from AS2 accept AS2 }",
		"",
		"{{{",
		"from action accept",
		"<unterminated",
		"afi refine except {}",
		"from AS1 accept " + strings.Repeat("(", 2000) + "ANY" + strings.Repeat(")", 2000),
		"from AS1 accept " + strings.Repeat("not ", 2000) + "ANY",
		strings.Repeat("{", 2000) + "from AS1 accept ANY",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, pi := parseImport(s, false)
		_, pe := parseExport(s, true)
		_, pd := parseDefault(s, false)
		for _, p := range []*parser{pi, pe, pd} {
			assertNothingDropped(t, s, p)
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
