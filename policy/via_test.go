package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// viaPolicy is what the via tests need from an Import or an Export.
type viaPolicy interface {
	String() string
	AppliesTo(types.AddrFamily) bool
}

func viaExpr(v viaPolicy) Expr {
	switch x := v.(type) {
	case Import:
		return x.Expr
	case Export:
		return x.Expr
	}
	return nil
}

var viaParsers = map[string]func(string) (viaPolicy, []ast.Diagnostic){
	"import-via": func(v string) (viaPolicy, []ast.Diagnostic) { x, d := ParseImportVia(v); return x, d },
	"export-via": func(v string) (viaPolicy, []ast.Diagnostic) { x, d := ParseExportVia(v); return x, d },
	"export":     func(v string) (viaPolicy, []ast.Diagnostic) { x, d := ParseExport(v); return x, d },
}

// Every example in draft-ietf-grow-rpsl-via-01 parses clean, every clause of a
// via policy carries its via peering, and rendering it parses back to the same
// policy.
func TestViaExamples(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "via-examples.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	where, n := "", 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			where = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}
		if line == "" {
			continue
		}
		example, expect, _ := strings.Cut(line, " ## expect:")
		attr, value, _ := strings.Cut(example, ":")
		parse := viaParsers[attr]
		if parse == nil {
			t.Fatalf("%s: no parser for %q", where, attr)
		}
		n++
		v, ds := parse(strings.TrimSpace(value))
		if got, want := strings.Join(diagRules(ds), " "), strings.Join(strings.Fields(expect), " "); got != want {
			t.Errorf("%s: %s\n  diagnostics %q, want %q", where, example, got, want)
			continue
		}
		if strings.HasSuffix(attr, "-via") {
			terms := Flatten(viaExpr(v))
			if len(terms) == 0 {
				t.Errorf("%s: %s flattens to no terms", where, example)
			}
			for _, tm := range terms {
				if tm.Via == nil {
					t.Errorf("%s: %s has a term without its via peering: %s", where, example, tm)
				}
			}
		}
		again, ds := parse(v.String())
		if len(ds) != 0 || again.String() != v.String() {
			t.Errorf("%s: %s renders as %q, which parses back as %q %v", where, example, v.String(), again.String(), diagRules(ds))
		}
	}
	if n != 10 {
		t.Errorf("read %d examples, want 10", n)
	}
}

// The draft's first example, field by field.
func TestParseImportViaFields(t *testing.T) {
	imp, ds := ParseImportVia("AS6777 from AS15562 action pref = 2; accept AS-SNIJDERS")
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", diagRules(ds))
	}
	if !imp.MP {
		t.Error("import-via is RFC 4012 syntax, so MP must be set")
	}
	f, ok := imp.Expr.(Factor)
	if !ok || len(f.Peers) != 1 {
		t.Fatalf("Expr = %#v, want one factor with one clause", imp.Expr)
	}
	pa := f.Peers[0]
	if got := exprText(pa.Via); got != "AS6777" {
		t.Errorf("Via = %q, want AS6777", got)
	}
	if got := exprText(pa.Peering); got != "AS15562" {
		t.Errorf("Peering = %q, want AS15562", got)
	}
	if len(pa.Actions) != 1 || pa.Actions[0].Attr != "pref" || pa.Actions[0].Value != "2" {
		t.Errorf("Actions = %+v, want pref = 2", pa.Actions)
	}
	if got := filterString(f.Filter, precOr); got != "AS-SNIJDERS" {
		t.Errorf("Filter = %q, want AS-SNIJDERS", got)
	}
}

// A via peering can be any peering specification, router expressions included.
func TestParseExportViaRouters(t *testing.T) {
	exp, ds := ParseExportVia("afi ipv6.unicast AS47498 at ( 2001:7f8:ca:1::111 OR 2001:7f8:ca:1::222 ) to AS-FOGIXP announce { 2001:67c:2ea8::/48, 2001:67c:e7c::/48 }")
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", diagRules(ds))
	}
	via, ok := exp.Expr.(Factor).Peers[0].Via.(PeeringAS)
	if !ok || via.AtRouter == nil || exprText(via.AS) != "AS47498" {
		t.Fatalf("Via = %#v, want AS47498 at <router expression>", exp.Expr.(Factor).Peers[0].Via)
	}
	exp, ds = ParseExportVia("AS6777 195.69.144.255 to AS-AMS-IX-RS announce AS-SNIJDERS")
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", diagRules(ds))
	}
	if via, ok := exp.Expr.(Factor).Peers[0].Via.(PeeringAS); !ok || via.Router == nil {
		t.Fatalf("Via = %#v, want AS6777 with a router", exp.Expr.(Factor).Peers[0].Via)
	}
}

// Canonical renderings of the forms real RIPE data uses, and of the structured
// forms the grammar shares with mp-import.
func TestViaStrings(t *testing.T) {
	for _, c := range []struct{ attr, in, want string }{
		{"import-via", "afi ipv4.unicast, ipv6.unicast AS8631 from AS-MSKROUTESERVER action pref=100; accept AS-MSKROUTESERVER",
			"afi ipv4.unicast, ipv6.unicast AS8631 from AS-MSKROUTESERVER action pref = 100; accept AS-MSKROUTESERVER"},
		{"import-via", "AS6777 from AS-ANY EXCEPT AS15169 accept ANY", "AS6777 from AS-ANY EXCEPT AS15169 accept ANY"},
		{"import-via", "afi ipv4.unicast AS51706 from AS-ANY action pref = 900; accept ANY AND NOT {0.0.0.0/0}",
			"afi ipv4.unicast AS51706 from AS-ANY action pref = 900; accept ANY AND NOT {0.0.0.0/0}"},
		{"import-via", "protocol BGP4 into OSPF AS6777 from AS1 accept ANY", "protocol BGP4 into OSPF AS6777 from AS1 accept ANY"},
		{"import-via", "AS6777 from AS1 action pref = 1; AS8631 from AS2 accept ANY", "AS6777 from AS1 action pref = 1; AS8631 from AS2 accept ANY"},
		{"import-via", "AS6777 from AS-ANY accept ANY refine AS6777 from AS1 accept AS1",
			"AS6777 from AS-ANY accept ANY REFINE AS6777 from AS1 accept AS1"},
		{"export-via", "afi ipv4.unicast AS6777 to AS-ANY announce NOT ANY", "afi ipv4.unicast AS6777 to AS-ANY announce NOT ANY"},
		{"export-via", "AS6777 to AS15562 action community.={15562:40}; announce AS-SNIJDERS",
			"AS6777 to AS15562 action community .= {15562:40}; announce AS-SNIJDERS"},
	} {
		v, ds := viaParsers[c.attr](c.in)
		if len(ds) != 0 {
			t.Errorf("%s: %s: diagnostics %v", c.attr, c.in, diagRules(ds))
			continue
		}
		if got := v.String(); got != c.want {
			t.Errorf("%s: %s\n  renders %q\n  want    %q", c.attr, c.in, got, c.want)
		}
	}
	// A brace list of via policies round-trips, and every clause keeps its via.
	imp, ds := ParseImportVia("{ AS6777 from AS1 accept AS1; AS8631 from AS2 accept AS2; }")
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", diagRules(ds))
	}
	again, ds := ParseImportVia(imp.String())
	if len(ds) != 0 || again.String() != imp.String() {
		t.Fatalf("%q parses back as %q %v", imp.String(), again.String(), diagRules(ds))
	}
	for _, tm := range Flatten(imp.Expr) {
		if tm.Via == nil {
			t.Errorf("term %s lost its via peering", tm)
		}
	}
}

// Malformed via policies are diagnosed at the offending token.
func TestViaErrors(t *testing.T) {
	for _, c := range []struct {
		attr, in string
		rules    string
		at       int // byte offset of the first diagnostic
	}{
		{"import-via", "from AS1 accept ANY", "policy/via", 0},
		{"export-via", "to AS1 announce ANY", "policy/via", 0},
		{"import-via", "AS6777 accept ANY", "policy/expect-peering", 7},
		{"import-via", "", "policy/empty", 0},
	} {
		_, ds := viaParsers[c.attr](c.in)
		if got := strings.Join(diagRules(ds), " "); got != c.rules {
			t.Errorf("%s: %q: diagnostics %q, want %q", c.attr, c.in, got, c.rules)
			continue
		}
		if ds[0].Severity != ast.Error || ds[0].Span.StartByte != c.at {
			t.Errorf("%s: %q: first diagnostic %v at byte %d, want an Error at %d", c.attr, c.in, ds[0].Severity, ds[0].Span.StartByte, c.at)
		}
	}
	// A clause without its via peering is dropped; the rest of the policy is kept.
	imp, _ := ParseImportVia("from AS1 accept AS1")
	if f, ok := imp.Expr.(Factor); !ok || len(f.Peers) != 0 {
		t.Errorf("Expr = %#v, want the clause without a via peering dropped", imp.Expr)
	}
	// import-via takes "from", not "to".
	if _, ds := ParseImportVia("AS6777 to AS1 accept ANY"); len(ds) == 0 || ds[0].Rule != "policy/expect-peering" {
		t.Errorf("import-via with 'to': diagnostics %v, want policy/expect-peering first", diagRules(ds))
	}
}

// With no afi clause a via policy applies to every family, as an mp-import
// does (RFC 4012 §2.5); with one, only to the families it lists.
func TestViaAppliesTo(t *testing.T) {
	v4, _ := types.ParseAddrFamily("ipv4.unicast")
	v6, _ := types.ParseAddrFamily("ipv6.unicast")
	for _, c := range []struct {
		attr, in     string
		want4, want6 bool
	}{
		{"import-via", "AS6777 from AS1 accept ANY", true, true},
		{"export-via", "AS6777 to AS1 announce ANY", true, true},
		{"import-via", "afi ipv6.unicast AS6777 from AS1 accept ANY", false, true},
		{"export-via", "afi ipv4.unicast AS6777 to AS1 announce ANY", true, false},
	} {
		v, ds := viaParsers[c.attr](c.in)
		if len(ds) != 0 {
			t.Fatalf("%q: diagnostics %v", c.in, diagRules(ds))
		}
		if v.AppliesTo(v4) != c.want4 || v.AppliesTo(v6) != c.want6 {
			t.Errorf("%s: %q applies to v4=%v v6=%v, want %v %v", c.attr, c.in, v.AppliesTo(v4), v.AppliesTo(v6), c.want4, c.want6)
		}
	}
}

// The afi list of a via policy ends at the first family not followed by a
// comma, since a peering follows it; other policies keep reading families.
func TestViaAFIListEnd(t *testing.T) {
	imp, ds := ParseImportVia("afi ipv4.unicast, ipv6.unicast AS8631 from AS1 accept ANY")
	if len(ds) != 0 || len(imp.AFIs) != 2 {
		t.Fatalf("AFIs %v, diagnostics %v; want two families and no diagnostic", imp.AFIs, diagRules(ds))
	}
	if _, ds := ParseMPImport("afi ipv4.unicast ipv6.unicast from AS1 accept ANY"); len(ds) != 0 {
		t.Errorf("mp-import without a comma between families: diagnostics %v, want none (unchanged)", diagRules(ds))
	}
}

// Refine and except combine two via terms only where both their via peerings
// and their peerings meet.
func TestViaFlatten(t *testing.T) {
	imp, ds := ParseImportVia("AS6777 from AS-ANY accept ANY refine AS6777 from AS1 accept AS1")
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", diagRules(ds))
	}
	terms := Flatten(imp.Expr)
	if len(terms) != 1 || exprText(terms[0].Via) != "AS6777" || exprText(terms[0].Peering) != "AS1" {
		t.Fatalf("refine terms %v, want one: via AS6777 from AS1", terms)
	}
	if got := terms[0].String(); got != "AS1 via AS6777 | ANY AND AS1" {
		t.Errorf("term renders %q", got)
	}
	imp, _ = ParseImportVia("AS6777 from AS-ANY accept ANY refine AS8631 from AS1 accept AS1")
	if terms := Flatten(imp.Expr); len(terms) != 0 {
		t.Errorf("refine across different via peerings gave %v, want no terms", terms)
	}
	imp, _ = ParseImportVia("AS6777 from AS-ANY accept ANY except AS6777 from AS1 accept AS1")
	terms = Flatten(imp.Expr)
	if len(terms) != 2 {
		t.Fatalf("except terms %v, want two", terms)
	}
	for _, tm := range terms {
		if exprText(tm.Via) != "AS6777" {
			t.Errorf("except term %s lost its via peering", tm)
		}
	}
}

// The With variants check actions against a dictionary.
func TestViaWithDictionary(t *testing.T) {
	dict := RFCDictionary
	o := Options{Dict: &dict}
	if _, ds := ParseImportViaWith("AS6777 from AS1 action nonsense = 1; accept ANY", o); len(ds) == 0 || ds[0].Rule != "policy/rp-attribute" {
		t.Errorf("import-via: diagnostics %v, want policy/rp-attribute", diagRules(ds))
	}
	if _, ds := ParseExportViaWith("AS6777 to AS1 action pref = 1; announce ANY", o); len(ds) != 0 {
		t.Errorf("export-via with a known attribute: diagnostics %v, want none", diagRules(ds))
	}
}
