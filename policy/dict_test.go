package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// The shipped dictionary must go through the same parsers a registry's
// dictionary object does, without a single diagnostic.
func TestRFCDictionaryParsesCleanly(t *testing.T) {
	for _, s := range rfcRPAttributes {
		if _, ds := ParseRPAttribute(s); len(ds) != 0 {
			t.Errorf("rp-attribute %q: %v", s, ds)
		}
	}
	for _, s := range rfcTypedefs {
		if _, ds := ParseTypedef(s); len(ds) != 0 {
			t.Errorf("typedef %q: %v", s, ds)
		}
	}
	for _, s := range rfcProtocols {
		if _, ds := ParseProtocol(s); len(ds) != 0 {
			t.Errorf("protocol %q: %v", s, ds)
		}
	}
}

func TestRFCDictionaryContents(t *testing.T) {
	d := RFCDictionary
	if d.IsZero() {
		t.Fatal("RFCDictionary is empty")
	}
	for _, name := range []string{"pref", "med", "dpa", "cost", "next-hop", "aspath", "community"} {
		if _, ok := d.Attr(name); !ok {
			t.Errorf("RFCDictionary has no rp-attribute %q", name)
		}
	}
	if _, ok := d.Attr("PREF"); !ok {
		t.Error("Attr is case-sensitive")
	}
	if _, ok := d.Attr("nonsense"); ok {
		t.Error("Attr invented an attribute")
	}
	for _, name := range []string{"BGP4", "OSPF", "RIP", "RIPng", "IS-IS", "STATIC", "MOSPF"} {
		if _, ok := d.Protocol(name); !ok {
			t.Errorf("RFCDictionary has no protocol %q", name)
		}
	}
	// aspath offers prepend and nothing else.
	aspath, _ := d.Attr("aspath")
	if m, ok := aspath.Method("prepend"); !ok || m.Args != "list of as_number" {
		t.Errorf("aspath.prepend = %+v, %v", m, ok)
	}
	if _, ok := aspath.Method("append"); ok {
		t.Error("aspath declares an append method")
	}
	// pref takes the Figure 25 assignment operators.
	pref, _ := d.Attr("pref")
	for _, m := range []string{"operator=", "operator+=", "operator<<="} {
		if _, ok := pref.Method(m); !ok {
			t.Errorf("pref has no method %q", m)
		}
	}
	// BGP4 declares a mandatory asno and an optional flap_damp.
	bgp, _ := d.Protocol("BGP4")
	asno, ok := bgp.Option("asno")
	if !ok || !asno.Mandatory || asno.Args != "as_number" {
		t.Errorf("BGP4 asno = %+v, %v", asno, ok)
	}
	if o, ok := bgp.Option("flap_damp"); !ok || o.Mandatory {
		t.Errorf("BGP4 flap_damp = %+v, %v; want optional", o, ok)
	}
	if _, ok := d.Typedef("community_list"); !ok {
		t.Error("RFCDictionary has no community_list typedef")
	}
	if got := d.AttrNames(); len(got) != 7 {
		t.Errorf("AttrNames() = %v, want 7", got)
	}
	if got := d.ProtocolNames(); len(got) != 12 {
		t.Errorf("ProtocolNames() = %v, want 12", got)
	}
}

func TestParseRPAttribute(t *testing.T) {
	a, ds := ParseRPAttribute("community operator=(community_list) append(community_list)")
	clean(t, "rp-attribute", ds)
	if a.Name != "community" || len(a.Methods) != 2 {
		t.Fatalf("ParseRPAttribute = %+v", a)
	}
	if a.Methods[0].Name != "operator=" || a.Methods[0].Args != "community_list" {
		t.Errorf("Methods[0] = %+v", a.Methods[0])
	}
	if a.Methods[0].Raw != "operator=(community_list)" {
		t.Errorf("Methods[0].Raw = %q", a.Methods[0].Raw)
	}
	// An operator spelling the tokenizer splits is still one name.
	for _, c := range []struct{ in, want string }{
		{"x operator=(int)", "operator="},
		{"x operator.=(int)", "operator.="},
		{"x operator<<=(int)", "operator<<="},
		{"x operator >>= (int)", "operator>>="},
		{"x prepend(int)", "prepend"},
	} {
		a, ds := ParseRPAttribute(c.in)
		clean(t, "rp-attribute "+c.in, ds)
		if len(a.Methods) != 1 || a.Methods[0].Name != c.want {
			t.Errorf("ParseRPAttribute(%q) methods = %+v, want %q", c.in, a.Methods, c.want)
		}
	}
	// Nested brackets and commas inside a signature stay inside it.
	a, ds = ParseRPAttribute("med operator=(union integer[0, 65535], enum[igp_cost])")
	clean(t, "rp-attribute", ds)
	if len(a.Methods) != 1 || a.Methods[0].Args != "union integer[0, 65535], enum[igp_cost]" {
		t.Errorf("Methods = %+v", a.Methods)
	}
	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"pref", "policy/rp-attribute"},
		{"pref operator=", "policy/rp-attribute"},
		{"pref operator=(", "policy/rp-attribute"},
	} {
		_, ds := ParseRPAttribute(c.in)
		if rules := errorsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParseRPAttribute(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
		}
	}
}

func TestParseTypedefAndProtocol(t *testing.T) {
	td, ds := ParseTypedef("community_list list of union integer[1, 4294967295], enum[internet]")
	clean(t, "typedef", ds)
	if td.Name != "community_list" {
		t.Errorf("Name = %q", td.Name)
	}
	if td.Definition != "list of union integer[1, 4294967295], enum[internet]" {
		t.Errorf("Definition = %q", td.Definition)
	}
	if _, ds := ParseTypedef("lonely"); len(errorsOf(ds)) == 0 {
		t.Error("a typedef with no definition reported no error")
	}

	pr, ds := ParseProtocol("BGP4 MANDATORY asno(as_number) OPTIONAL flap_damp()")
	clean(t, "protocol", ds)
	if pr.Name != "bgp4" || len(pr.Options) != 2 {
		t.Fatalf("ParseProtocol = %+v", pr)
	}
	if !pr.Options[0].Mandatory || pr.Options[0].Name != "asno" {
		t.Errorf("Options[0] = %+v", pr.Options[0])
	}
	if pr.Options[1].Mandatory || pr.Options[1].Name != "flap_damp" {
		t.Errorf("Options[1] = %+v", pr.Options[1])
	}
	// A protocol with no options is fine.
	if pr, ds := ParseProtocol("OSPF"); len(ds) != 0 || pr.Name != "ospf" || len(pr.Options) != 0 {
		t.Errorf("ParseProtocol(OSPF) = %+v, %v", pr, ds)
	}
	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"BGP4 asno(as_number)", "policy/rp-protocol"}, // neither MANDATORY nor OPTIONAL
	} {
		_, ds := ParseProtocol(c.in)
		if rules := errorsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParseProtocol(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
		}
	}
}

// With a dictionary, an unknown attribute, method or protocol warns; without
// one, nothing is checked — the RP-attribute set is open-ended by design.
func TestDictionaryChecking(t *testing.T) {
	d := RFCDictionary
	cases := []struct {
		in    string
		rule  string // "" when the value must be accepted
		point string // text the diagnostic must cover
	}{
		{"from AS1 action pref = 10; accept ANY", "", ""},
		{"from AS1 action med += 5; accept ANY", "", ""},
		{"from AS1 action aspath.prepend(AS1); accept ANY", "", ""},
		{"from AS1 action community.append(1:2); accept ANY", "", ""},
		{"from AS1 action nonsense = 10; accept ANY", "policy/rp-attribute", "nonsense"},
		{"from AS1 action aspath.append(AS1); accept ANY", "policy/rp-method", "append"},
		{"protocol BGP4 from AS1 accept ANY", "", ""},
		{"protocol NONSENSE from AS1 accept ANY", "policy/rp-protocol", "NONSENSE"},
	}
	for _, c := range cases {
		// Without a dictionary nothing is flagged.
		if _, ds := ParseImport(c.in); len(ds) != 0 {
			t.Errorf("ParseImport(%q) without a dictionary: %v", c.in, ds)
		}
		_, ds := ParseImportWith(c.in, false, Options{Dict: &d})
		if c.rule == "" {
			if len(ds) != 0 {
				t.Errorf("ParseImportWith(%q): %v, want clean", c.in, ds)
			}
			continue
		}
		if rules := warningsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParseImportWith(%q) warnings = %v, want one to be %s", c.in, rules, c.rule)
			continue
		}
		if rules := errorsOf(ds); len(rules) != 0 {
			t.Errorf("ParseImportWith(%q) errors = %v, want only warnings", c.in, rules)
		}
		if !spansText(c.in, ds, c.point) {
			t.Errorf("ParseImportWith(%q) diagnostic does not point at %q: %+v", c.in, c.point, ds)
		}
	}
	// Export and default take the same option.
	if _, ds := ParseExportWith("to AS1 action nonsense = 1; announce ANY", false, Options{Dict: &d}); len(ds) == 0 {
		t.Error("ParseExportWith did not check the action")
	}
	if _, ds := ParseDefaultWith("to AS1 action nonsense = 1;", false, Options{Dict: &d}); len(ds) == 0 {
		t.Error("ParseDefaultWith did not check the action")
	}
	// An empty dictionary is not a filter that rejects everything by accident:
	// passing none is what turns checking off.
	if _, ds := ParseImportWith("from AS1 action pref = 10; accept ANY", false, Options{}); len(ds) != 0 {
		t.Errorf("Options{} checked anyway: %v", ds)
	}
}

// spansText reports whether some diagnostic's span covers want in s.
func spansText(s string, ds []ast.Diagnostic, want string) bool {
	for _, d := range ds {
		lo, hi := d.Span.StartByte, d.Span.EndByte
		if lo < 0 || hi > len(s) || lo > hi {
			continue
		}
		if strings.Contains(s[lo:hi], want) {
			return true
		}
	}
	return false
}

func TestMethodName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pref = 10", "operator="},
		{"community .= {1:2}", "operator.="},
		{"community.append(1:2)", "append"},
		{"med += 5", "operator+="},
		{"aspath.prepend(AS1)", "prepend"},
	}
	for _, c := range cases {
		a, msg := parseAction(c.in)
		if msg != "" {
			t.Fatalf("parseAction(%q): %s", c.in, msg)
		}
		if got := MethodName(a); got != c.want {
			t.Errorf("MethodName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
