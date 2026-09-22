package policy

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// errorsOf returns the Error-severity rules of ds, in order.
func errorsOf(ds []ast.Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Severity >= ast.Error {
			out = append(out, d.Rule)
		}
	}
	return out
}

// warningsOf returns the Warning-severity rules of ds, in order.
func warningsOf(ds []ast.Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Severity == ast.Warning {
			out = append(out, d.Rule)
		}
	}
	return out
}

// clean fails when a value did not parse without Error diagnostics.
func clean(t *testing.T, what string, ds []ast.Diagnostic) {
	t.Helper()
	if rules := errorsOf(ds); rules != nil {
		t.Fatalf("%s: unexpected errors %v (%+v)", what, rules, ds)
	}
}

func TestParseInject(t *testing.T) {
	// The worked examples of RFC 2622 §8.1 plus the shapes its grammar allows.
	for _, s := range []string{
		"at 1.1.1.1",
		"at 1.1.1.1 action dpa = 100;",
		"at 1.1.1.1 upon STATIC",
		"upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}",
		"at 1.1.1.1 action dpa = 100; upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}",
		"upon EXCLUDE {128.8.0.0/16}",
		"upon HAVE-COMPONENTS {128.8.0.0/16} AND NOT EXCLUDE {128.9.0.0/16}",
		"upon (STATIC OR HAVE-COMPONENTS {10.0.0.0/8}) AND NOT STATIC",
		"at rtr.example.net upon STATIC",
		"at RTRS-FOO",
		"action pref = 10",
	} {
		in, ds := ParseInject(s)
		clean(t, "ParseInject("+s+")", ds)
		if in.Raw != s {
			t.Errorf("ParseInject(%q).Raw = %q", s, in.Raw)
		}
	}

	t.Run("structure", func(t *testing.T) {
		in, ds := ParseInject("at 1.1.1.1 action dpa = 100; upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}")
		clean(t, "inject", ds)
		addr, ok := in.At.(RouterAddr)
		if !ok || addr.Addr.String() != "1.1.1.1" {
			t.Errorf("At = %#v, want RouterAddr 1.1.1.1", in.At)
		}
		if len(in.Actions) != 1 || in.Actions[0].Attr != "dpa" {
			t.Fatalf("Actions = %#v, want one dpa action", in.Actions)
		}
		if n, ok := in.Actions[0].Int(); !ok || n != 100 {
			t.Errorf("dpa value = %d, %v; want 100", n, ok)
		}
		hc, ok := in.Upon.(InjectHaveComponents)
		if !ok {
			t.Fatalf("Upon = %#v, want InjectHaveComponents", in.Upon)
		}
		want := []string{"128.8.0.0/16", "128.9.0.0/16"}
		if len(hc.Ranges) != len(want) {
			t.Fatalf("Ranges = %v, want %v", hc.Ranges, want)
		}
		for i, r := range hc.Ranges {
			if r.String() != want[i] {
				t.Errorf("Ranges[%d] = %s, want %s", i, r, want[i])
			}
		}
	})

	t.Run("boolean precedence", func(t *testing.T) {
		// NOT binds tighter than AND, which binds tighter than OR.
		in, ds := ParseInject("upon STATIC OR NOT STATIC AND STATIC")
		clean(t, "inject", ds)
		or, ok := in.Upon.(InjectOr)
		if !ok || len(or.Terms) != 2 {
			t.Fatalf("Upon = %#v, want InjectOr of 2", in.Upon)
		}
		if _, ok := or.Terms[0].(InjectStatic); !ok {
			t.Errorf("Terms[0] = %#v, want InjectStatic", or.Terms[0])
		}
		and, ok := or.Terms[1].(InjectAnd)
		if !ok || len(and.Terms) != 2 {
			t.Fatalf("Terms[1] = %#v, want InjectAnd of 2", or.Terms[1])
		}
		if _, ok := and.Terms[0].(InjectNot); !ok {
			t.Errorf("and.Terms[0] = %#v, want InjectNot", and.Terms[0])
		}
	})

	t.Run("errors", func(t *testing.T) {
		for _, c := range []struct{ in, rule string }{
			{"", "policy/empty"},
			{"upon", "policy/inject"},
			{"upon WHATEVER", "policy/inject"},
			{"upon HAVE-COMPONENTS", "policy/inject"},
			{"upon HAVE-COMPONENTS {", "policy/prefix-list"},
			{"upon HAVE-COMPONENTS {not-a-prefix}", "policy/prefix-list"},
			{"upon (STATIC", "policy/inject"},
			{"nonsense", "policy/trailing"},
			{"at 1.1.1.1 at 2.2.2.2", "policy/trailing"}, // the clauses come once, in order
			{"upon STATIC at 1.1.1.1", "policy/trailing"},
		} {
			_, ds := ParseInject(c.in)
			rules := errorsOf(ds)
			found := false
			for _, r := range rules {
				if r == c.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("ParseInject(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
			}
		}
	})
}

func TestParseComponents(t *testing.T) {
	t.Run("atomic", func(t *testing.T) {
		c, ds := ParseComponents("ATOMIC")
		clean(t, "components", ds)
		if !c.Atomic || len(c.Lists) != 0 {
			t.Errorf("ParseComponents(ATOMIC) = %+v", c)
		}
	})

	t.Run("bare filter", func(t *testing.T) {
		c, ds := ParseComponents("{128.8.0.0/16^+}")
		clean(t, "components", ds)
		if c.Atomic || len(c.Lists) != 1 || c.Lists[0].Protocol != "" {
			t.Fatalf("ParseComponents = %+v", c)
		}
		list, ok := c.Lists[0].Filter.(FilterPrefixList)
		if !ok || len(list.Ranges) != 1 || list.Ranges[0].String() != "128.8.0.0/16^+" {
			t.Errorf("filter = %#v", c.Lists[0].Filter)
		}
	})

	t.Run("per protocol", func(t *testing.T) {
		c, ds := ParseComponents("protocol BGP4 {128.8.0.0/16^+} protocol OSPF {128.9.0.0/16^+}")
		clean(t, "components", ds)
		if len(c.Lists) != 2 {
			t.Fatalf("Lists = %+v, want 2", c.Lists)
		}
		if c.Lists[0].Protocol != "BGP4" || c.Lists[1].Protocol != "OSPF" {
			t.Errorf("protocols = %q, %q", c.Lists[0].Protocol, c.Lists[1].Protocol)
		}
		for i, want := range []string{"128.8.0.0/16^+", "128.9.0.0/16^+"} {
			list, ok := c.Lists[i].Filter.(FilterPrefixList)
			if !ok || len(list.Ranges) != 1 || list.Ranges[0].String() != want {
				t.Errorf("Lists[%d].Filter = %#v, want %s", i, c.Lists[i].Filter, want)
			}
		}
	})

	t.Run("atomic then filter", func(t *testing.T) {
		c, ds := ParseComponents("ATOMIC {10.0.0.0/8}")
		clean(t, "components", ds)
		if !c.Atomic || len(c.Lists) != 1 {
			t.Errorf("ParseComponents = %+v", c)
		}
	})

	if c, _ := ParseComponents(""); !c.IsZero() {
		t.Errorf("empty components is not zero: %+v", c)
	}
}

func TestParseAggrMtd(t *testing.T) {
	cases := []struct {
		in       string
		inbound  bool
		outbound bool
		as       string // "" when no as-expression
	}{
		{"inbound", true, false, ""},
		{"INBOUND", true, false, ""},
		{"outbound", false, true, ""},
		{"outbound AS-ANY", false, true, "AS-ANY"},
		{"outbound AS1 OR AS2", false, true, ""},
	}
	for _, c := range cases {
		m, ds := ParseAggrMtd(c.in)
		clean(t, "ParseAggrMtd("+c.in+")", ds)
		if m.Inbound != c.inbound || m.Outbound != c.outbound {
			t.Errorf("ParseAggrMtd(%q) = inbound %v, outbound %v", c.in, m.Inbound, m.Outbound)
		}
		if c.as != "" {
			ref, ok := m.AS.(ASSetRef)
			if !ok || ref.Name.String() != c.as {
				t.Errorf("ParseAggrMtd(%q).AS = %#v, want %s", c.in, m.AS, c.as)
			}
		}
		if m.Raw != c.in {
			t.Errorf("ParseAggrMtd(%q).Raw = %q", c.in, m.Raw)
		}
	}
	// "outbound AS1 OR AS2" must build a binary node.
	m, _ := ParseAggrMtd("outbound AS1 OR AS2")
	if _, ok := m.AS.(ASExprBinary); !ok {
		t.Errorf("outbound AS1 OR AS2: AS = %#v, want ASExprBinary", m.AS)
	}
	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"sideways", "policy/aggr-mtd"},
		{"inbound AS1", "policy/trailing"},
	} {
		_, ds := ParseAggrMtd(c.in)
		rules := errorsOf(ds)
		if len(rules) == 0 || rules[0] != c.rule {
			t.Errorf("ParseAggrMtd(%q) rules = %v, want %s first", c.in, rules, c.rule)
		}
	}
	if m, _ := ParseAggrMtd(""); !m.IsZero() {
		t.Errorf("empty aggr-mtd is not zero: %+v", m)
	}
}

func TestParseASExpression(t *testing.T) {
	as, ds := ParseASExpression("AS-FOO")
	clean(t, "aggr-bndry", ds)
	ref, ok := as.(ASSetRef)
	if !ok || ref.Name.Class() != types.ClassAsSet {
		t.Errorf("ParseASExpression(AS-FOO) = %#v", as)
	}
	as, ds = ParseASExpression("AS1 OR AS2 AND AS3")
	clean(t, "aggr-bndry", ds)
	if _, ok := as.(ASExprBinary); !ok {
		t.Errorf("ParseASExpression = %#v, want ASExprBinary", as)
	}
	if _, ds := ParseASExpression(""); len(errorsOf(ds)) == 0 {
		t.Error("ParseASExpression(\"\") reported no error")
	}
	if got, ds := ParseASExpression("{"); got != nil && len(errorsOf(ds)) == 0 {
		t.Errorf("ParseASExpression(\"{\") = %#v with no error", got)
	}
}
