package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// hasRuleAt reports whether ds holds rule at severity sev.
func hasRuleAt(ds []ast.Diagnostic, rule string, sev ast.Severity) bool {
	for _, d := range ds {
		if d.Rule == rule && d.Severity == sev {
			return true
		}
	}
	return false
}

// A router expression term whose last label is all digits is a mistyped
// address, not an inet-rtr name: top-level domains are never all-numeric
// (RFC 3696 §2), and a config generator would try to resolve "256.0.0.1".
func TestRouterNamesNotNumeric(t *testing.T) {
	for _, v := range []string{
		"from AS1 999.1.1.1 accept ANY",
		"from AS1 at 256.0.0.1 accept ANY",
		"from AS1 10.1.1 accept ANY",
		"from AS1 1.2.3.4.5 accept ANY",
		"from AS1 AS1.10 accept ANY",
	} {
		_, ds := ParseImport(v)
		if !hasRuleAt(ds, "policy/router", ast.Error) {
			t.Errorf("%s: %v, want a policy/router Error", v, diagRules(ds))
		}
	}
	for _, v := range []string{
		"from AS1 rtr1.example.net accept ANY",
		"from AS1 192.0.2.1 at rtr-2.example.net accept ANY",
		"from AS1 r1.as64500.net accept ANY",
	} {
		_, ds := ParseImport(v)
		clean(t, v, ds)
	}
}

// An operator after a prefix list that deletes every range in it leaves a
// filter that matches nothing: that is legal, and almost never meant.
func TestPrefixListOpEmptyWarns(t *testing.T) {
	for _, v := range []string{"{1.0.0.0/8}^64", "{1.0.0.0/8}^4", "{1.0.0.0/8^+}^40", "{10.0.0.0/8^24}^16"} {
		f, ds := ParseFilter(v)
		if !hasRuleAt(ds, "policy/range-op-empty", ast.Warning) {
			t.Errorf("%s: %v, want a policy/range-op-empty Warning", v, diagRules(ds))
		}
		if pl, ok := f.(FilterPrefixList); !ok || len(pl.Ranges) != 0 {
			t.Errorf("%s: %#v, want an empty prefix list", v, f)
		}
	}
	// An operator that keeps some of the ranges is ordinary.
	for _, v := range []string{"{1.0.0.0/8}^16", "{1.0.0.0/8, 2001:db8::/32}^48", "{}"} {
		_, ds := ParseFilter(v)
		clean(t, v, ds)
	}
}

// OR and AND chains in an inject: condition are flat, as in a filter, so their
// length is not nesting: a chain of 5,000 terms parses.
func TestInjectLongFlatChain(t *testing.T) {
	for _, op := range []string{" OR ", " AND "} {
		v := "upon " + strings.Repeat("STATIC"+op, 4999) + "STATIC"
		in, ds := ParseInject(v)
		clean(t, "a chain of 5,000"+op, ds)
		if in.Upon == nil {
			t.Errorf("a chain of 5,000%s: no condition", op)
		}
	}
}

// An IPv6 zone means nothing in a registry, and an IPv4-mapped address is an
// IPv4 address: both are read as they always were, and now say so.
func TestInterfaceZoneWarns(t *testing.T) {
	ifa, ds := ParseIfaddr("fe80::1%eth0 masklen 64")
	if ifa.Addr.String() != "fe80::1" || !hasRuleAt(ds, "policy/ifaddr", ast.Warning) {
		t.Errorf("a zoned ifaddr: %s, %v; want fe80::1 and a policy/ifaddr Warning", ifa.Addr, diagRules(ds))
	}
	ifa, ds = ParseIfaddr("::ffff:192.0.2.1 masklen 24")
	if ifa.Addr.String() != "192.0.2.1" || !hasRuleAt(ds, "policy/ifaddr", ast.Warning) {
		t.Errorf("a mapped ifaddr: %s, %v; want 192.0.2.1 and a policy/ifaddr Warning", ifa.Addr, diagRules(ds))
	}
	p, ds := ParsePeering("AS1 fe80::1%eth0")
	if s := exprText(p); s != "AS1 fe80::1" || !hasRuleAt(ds, "policy/router", ast.Warning) {
		t.Errorf("a zoned router address: %q, %v; want the zone dropped and a policy/router Warning", s, diagRules(ds))
	}
}
