package policy

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// Router expressions (RFC 2622 §5.6, RFC 4012) are parsed into typed nodes:
// addresses, rtr-sets and inet-rtr names under AND, OR and EXCEPT.
func TestRouterExpressions(t *testing.T) {
	addr := func(s string) RouterExpr { return RouterAddr{Addr: netip.MustParseAddr(s)} }
	rtrs := func(s string) RouterExpr {
		n, err := types.ParseSetName(s)
		if err != nil {
			t.Fatal(err)
		}
		return RouterSetRef{Name: n}
	}
	cases := []struct {
		in           string
		router, atRt RouterExpr
	}{
		{"from AS1 192.0.2.1 at 192.0.2.2 accept ANY", addr("192.0.2.1"), addr("192.0.2.2")},
		{"from AS1 at 2001:db8::1 accept ANY", nil, addr("2001:db8::1")},
		{"from AS1 rtrs-a AND rtrs-b at 1.1.1.1 EXCEPT 1.1.1.2 accept ANY",
			RouterExprBinary{Op: RouterAnd, L: rtrs("RTRS-A"), R: rtrs("RTRS-B")},
			RouterExprBinary{Op: RouterExcept, L: addr("1.1.1.1"), R: addr("1.1.1.2")}},
		{"from AS1 rtr1.example.net OR (rtr2.example.net AND AS1:RTRS-X) accept ANY",
			RouterExprBinary{Op: RouterOr, L: RouterName{Name: "rtr1.example.net"},
				R: RouterExprBinary{Op: RouterAnd, L: RouterName{Name: "rtr2.example.net"}, R: rtrs("AS1:RTRS-X")}}, nil},
	}
	for _, c := range cases {
		imp, diags := ParseImport(c.in)
		if len(diags) != 0 {
			t.Errorf("%q: diagnostics %v", c.in, diagRules(diags))
			continue
		}
		pa := factor(t, imp.Expr).Peers[0].Peering.(PeeringAS)
		if !reflect.DeepEqual(pa.Router, c.router) || !reflect.DeepEqual(pa.AtRouter, c.atRt) {
			t.Errorf("%q: Router %#v at %#v", c.in, pa.Router, pa.AtRouter)
		}
	}
}

// What is not a router is reported, not silently taken for one: a bare label
// (real RIPE data has "from AS174 PEERING") warns; a dangling or missing
// operator, or a term that is no router at all, is an error.
func TestRouterExpressionsAreValidated(t *testing.T) {
	cases := map[string][]string{
		"from AS174 PEERING accept ANY":               {"policy/router"},
		"from AS1 1.2.3.4 AND accept ANY":             {"policy/router"},
		"from AS1 1.2.3.4 1.2.3.5 accept ANY":         {"policy/router"},
		"from AS1 at rtr!x accept ANY":                {"policy/router"},
		"from AS1 RS-FOO accept ANY":                  {"policy/router"},
		"from AS1 (192.0.2.1 OR 192.0.2.2 accept ANY": {"policy/router"},
	}
	for in, want := range cases {
		if _, diags := ParseImport(in); !reflect.DeepEqual(diagRules(diags), want) {
			t.Errorf("%q: diagnostics %v, want %v", in, diagRules(diags), want)
		}
	}
}

// Actions name the rp-attribute and the method separately, so a community
// deletion is never mistaken for an addition.
func TestActionShape(t *testing.T) {
	as := actions(t, "from AS1 action pref = 100; community .= {1:2}; community.append(3:4, 5:6); community.delete(7:8); aspath.prepend(AS1, AS1) accept ANY")
	want := []Action{
		{Attr: "pref", Op: ActionAssign, Value: "100", Raw: "pref = 100"},
		{Attr: "community", Op: ActionAppend, Value: "{1:2}", Raw: "community .= {1:2}"},
		{Attr: "community", Method: "append", Op: ActionMethod, Args: []string{"3:4", "5:6"}, Raw: "community.append(3:4, 5:6)"},
		{Attr: "community", Method: "delete", Op: ActionMethod, Args: []string{"7:8"}, Raw: "community.delete(7:8)"},
		{Attr: "aspath", Method: "prepend", Op: ActionMethod, Args: []string{"AS1", "AS1"}, Raw: "aspath.prepend(AS1, AS1)"},
	}
	if !reflect.DeepEqual(as, want) {
		t.Errorf("actions\n got %+v\nwant %+v", as, want)
	}
	if got, ok := as[3].Communities(); ok {
		t.Errorf("community.delete reported as adding %v", got)
	}
}

// A community filter records what it tests and the values it names.
func TestFilterCommunityShape(t *testing.T) {
	for in, want := range map[string]FilterCommunity{
		"community(65000:1, NO_EXPORT)": {Op: CommunityContains, Values: []string{"65000:1", "NO_EXPORT"}, Raw: "community(65000:1, NO_EXPORT)"},
		"community.contains(65000:1)":   {Op: CommunityContains, Values: []string{"65000:1"}, Raw: "community.contains(65000:1)"},
		"Community.Contains(65000:1)":   {Op: CommunityContains, Values: []string{"65000:1"}, Raw: "Community.Contains(65000:1)"},
	} {
		f, diags := ParseFilter(in)
		if len(diags) != 0 || !reflect.DeepEqual(f, want) {
			t.Errorf("ParseFilter(%q) = %#v, %v; want %#v", in, f, diagRules(diags), want)
		}
	}
}
