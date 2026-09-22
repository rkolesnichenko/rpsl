package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// FuzzParseFilter asserts the standalone filter parser never panics.
func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{
		"ANY", "PeerAS", "{192.0.2.0/24^+}", "AS65000",
		"AS-FOO AND NOT AS65001", "(AS1 OR AS2)", "community(65000:1)", "AS1 (AS2)",
		"<^AS1+$>", "", "{", "()", "fltr-EXAMPLE",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, p := parseFilterValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, flt, p.diags, func(v string) (any, []ast.Diagnostic) { return ParseFilter(v) })
		walkFilter(flt, func(f Filter) {
			if c, ok := f.(FilterCommunity); ok && !strings.HasPrefix(strings.ToLower(c.Raw), "community") {
				t.Fatalf("ParseFilter(%q) made a FilterCommunity of %q", s, c.Raw)
			}
		})
	})
}

// walkFilter calls fn for f and every filter nested in it.
func walkFilter(f Filter, fn func(Filter)) {
	fn(f)
	switch x := f.(type) {
	case FilterAnd:
		for _, t := range x.Terms {
			walkFilter(t, fn)
		}
	case FilterOr:
		for _, t := range x.Terms {
			walkFilter(t, fn)
		}
	case FilterNot:
		walkFilter(x.Inner, fn)
	}
}

// FuzzParsePeering asserts the standalone peering parser never panics.
func FuzzParsePeering(f *testing.F) {
	for _, s := range []string{
		"AS65000", "AS65000 at 192.0.2.1", "prng-EXAMPLE",
		"AS-FOO 192.0.2.1", "<^AS1$>", "", "at", "192.0.2.1 at",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		pe, p := parsePeeringValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, pe, p.diags, func(v string) (any, []ast.Diagnostic) { return ParsePeering(v) })
	})
}

// FuzzParseInject asserts the inject: parser never panics and keeps the
// package's parse properties.
func FuzzParseInject(f *testing.F) {
	for _, s := range []string{
		"at 1.1.1.1", "at 1.1.1.1 action dpa = 100; upon HAVE-COMPONENTS {10.0.0.0/8}",
		"upon STATIC", "upon NOT EXCLUDE {10.0.0.0/8} AND STATIC",
		"upon (STATIC OR STATIC)", "at RTRS-X", "", "upon", "at", "upon {",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		in, p := parseInjectValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, in, p.diags, func(v string) (any, []ast.Diagnostic) { return ParseInject(v) })
	})
}

// FuzzParseComponents asserts the components: parser never panics.
func FuzzParseComponents(f *testing.F) {
	for _, s := range []string{
		"ATOMIC", "{10.0.0.0/8^+}", "ATOMIC {10.0.0.0/8}",
		"protocol BGP4 {10.0.0.0/8} protocol OSPF {11.0.0.0/8}",
		"", "protocol", "{", "ATOMIC ATOMIC",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, p := parseComponentsValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, c, p.diags, func(v string) (any, []ast.Diagnostic) { return ParseComponents(v) })
	})
}

// FuzzParseAggrMtd asserts the aggr-mtd: parser never panics.
func FuzzParseAggrMtd(f *testing.F) {
	for _, s := range []string{
		"inbound", "outbound", "outbound AS-ANY", "outbound AS1 OR AS2",
		"", "sideways", "inbound AS1", "outbound (",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m, p := parseAggrMtdValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, m, p.diags, func(v string) (any, []ast.Diagnostic) { return ParseAggrMtd(v) })
	})
}

// FuzzParseIfaddr asserts the ifaddr: parser never panics.
func FuzzParseIfaddr(f *testing.F) {
	for _, s := range []string{
		"1.1.1.1 masklen 30", "1.1.1.1 masklen 30 action mtu = 1500;",
		"2001:db8::1 masklen 64", "", "1.1.1.1", "masklen", "1.1.1.1 masklen 999",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, p := parseIfaddrValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, v, p.diags, func(x string) (any, []ast.Diagnostic) { return ParseIfaddr(x) })
	})
}

// FuzzParseInterface asserts the RFC 4012 interface: parser never panics.
func FuzzParseInterface(f *testing.F) {
	for _, s := range []string{
		"2001:db8::1 masklen 48", "afi ipv6.unicast 2001:db8::1 masklen 48",
		"ipv4.unicast 1.1.1.1 masklen 30", "2001:db8::1 masklen 48 tunnel 192.0.2.1,GRE",
		"", "afi", "2001:db8::1 masklen 48 tunnel", "tunnel 1.1.1.1,",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, p := parseInterfaceValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, v, p.diags, func(x string) (any, []ast.Diagnostic) { return ParseInterface(x) })
	})
}

// FuzzParsePeer asserts the peer:/mp-peer: parser never panics.
func FuzzParsePeer(f *testing.F) {
	for _, s := range []string{
		"BGP4 192.0.2.1", "BGP4 192.0.2.1 asno(AS2), flap_damp()",
		"OSPF rtr.example.net", "BGP4 RTRS-X asno(AS2)",
		"", "BGP4", "BGP4 192.0.2.1 asno(", "BGP4 192.0.2.1 ,,",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, p := parsePeerValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, v, p.diags, func(x string) (any, []ast.Diagnostic) { return ParsePeer(x) })
	})
}

// The dictionary parsers keep each type expression as written, so their Args
// and Definition fields carry the source's own spacing. That is deliberate —
// the type language is not interpreted — but it means these values are not
// whitespace-invariant, so these targets check every property except the
// reparse ones.

// FuzzParseRPAttribute asserts the rp-attribute: parser never panics.
func FuzzParseRPAttribute(f *testing.F) {
	for _, s := range []string{
		"pref operator=(integer[0, 65535])",
		"community operator=(community_list) append(community_list)",
		"aspath prepend(list of as_number)", "x operator<<=(int)",
		"", "pref", "pref operator=", "pref operator=(", "x y(",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, p := parseRPAttributeValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, a, p.diags, nil)
	})
}

// FuzzParseTypedef asserts the typedef: parser never panics.
func FuzzParseTypedef(f *testing.F) {
	for _, s := range []string{
		"community_list list of union integer[1, 4294967295], enum[internet]",
		"as_number integer[1, 4294967295]", "", "lonely", "( )",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		td, p := parseTypedefValue(s)
		checkParse(t, s, td, p.diags, nil)
	})
}

// FuzzParseProtocol asserts the protocol: parser never panics.
func FuzzParseProtocol(f *testing.F) {
	for _, s := range []string{
		"BGP4 MANDATORY asno(as_number) OPTIONAL flap_damp()",
		"OSPF", "IS-IS", "", "BGP4 asno(as_number)", "BGP4 MANDATORY",
		"BGP4 OPTIONAL x( MANDATORY y()",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		pr, p := parseProtocolValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, pr, p.diags, nil)
	})
}
