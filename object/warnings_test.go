package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Values that decode but are almost certainly mistakes get a diagnostic instead
// of passing silently.
func TestSuspectValuesAreDiagnosed(t *testing.T) {
	cases := []struct {
		src  string
		rule string
		sev  ast.Severity
	}{
		{"route: 2001:db8::/32\norigin: AS1\n", "object/route-afi", ast.Warning},
		{"route: 192.0.2.1/24\norigin: AS1\n", "object/route-host-bits", ast.Warning},
		{"route6: 2001:db8::1/32\norigin: AS1\n", "object/route6-host-bits", ast.Warning},
		{"route: 192.0.2.0/24\norigin: AS1\nholes: 198.51.100.0/25\n", "object/route-holes-outside", ast.Warning},
		{"route: 192.0.2.0/24\norigin: AS1\nholes: 2001:db8::/48\n", "object/route-holes-outside", ast.Warning},
		{"route6: 2001:db8::/32\norigin: AS1\nholes: 2001:db9::/48\n", "object/route6-holes-outside", ast.Warning},
		{"route-set: AS-FOO\n", "object/route-set-name-class", ast.Warning},
		{"as-set: RS-FOO\n", "object/as-set-name-class", ast.Warning},
		{"filter-set: RS-FOO\n", "object/filter-set-name-class", ast.Warning},
		{"peering-set: AS-FOO\nmp-peering: AS1\n", "object/peering-set-name-class", ast.Warning},
		{"rtr-set: AS-FOO\n", "object/rtr-set-name-class", ast.Warning},
		{"mntner:\nauth: x\n", "object/empty-key", ast.Error},
		{"person:\nnic-hdl: EX1-RIPE\n", "object/empty-key", ast.Error},
		{"role:   \nnic-hdl: EX1-RIPE\n", "object/empty-key", ast.Error},
		{"inet-rtr:\nlocal-as: AS1\n", "object/empty-key", ast.Error},
		{"irt:\n", "object/empty-key", ast.Error},
		{"domain:\n", "object/empty-key", ast.Error},
		{"organisation:\n", "object/empty-key", ast.Error},
	}
	for _, c := range cases {
		_, diags := Decode(parse(c.src))
		if len(diags) != 1 || diags[0].Rule != c.rule || diags[0].Severity != c.sev {
			t.Errorf("Decode(%q) diagnostics = %+v, want one %s", c.src, diags, c.rule)
		}
	}
	// The unsuspicious forms stay clean.
	for _, src := range []string{
		"route: 192.0.2.0/24\norigin: AS1\nholes: 192.0.2.128/25\n",
		"route6: 2001:db8::/32\norigin: AS1\nholes: 2001:db8:1::/48\n",
		"route-set: RS-FOO\n",
		"mntner: MNT-X\n",
	} {
		if _, diags := Decode(parse(src)); len(diags) != 0 {
			t.Errorf("Decode(%q) diagnostics = %+v, want none", src, diags)
		}
	}
}

// RIPE allows several country: attributes on an inetnum/inet6num.
func TestInetnumCountryIsMultiValued(t *testing.T) {
	in := mustDecode(t, "inetnum: 192.0.2.0 - 192.0.2.255\ncountry: NL\ncountry: BE\n").(Inetnum)
	in6 := mustDecode(t, "inet6num: 2001:db8::/32\ncountry: NL\ncountry: BE\n").(Inet6num)
	if !reflect.DeepEqual(in.Country, []string{"NL", "BE"}) || !reflect.DeepEqual(in6.Country, []string{"NL", "BE"}) {
		t.Errorf("Country = %q / %q, want [NL BE]", in.Country, in6.Country)
	}
}
