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
		{"route: 192.0.2.0/24\norigin: AS1\nholes: 192.0.2.1/25\n", "object/route-holes-host-bits", ast.Warning},
		{"route6: 2001:db8::/32\norigin: AS1\nholes: 2001:db8::1/48\n", "object/route6-holes-host-bits", ast.Warning},
		{"inet6num: 2001:db8::1/32\n", "object/inet6num-host-bits", ast.Warning},
		{"inet6num: 192.0.2.0/24\n", "object/inet6num-prefix", ast.Error},
		{"inetnum: 192.0.2.255 - 192.0.2.0\n", "object/inetnum-range", ast.Error},
		{"inetnum: 2001:db8:: - 2001:db8::ff\n", "object/inetnum-range", ast.Error},
		{"inetnum: 192.0.2.0 - 2001:db8::\n", "object/inetnum-range", ast.Error},
		{"as-block: AS10 - AS1\n", "object/as-block-range", ast.Error},
		{"route-set: RS-FOO\nmembers: 192.0.2.1/24^+\n", "object/route-set-members-host-bits", ast.Warning},
		{"route-set: RS-FOO\nmp-members: 2001:db8::1/32\n", "object/route-set-mp-members-host-bits", ast.Warning},
		{"route-set: RS-FOO\nmembers: 2001:db8::/32^+\n", "object/route-set-members-afi", ast.Warning},
		{"aut-num: AS1\nmember-of: RS-FOO\n", "object/aut-num-member-of-class", ast.Warning},
		{"route: 192.0.2.0/24\norigin: AS1\nmember-of: AS-FOO\n", "object/route-member-of-class", ast.Warning},
		{"route6: 2001:db8::/32\norigin: AS1\nmember-of: RTRS-FOO\n", "object/route6-member-of-class", ast.Warning},
		{"inet-rtr: r.example\nlocal-as: AS1\nmember-of: AS-FOO\n", "object/inet-rtr-member-of-class", ast.Warning},
		{"route-set: AS-FOO\n", "object/route-set-name-class", ast.Warning},
		{"as-set: RS-FOO\n", "object/as-set-name-class", ast.Warning},
		{"filter-set: RS-FOO\n", "object/filter-set-name-class", ast.Warning},
		{"peering-set: AS-FOO\nmp-peering: AS1\n", "object/peering-set-name-class", ast.Warning},
		{"rtr-set: AS-FOO\n", "object/rtr-set-name-class", ast.Warning},
		{"mntner:\nauth: NONE\n", "object/empty-key", ast.Error},
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
		"route-set: RS-FOO\nmembers: 192.0.2.0/24^+, 10.0.0.0/8\n",
		"route-set: RS-FOO\nmp-members: 2001:db8::/32, 192.0.2.0/24\n",
		"mntner: MNT-X\n",
		"inetnum: 192.0.2.7 - 192.0.2.7\n",
		"aut-num: AS1\nmember-of: AS-FOO, AS1:AS-BAR\n",
		"route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-FOO\n",
		"inet-rtr: r.example\nlocal-as: AS1\nmember-of: RTRS-FOO\n",
		"as-block: AS1 - AS1\n",
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

// An impossible range or a prefix of the wrong family is an Error and is not
// in the typed struct; a hole with host bits is read as its network.
func TestImpossibleValuesAreDropped(t *testing.T) {
	decode := func(src string) Object { obj, _ := Decode(parse(src)); return obj }
	in := decode("inetnum: 192.0.2.255 - 192.0.2.0\n").(Inetnum)
	if in.Lo.IsValid() || in.Hi.IsValid() {
		t.Errorf("reversed inetnum range = %s - %s, want none", in.Lo, in.Hi)
	}
	b := decode("as-block: AS10 - AS1\n").(AsBlock)
	if b.Lo != 0 || b.Hi != 0 {
		t.Errorf("reversed as-block = %s - %s, want none", b.Lo, b.Hi)
	}
	in6 := decode("inet6num: 192.0.2.0/24\n").(Inet6num)
	if in6.Prefix.IsValid() {
		t.Errorf("IPv4 inet6num = %s, want none", in6.Prefix)
	}
	r := decode("route: 192.0.2.0/24\norigin: AS1\nholes: 192.0.2.1/25\n").(Route)
	if len(r.Holes) != 1 || r.Holes[0].String() != "192.0.2.0/25" {
		t.Errorf("holes = %v, want [192.0.2.0/25]", r.Holes)
	}
}
