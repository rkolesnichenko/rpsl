package policy

import (
	"fmt"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseIfaddr(t *testing.T) {
	t.Run("structure", func(t *testing.T) {
		v, ds := ParseIfaddr("1.1.1.1 masklen 30 action mtu = 1500;")
		clean(t, "ifaddr", ds)
		if v.Addr.String() != "1.1.1.1" || v.Masklen != 30 {
			t.Errorf("ParseIfaddr = %v/%d, want 1.1.1.1/30", v.Addr, v.Masklen)
		}
		if len(v.Actions) != 1 || v.Actions[0].Attr != "mtu" {
			t.Fatalf("Actions = %#v, want one mtu action", v.Actions)
		}
		if n, ok := v.Actions[0].Int(); !ok || n != 1500 {
			t.Errorf("mtu = %d, %v; want 1500", n, ok)
		}
		if v.Raw != "1.1.1.1 masklen 30 action mtu = 1500;" {
			t.Errorf("Raw = %q", v.Raw)
		}
	})

	for _, s := range []string{
		"1.1.1.1 masklen 30",
		"2001:db8::1 masklen 64",
		"1.1.1.1 masklen 0",
		"1.1.1.1 MASKLEN 30",
		"1.1.1.1 masklen 32 action mtu = 1500; dpa = 5",
	} {
		if _, ds := ParseIfaddr(s); len(errorsOf(ds)) != 0 {
			t.Errorf("ParseIfaddr(%q): %v", s, errorsOf(ds))
		}
	}

	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"1.1.1.1", "policy/ifaddr"},            // masklen is not optional
		{"1.1.1.1 masklen 33", "policy/ifaddr"}, // longer than an IPv4 address
		{"2001:db8::1 masklen 129", "policy/ifaddr"},
		{"1.1.1.1 masklen -1", "policy/ifaddr"},
		{"1.1.1.1 masklen x", "policy/ifaddr"},
		{"nonsense masklen 30", "policy/ifaddr"},
		{"masklen 30", "policy/ifaddr"},
		{"1.1.1.1 masklen 30 extra", "policy/trailing"},
	} {
		_, ds := ParseIfaddr(c.in)
		if rules := errorsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParseIfaddr(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
		}
	}
}

func TestParseInterface(t *testing.T) {
	t.Run("afi forms", func(t *testing.T) {
		// RFC 4012 §4 writes the family bare; the "afi" keyword is also accepted.
		for _, s := range []string{
			"afi ipv6.unicast 2001:db8::1 masklen 48",
			"ipv6.unicast 2001:db8::1 masklen 48",
		} {
			v, ds := ParseInterface(s)
			clean(t, "interface "+s, ds)
			want := types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
			if v.AFI != want {
				t.Errorf("ParseInterface(%q).AFI = %v, want %v", s, v.AFI, want)
			}
			if v.Addr.String() != "2001:db8::1" || v.Masklen != 48 {
				t.Errorf("ParseInterface(%q) = %v/%d", s, v.Addr, v.Masklen)
			}
		}
		// No family at all: the address must not be eaten by the afi parse.
		v, ds := ParseInterface("2001:db8::1 masklen 48")
		clean(t, "interface", ds)
		if v.AFI != (types.AddrFamily{}) {
			t.Errorf("AFI = %v, want the zero value", v.AFI)
		}
		if v.Addr.String() != "2001:db8::1" {
			t.Errorf("Addr = %v, want 2001:db8::1", v.Addr)
		}
	})

	t.Run("tunnel", func(t *testing.T) {
		v, ds := ParseInterface("2001:db8::1 masklen 48 action mtu = 1500; tunnel 192.0.2.1,GRE")
		clean(t, "interface", ds)
		if v.Tunnel == nil {
			t.Fatal("Tunnel = nil")
		}
		if v.Tunnel.Remote.String() != "192.0.2.1" || v.Tunnel.Type != "GRE" {
			t.Errorf("Tunnel = %+v, want 192.0.2.1/GRE", *v.Tunnel)
		}
		if len(v.Actions) != 1 {
			t.Errorf("Actions = %#v, want one", v.Actions)
		}
	})

	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"afi 2001:db8::1 masklen 48", "policy/interface"}, // afi without a family
		{"afi nonsense 2001:db8::1 masklen 48", "policy/interface"},
		{"2001:db8::1 masklen 48 tunnel 192.0.2.1", "policy/interface"}, // no ','
		{"2001:db8::1 masklen 48 tunnel nonsense,GRE", "policy/interface"},
		{"2001:db8::1 masklen 129", "policy/interface"},
	} {
		_, ds := ParseInterface(c.in)
		if rules := errorsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParseInterface(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
		}
	}
}

func TestParsePeer(t *testing.T) {
	t.Run("structure", func(t *testing.T) {
		v, ds := ParsePeer("BGP4 192.0.2.1 asno(AS2), flap_damp()")
		clean(t, "peer", ds)
		if v.Protocol != "BGP4" {
			t.Errorf("Protocol = %q, want BGP4", v.Protocol)
		}
		addr, ok := v.Peer.(RouterAddr)
		if !ok || addr.Addr.String() != "192.0.2.1" {
			t.Errorf("Peer = %#v, want RouterAddr 192.0.2.1", v.Peer)
		}
		if len(v.Options) != 2 {
			t.Fatalf("Options = %+v, want 2", v.Options)
		}
		if v.Options[0].Name != "asno" || len(v.Options[0].Args) != 1 || v.Options[0].Args[0] != "AS2" {
			t.Errorf("Options[0] = %+v, want asno(AS2)", v.Options[0])
		}
		if v.Options[0].Raw != "asno(AS2)" {
			t.Errorf("Options[0].Raw = %q", v.Options[0].Raw)
		}
		if v.Options[1].Name != "flap_damp" || len(v.Options[1].Args) != 0 {
			t.Errorf("Options[1] = %+v, want flap_damp()", v.Options[1])
		}
	})

	t.Run("peer kinds", func(t *testing.T) {
		for _, c := range []struct {
			in   string
			want any
		}{
			{"BGP4 192.0.2.1", RouterAddr{}},
			{"OSPF rtr.example.net", RouterName{}},
			{"BGP4 RTRS-FOO", RouterSetRef{}},
		} {
			v, ds := ParsePeer(c.in)
			clean(t, "peer "+c.in, ds)
			if got, want := typeName(v.Peer), typeName(c.want); got != want {
				t.Errorf("ParsePeer(%q).Peer is %s, want %s", c.in, got, want)
			}
		}
	})

	for _, c := range []struct{ in, rule string }{
		{"", "policy/empty"},
		{"BGP4", "policy/router"},
		{"BGP4 192.0.2.1 asno(", "policy/peer"},
	} {
		_, ds := ParsePeer(c.in)
		if rules := errorsOf(ds); !hasRule(rules, c.rule) {
			t.Errorf("ParsePeer(%q) rules = %v, want one to be %s", c.in, rules, c.rule)
		}
	}

	// An empty item drops nothing, so it warns rather than erroring.
	for _, in := range []string{
		"BGP4 192.0.2.1 ,",
		"BGP4 192.0.2.1 , asno(AS2)",
		"BGP4 192.0.2.1 asno(AS2),,flap_damp()",
		"BGP4 192.0.2.1 asno(AS2),",
	} {
		_, ds := ParsePeer(in)
		if rules := errorsOf(ds); len(rules) != 0 {
			t.Errorf("ParsePeer(%q) errors = %v, want none", in, rules)
		}
		if rules := warningsOf(ds); !hasRule(rules, "policy/peer") {
			t.Errorf("ParsePeer(%q) warnings = %v, want one to be policy/peer", in, rules)
		}
	}
}

func hasRule(rules []string, want string) bool {
	for _, r := range rules {
		if r == want {
			return true
		}
	}
	return false
}

// typeName renders a value's dynamic type, so a test can assert which variant
// of a sealed interface a parser produced.
func typeName(v any) string { return fmt.Sprintf("%T", v) }
