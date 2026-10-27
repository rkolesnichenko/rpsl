package object

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// LACNIC writes an inetnum's key as a prefix, often abbreviated
// ("inetnum: 2.152.0/22"), where RIPE writes "lo - hi": it reads as the
// prefix's range, with a Warning.
func TestInetnumPrefixKey(t *testing.T) {
	cases := []struct {
		key    string
		lo, hi string // "" when the key is an Error
		rules  []string
	}{
		{"200.16.0.0/16", "200.16.0.0", "200.16.255.255", []string{"object/inetnum-prefix-key"}},
		{"2.152.0/22", "2.152.0.0", "2.152.3.255", []string{"object/inetnum-prefix-key", "object/inetnum-abbreviated-prefix"}},
		{"200.16.248.5/24", "200.16.248.0", "200.16.248.255", []string{"object/inetnum-prefix-key", "object/inetnum-host-bits"}},
		{"010.000.000.000/8", "10.0.0.0", "10.255.255.255", []string{"object/inetnum-prefix-key", "object/inetnum-leading-zeros"}},
		{"192.0.2.7/32", "192.0.2.7", "192.0.2.7", []string{"object/inetnum-prefix-key"}},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255", []string{"object/inetnum-prefix-key"}},
		{"192.0.2.0 - 192.0.2.255", "192.0.2.0", "192.0.2.255", nil},
		{"2001:db8::/32", "", "", []string{"object/inetnum-range"}},
		{"::ffff:10.0.0.0/104", "", "", []string{"object/inetnum-range"}}, // IPv4-mapped is IPv6
		{"10.0.0.0/33", "", "", []string{"object/inetnum-range"}},
		{"10.0.0.0/", "", "", []string{"object/inetnum-range"}},
		{"10.0.0.0", "", "", []string{"object/inetnum-range"}},
	}
	for _, c := range cases {
		obj, diags := Decode(parse("inetnum: " + c.key + "\nnetname: N\n"))
		in := obj.(*Inetnum)
		var lo, hi netip.Addr
		if c.lo != "" {
			lo, hi = netip.MustParseAddr(c.lo), netip.MustParseAddr(c.hi)
		}
		if in.Lo != lo || in.Hi != hi {
			t.Errorf("%q: range %v - %v, want %v - %v", c.key, in.Lo, in.Hi, lo, hi)
		}
		var rules []string
		for _, d := range diags {
			want := "warning"
			if c.lo == "" {
				want = "error"
			}
			if d.Severity.String() != want {
				t.Errorf("%q: %s %s, want a %s", c.key, d.Severity, d.Rule, want)
			}
			rules = append(rules, d.Rule)
		}
		if c.key == "10.0.0.0/33" && (len(diags) != 1 || !strings.Contains(diags[0].Message, "expected 'lo - hi' or an IPv4 prefix")) {
			t.Errorf("%q: %v, want the message to say what an inetnum key may be", c.key, diags)
		}
		slices.Sort(rules)
		want := slices.Clone(c.rules)
		slices.Sort(want)
		if !slices.Equal(rules, want) {
			t.Errorf("%q: rules %v, want %v", c.key, rules, want)
		}
	}
}
