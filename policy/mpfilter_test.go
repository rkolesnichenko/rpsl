package policy

import (
	"fmt"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

func TestParseMPFilter(t *testing.T) {
	for _, c := range []struct {
		in, afis, filter string
		errs             bool
	}{
		{"AS-FOO", "[]", "AS-FOO", false},
		{"afi ipv6.unicast AS-FOO", "[ipv6.unicast]", "AS-FOO", false},
		{"afi ipv4.unicast, ipv6.unicast {10.0.0.0/8}", "[ipv4.unicast ipv6.unicast]", "{10.0.0.0/8}", false},
		{"afi ipv4 ipv6 ANY", "[ipv4 ipv6]", "ANY", false},
		{"afi ipv4 any", "[ipv4]", "ANY", false}, // the last "any" is the filter
		{"afi any ANY", "[any]", "ANY", false},
		{"AFI IPV6.UNICAST AS1", "[ipv6.unicast]", "AS1", false},
		{"afi AS-FOO", "[]", "AS-FOO", true}, // empty afi list
		{"afi", "[]", "", true},
	} {
		afis, f, diags := ParseMPFilter(c.in)
		errs := false
		for _, d := range diags {
			errs = errs || d.Severity >= ast.Error
		}
		got := fmt.Sprint(afis)
		if afis == nil {
			got = "[]"
		}
		text := ""
		if f != nil {
			text = exprText(f)
		}
		if got != c.afis || text != c.filter || errs != c.errs {
			t.Errorf("ParseMPFilter(%q) = %s, %q, errors %v; want %s, %q, errors %v (diags %v)",
				c.in, got, text, errs, c.afis, c.filter, c.errs, diags)
		}
	}
}
