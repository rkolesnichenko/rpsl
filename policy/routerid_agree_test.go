package policy

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// A router is the same thing to the policy parser and to types.ParseRouterID,
// which reads rtr-set members and inet-rtr names: both take an address or a
// DNS name, and both refuse a mistyped address such as "1.2.3" — a name's last
// label is never all digits.
func TestRouterAgreesWithParseRouterID(t *testing.T) {
	for _, r := range []string{
		"192.0.2.1", "2001:db8::1", "rtr1.example.net", "a1.b2", "rtr.example.1net",
		"1.2.3", "256.0.0.1", "1.2.3.4.5", "10.1.1.", "rtr.1", "rtr_1.example.net",
	} {
		_, typesErr := types.ParseRouterID(r)
		_, diags := ParsePeering("AS1 " + r)
		policyErr := false
		for _, d := range diags {
			policyErr = policyErr || d.Severity == ast.Error
		}
		if (typesErr != nil) != policyErr {
			t.Errorf("%q: ParseRouterID error %v, policy diagnostics %v", r, typesErr, diags)
		}
	}
}
