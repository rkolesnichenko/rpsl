package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// An abbreviated IPv4 prefix in a prefix list reads with the missing octets
// zero, as IRRd reads route-set members, with a Warning on the token.
func TestAbbreviatedPrefixes(t *testing.T) {
	for _, c := range []struct {
		in, want string
		at       int
	}{
		{"{143.208.148/22^+, 192.0.2.0/24}", "143.208.148.0/22^+", 1},
		{"{192.0.2.0/24, 10/8}", "10.0.0.0/8", 15},
	} {
		f, ds := ParseFilter(c.in)
		if len(ds) != 1 || ds[0].Rule != "policy/abbreviated-prefix" || ds[0].Severity != ast.Warning ||
			ds[0].Span.StartByte != c.at || !strings.Contains(ds[0].Message, "abbreviated") {
			t.Errorf("%q: diagnostics %+v, want one policy/abbreviated-prefix Warning at byte %d", c.in, ds, c.at)
		}
		pl, ok := f.(FilterPrefixList)
		if !ok || !strings.Contains(pl.String(), c.want) {
			t.Errorf("%q parsed as %#v, want it to hold %s", c.in, f, c.want)
		}
	}
	// Zero-padded and abbreviated at once: both are reported.
	_, ds := ParseImport("from AS1 accept {010.1/16}")
	if len(ds) != 2 {
		t.Errorf("diagnostics %v, want leading-zeros and abbreviated-prefix", diagRules(ds))
	}
}
