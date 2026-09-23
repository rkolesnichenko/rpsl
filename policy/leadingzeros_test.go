package policy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// A zero-padded IPv4 octet in a policy value is decimal, as RPSL and IRRd read
// it: the address is used in its canonical form, with a Warning on the token.
func TestLeadingZeros(t *testing.T) {
	oneWarning := func(t *testing.T, in string, ds []ast.Diagnostic, at int) {
		t.Helper()
		if len(ds) != 1 || ds[0].Rule != "policy/leading-zeros" || ds[0].Severity != ast.Warning ||
			ds[0].Span.StartByte != at || !strings.Contains(ds[0].Message, "decimal") {
			t.Fatalf("%q: diagnostics %+v, want one policy/leading-zeros Warning at byte %d", in, ds, at)
		}
	}

	in := "{064.006.160.000/19^+, 192.0.2.0/24}"
	f, ds := ParseFilter(in)
	oneWarning(t, in, ds, 1)
	if pl, ok := f.(FilterPrefixList); !ok || pl.Ranges[0].String() != "64.6.160.0/19^+" {
		t.Errorf("%q parsed as %#v", in, f)
	}

	in = "from AS1 010.000.000.001 accept ANY"
	imp, ds := ParseImport(in)
	oneWarning(t, in, ds, 9)
	if pa := imp.Expr.(Factor).Peers[0].Peering.(PeeringAS); pa.Router != (RouterAddr{Addr: netip.MustParseAddr("10.0.0.1")}) {
		t.Errorf("%q: router %#v, want 10.0.0.1", in, pa.Router)
	}

	in = "010.000.000.001 masklen 30"
	ifa, ds := ParseIfaddr(in)
	oneWarning(t, in, ds, 0)
	if ifa.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("%q: address %v, want 10.0.0.1", in, ifa.Addr)
	}
}
