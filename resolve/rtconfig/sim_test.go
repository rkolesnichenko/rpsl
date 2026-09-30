package rtconfig

import (
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// simulate parses text as v's configuration and runs r through the policy the
// session's neighbour uses.
func simulate(t *testing.T, v Vendor, text string, s peval.Session, export bool, r cfgsim.Route) (bool, cfgsim.Attrs) {
	t.Helper()
	if v == BIRD2 {
		if err := cfgsim.BIRDSyntax(text); err != nil && !errors.Is(err, cfgsim.ErrNoBIRD) {
			t.Fatalf("bird -p refuses the configuration: %v\n%s", err, text)
		}
	}
	c, err := cfgsim.Parse(v.String(), text)
	if err != nil {
		t.Fatalf("%v config does not parse: %v\n%s", v, err, text)
	}
	name, ok := c.Attached(s.PeerRtr, export)
	if !ok {
		t.Fatalf("%v config attaches no policy to %v:\n%s", v, s.PeerRtr, text)
	}
	accepted, a, err := c.Policy(name, r)
	if err != nil {
		t.Fatalf("%v policy %s: %v\n%s", v, name, err, text)
	}
	return accepted, a
}

func rt(p string, path []types.ASN, comms ...string) cfgsim.Route {
	return cfgsim.Route{Prefix: netip.MustParsePrefix(p), Path: path, Communities: comms}
}

// writeImport writes s's import policy as a whole configuration: WriteImport,
// then the sessions a BIRD writer collected.
func writeImport(g *Generator, w io.Writer, s peval.Session, p peval.Policy) error {
	if err := g.WriteImport(w, s, p); err != nil {
		return err
	}
	return g.WriteSessions(w)
}
