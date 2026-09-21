package resolve_test

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/rdap"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestLiveSmoke is an opt-in, read-only check of the network backends against
// the real public services (RPSL_LIVE=1). It asserts only stable facts — RIPE
// NCC's AS3333 originates 193.0.0.0/21 and its AS-RIPENCC as-set is non-empty —
// so it does not go stale as registry data changes.
func TestLiveSmoke(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to query whois.radb.net, whois.ripe.net and rdap.db.ripe.net")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	set, err := types.ParseSetName("AS-RIPENCC")
	if err != nil {
		t.Fatal(err)
	}
	ncc := netip.MustParsePrefix("193.0.0.0/21")

	sources := map[string]resolve.Source{
		"irrd (whois.radb.net, !s RIPE)": &irrd.Source{Addr: "whois.radb.net:43", Sources: "RIPE"},
		"whois (whois.ripe.net)":         &whois.Source{Addr: "whois.ripe.net:43"},
	}
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			routes, err := src.OriginatedRoutes(ctx, 3333, types.AFIv4)
			if err != nil || !slices.Contains(routes, ncc) {
				t.Errorf("OriginatedRoutes(AS3333) = %v, %v; want it to include %s", routes, err, ncc)
			}
			asns, err := (&resolve.Expander{Src: src}).ExpandAS(ctx, set)
			if err != nil || asns.Len() == 0 {
				t.Errorf("ExpandAS(AS-RIPENCC) = %v, %v; want a non-empty set", asns, err)
			}
			t.Logf("AS3333 routes: %d; AS-RIPENCC: %v (missing nested: %v)", len(routes), asns, asns.Missing())
		})
	}
	t.Run("rdap (rdap.db.ripe.net)", func(t *testing.T) {
		a, err := (&rdap.Client{BaseURL: "https://rdap.db.ripe.net"}).LookupAutnum(ctx, 3333)
		if err != nil || a.Name == "" {
			t.Errorf("LookupAutnum(AS3333) = %+v, %v; want a named record", a, err)
		} else {
			t.Logf("AS3333: %s (%s)", a.Name, a.Handle)
		}
	})
}
