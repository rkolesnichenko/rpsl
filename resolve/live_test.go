package resolve_test

import (
	"context"
	"errors"
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
// the real public services (RPSL_LIVE=1): irrd against RADB, whois against both
// RIPE and RADB (two different server implementations), and rdap against RIPE. It asserts only stable facts — RIPE
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
		"irrd (whois.radb.net, !s RIPE)": &irrd.Source{Addr: "whois.radb.net:43", Sources: []string{"RIPE"}},
		"whois (whois.ripe.net)":         &whois.Source{Addr: "whois.ripe.net:43"},
		// RADB runs IRRd, whose whois parser needs every flag before "-i".
		"whois (whois.radb.net)": &whois.Source{Addr: "whois.radb.net:43"},
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
	// A missing set takes the "!i" D answer and then the "!m" check that tells a
	// missing set from an empty one.
	t.Run("irrd missing set", func(t *testing.T) {
		missing, err := types.ParseSetName("AS-RPSL-GO-NO-SUCH-SET")
		if err != nil {
			t.Fatal(err)
		}
		src := &irrd.Source{Addr: "whois.radb.net:43"}
		if _, err := src.GetSet(ctx, missing); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("GetSet(%s) err = %v, want ErrNotFound", missing, err)
		}
	})
	t.Run("rdap (rdap.db.ripe.net)", func(t *testing.T) {
		a, err := (&rdap.Client{BaseURL: "https://rdap.db.ripe.net"}).LookupAutnum(ctx, 3333)
		if err != nil || a.Name == "" || a.StartAutnum != 3333 || a.EndAutnum != 3333 {
			t.Errorf("LookupAutnum(AS3333) = %+v, %v; want a named record for AS3333", a, err)
		} else {
			t.Logf("AS3333: %s (%s)", a.Name, a.Handle)
		}
	})
}
