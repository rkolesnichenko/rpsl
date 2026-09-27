package nrtm4

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

const (
	ripeUNF = "https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose"
	ripeKey = "https://ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt"
)

func ripeClient(t *testing.T) *Client {
	t.Helper()
	resp, err := http.Get(ripeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	key, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{URL: ripeUNF, Database: "RIPE", PublicKey: string(key)}
}

// TestLiveRIPE (opt-in: RPSL_LIVE=1) verifies the notification file the RIPE
// Database publishes with the key RIPE publishes, and fetches, hash-checks
// and parses its newest delta.
func TestLiveRIPE(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to run against nrtm.db.ripe.net")
	}
	c := ripeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := c.notification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.st.stale || len(n.Deltas) == 0 {
		t.Fatalf("RIPE's notification file: stale %v, %d deltas", c.st.stale, len(n.Deltas))
	}
	c.st.objs = map[string]object.Object{}
	if _, _, _, err := c.applyDelta(ctx, n, n.Deltas[len(n.Deltas)-1]); err != nil {
		t.Fatal(err)
	}
	t.Logf("RIPE at version %d (snapshot %d), %d deltas listed", n.Version, n.Snapshot.Version, len(n.Deltas))
}

// TestLiveRIPEMirror (opt-in: RPSL_LIVE_NRTM=1; downloads RIPE's snapshot,
// about 400 MB) mirrors the RIPE Database from scratch and expands a set
// whose routes are stable.
func TestLiveRIPEMirror(t *testing.T) {
	if os.Getenv("RPSL_LIVE_NRTM") == "" {
		t.Skip("set RPSL_LIVE_NRTM=1 to mirror the RIPE Database (about 400 MB)")
	}
	c := ripeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	start := time.Now()
	u, err := c.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v in %s; %d objects held", u, time.Since(start).Round(time.Second), c.Status().Objects)
	routes, _ := c.Source().OriginatedRoutes(ctx, 3333, types.AFIAny)
	found := false
	for _, p := range routes {
		found = found || p.String() == "193.0.0.0/21"
	}
	if !found {
		t.Errorf("AS3333 originates %v, not 193.0.0.0/21", routes)
	}
	u, err = c.Sync(ctx)
	if err != nil || u.Snapshot {
		t.Errorf("the second Sync: %+v, %v", u, err)
	}
	if c.Status().CurrentKey == "" {
		t.Error("no current key")
	}
}
