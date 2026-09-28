package irrd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
)

func newBackend(t *testing.T, db *irrtest.DB) *Source {
	return &Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
}

func closeBackend(src *Source) { src.Close() }

func TestPolicyLookups(t *testing.T) {
	db := irrtest.New(
		"aut-num: AS1\nas-name: ONE-RIPE\nimport: from AS2 accept ANY\nsource: RIPE\n",
		"aut-num: AS1\nas-name: ONE-PROXY\nsource: RADB\n",
		"inet-rtr: rtr1.example.net\nlocal-as: AS1\nifaddr: 192.0.2.1 masklen 30\nsource: RIPE\n",
	)
	src := newBackend(t, db) // the package's Source, Sources RIPE then RADB
	defer closeBackend(src)
	var _ resolve.PolicySource = src
	ctx := context.Background()
	for source, want := range map[string]string{"": "ONE-RIPE", "RADB": "ONE-PROXY"} {
		an, err := src.AutNum(ctx, 1, source)
		if err != nil || an.AsName != want || len(an.Imports) != 1 && want == "ONE-RIPE" {
			t.Errorf("AutNum(AS1, %q) = %q, %v; want %q", source, an.AsName, err, want)
		}
	}
	if _, err := src.AutNum(ctx, 9, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("missing aut-num: %v", err)
	}
	if _, err := src.AutNum(ctx, 1, "NOSUCH"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: %v", err)
	}
	if ir, err := src.InetRtr(ctx, "rtr1.example.net", ""); err != nil || ir.LocalAS != 1 {
		t.Errorf("InetRtr = %+v, %v", ir, err)
	}
	if _, err := src.InetRtr(ctx, "rtr1.example.net\n!q", ""); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a router name with a newline was not refused: %v", err)
	}
}
