package irrd

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
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

// Fix round 1, finding 1 (Important, plan-mandated; spec §7.3): an unscoped
// AutNum/InetRtr call (source == "") whose own Sources list names a registry
// the server refuses must surface that refusal loudly, not silently turn it
// into resolve.ErrNotFound — a bad default Sources list stays a loud error,
// as GetSet's unscoped path (getSet, which only intercepts errNotFound)
// already does on the same misconfigured Source.
func TestAutNumUnscopedUnknownSourceIsLoud(t *testing.T) {
	db := irrtest.New("aut-num: AS1\nas-name: ONE\nsource: RIPE\n")
	src := &Source{Addr: db.IRRd(t), Sources: []string{"NOSUCH"}, Timeout: 5 * time.Second}
	defer src.Close()
	ctx := context.Background()
	if _, err := src.AutNum(ctx, 1, ""); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unscoped AutNum with an unknown default source: err = %v, want a loud non-ErrNotFound error", err)
	}
	if _, err := src.InetRtr(ctx, "rtr1.example.net", ""); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unscoped InetRtr with an unknown default source: err = %v, want a loud non-ErrNotFound error", err)
	}
}

// Fix round 1, finding 2: a second scoped AutNum to a registry the server
// already refused does not dial or query again — the sub-source's cached
// refusal (Source.in's "unknown" flag) applies to AutNum/InetRtr exactly as
// it does to GetSet (TestUnknownRegistryIsRemembered).
func TestAutNumUnknownRegistryIsRemembered(t *testing.T) {
	db := irrtest.New("aut-num: AS1\nas-name: ONE\nsource: RIPE\n")
	addr := db.IRRd(t)
	var dials atomic.Int32
	src := &Source{Sources: []string{"RIPE"}, Timeout: 5 * time.Second,
		Dial: func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}}
	defer src.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := src.AutNum(ctx, 1, "NOSUCH"); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("lookup %d: err = %v", i, err)
		}
	}
	n := 0
	for _, cmd := range db.Commands() {
		if cmd == "!sNOSUCH" {
			n++
		}
	}
	if n != 1 || dials.Load() != 1 {
		t.Errorf("%d dials, %d %q; want the refusal asked for once", dials.Load(), n, "!sNOSUCH")
	}
}
