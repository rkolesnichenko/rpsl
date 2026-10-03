// Package rpsldtest builds and serves rpsld snapshots for tests: RPSL texts
// split into one registry per source, served by irrdserver on a localhost
// port until the test ends. Only _test.go files import it.
package rpsldtest

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
)

// Snapshot builds what rpsld serves for texts: a registry per source, in
// the order given, each from a Corpus (KeepPolicy, KeepRouteText) of the
// objects whose source: is that registry; objects of other sources are
// dropped. Serial 0. It calls t.Fatal, so only the test's own goroutine may
// call it.
func Snapshot(t testing.TB, texts []string, opts irrdq.SnapshotOptions, sources ...string) *irrdq.Snapshot {
	t.Helper()
	corpora := map[string]*resolve.Corpus{}
	for _, s := range sources {
		corpora[strings.ToUpper(s)] = &resolve.Corpus{KeepPolicy: true, KeepRouteText: true}
	}
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		if o == nil {
			continue
		}
		obj, _ := object.Decode(o)
		src := ""
		if a, ok := o.GetFirst("source"); ok {
			src = strings.ToUpper(strings.TrimSpace(a.Value))
		}
		if c := corpora[src]; c != nil {
			c.Put(obj)
		}
	}
	var regs []*irrdq.Registry
	for _, s := range sources {
		r, err := irrdq.NewRegistry(s, 0, corpora[strings.ToUpper(s)])
		if err != nil {
			t.Fatal(err)
		}
		regs = append(regs, r)
	}
	snap, err := irrdq.NewSnapshot(regs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// Serve serves snap on a localhost port until the test ends; it returns the
// address. Like Snapshot, it is for the test's own goroutine.
func Serve(t testing.TB, snap *irrdq.Snapshot) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &irrdserver.Server{Snapshot: func() *irrdq.Snapshot { return snap }}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("rpsldtest: Shutdown: %v", err)
		}
		if err := <-done; err != nil && !errors.Is(err, irrdserver.ErrServerClosed) {
			t.Errorf("rpsldtest: Serve: %v", err)
		}
	})
	return ln.Addr().String()
}
