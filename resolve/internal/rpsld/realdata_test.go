package rpsld

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
)

// TestRealDataServe (opt-in: RPSL_REALDATA=<the directory
// scripts/fetch-irr-dumps.sh fills>) loads one registry's dumps — RIPE's
// routing classes, or RADB's dump — with or without -keep-route-text, and
// logs what it costs: load time, heap, the registry's reload time and the
// heap while the old and the new registry are both alive. It then asks the
// served snapshot a sample of queries and requires answers.
//
// One process measures one registry in one configuration, so that no run
// holds two registries' dumps at once: RPSL_REALDATA_REGISTRY chooses RIPE
// (the default) or RADB, and RPSL_REALDATA_KEEPTEXT 0 (the default) or 1.
func TestRealDataServe(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	var ripe []string
	for _, class := range []string{"as-set", "route-set", "rtr-set", "filter-set", "peering-set", "aut-num", "inet-rtr", "route", "route6"} {
		ripe = append(ripe, filepath.Join(dir, "ripe", "ripe.db."+class+".gz"))
	}
	// Each registry's dumps and queries: a large as-set, its server-side
	// expansion, an AS's routes, its aut-num, and one of its routes by prefix.
	var spec SourceSpec
	var queries []string
	switch v := os.Getenv("RPSL_REALDATA_REGISTRY"); v {
	case "", "RIPE":
		spec = SourceSpec{Name: "RIPE", Kind: "dump", Paths: ripe}
		queries = []string{"!iAS-DECIX", "!aAS-DECIX", "!gAS3333", "!maut-num,AS3333", "!r193.0.0.0/21,o"}
	case "RADB":
		spec = SourceSpec{Name: "RADB", Kind: "dump", Paths: []string{filepath.Join(dir, "radb", "radb.db.gz")}}
		queries = []string{"!iAS-HURRICANE", "!aAS-HURRICANE", "!gAS6939", "!maut-num,AS6939", "!r23.95.45.0/24,o"}
	default:
		t.Fatalf("RPSL_REALDATA_REGISTRY=%q: want RIPE or RADB", v)
	}
	var keepText bool
	switch v := os.Getenv("RPSL_REALDATA_KEEPTEXT"); v {
	case "", "0":
	case "1":
		keepText = true
	default:
		t.Fatalf("RPSL_REALDATA_KEEPTEXT=%q: want 0 or 1", v)
	}
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	ctx := context.Background()
	base := heap()
	begin := time.Now()
	reg, st, err := loadDump(ctx, spec, keepText, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("keep-route-text=%v: %s: %d objects read, %d of another source left out", keepText, spec.Name, st.objects, st.other)
	loaded := time.Since(begin)
	held := heap() - base
	// The reload, as a dump watcher does it: the new registry is built while
	// the old one still serves. A sampler records the highest HeapAlloc it
	// sees meanwhile, garbage included.
	stop, sampled := make(chan struct{}), make(chan uint64)
	go func() {
		var hi uint64
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			hi = max(hi, m.HeapAlloc)
			select {
			case <-stop:
				sampled <- hi
				return
			case <-tick.C:
			}
		}
	}()
	begin = time.Now()
	again, _, err := loadDump(ctx, spec, keepText, 2)
	if err != nil {
		t.Fatal(err)
	}
	reload := time.Since(begin)
	close(stop)
	hi := <-sampled - base
	peak := heap() - base
	t.Logf("keep-route-text=%v: loaded %s in %v, heap %d MB; %s reloaded in %v; heap with both %s registries alive %d MB",
		keepText, spec.Name, loaded.Round(time.Second), held>>20, spec.Name, reload.Round(time.Second), spec.Name, peak>>20)
	t.Logf("keep-route-text=%v: highest heap sampled during the reload %d MB (garbage included)", keepText, hi>>20)
	runtime.KeepAlive(reg) // alive until both were measured
	snap, err := irrdq.NewSnapshot([]*irrdq.Registry{again}, irrdq.SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
	s.Do(ctx, "!!")
	for _, cmd := range queries {
		begin := time.Now()
		r, _ := s.Do(ctx, cmd)
		var b strings.Builder
		r.WriteTo(&b)
		if !strings.HasPrefix(b.String(), "A") {
			t.Errorf("keep-route-text=%v: %s answered %q", keepText, cmd, b.String())
		}
		t.Logf("%s: %d bytes in %v", cmd, b.Len(), time.Since(begin).Round(time.Millisecond))
	}
}
