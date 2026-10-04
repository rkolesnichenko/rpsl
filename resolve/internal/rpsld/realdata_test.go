package rpsld

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
)

// TestRealDataServe (opt-in: RPSL_REALDATA=<the directory
// scripts/fetch-irr-dumps.sh fills>) loads RIPE's routing-class dumps and
// RADB's dump as two registries, with and without -keep-route-text, and
// logs what it costs: load time, heap, one registry's reload time and the
// heap while the old and the new registry are both alive. It then asks the
// served snapshot a sample of queries and requires answers.
//
// RPSL_REALDATA_REGISTRY (RIPE or RADB) loads that registry alone, and
// RPSL_REALDATA_KEEPTEXT (0 or 1) runs one of the two configurations, so that
// each can be measured in a process of its own.
func TestRealDataServe(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	var ripe []string
	for _, class := range []string{"as-set", "route-set", "rtr-set", "filter-set", "peering-set", "aut-num", "inet-rtr", "route", "route6"} {
		ripe = append(ripe, filepath.Join(dir, "ripe", "ripe.db."+class+".gz"))
	}
	specs := []SourceSpec{
		{Name: "RIPE", Kind: "dump", Paths: ripe},
		{Name: "RADB", Kind: "dump", Paths: []string{filepath.Join(dir, "radb", "radb.db.gz")}},
	}
	// Each registry's queries: a large as-set, its server-side expansion, an
	// AS's routes, its aut-num, and one of its routes by prefix.
	queries := map[string][]string{
		"RIPE": {"!iAS-DECIX", "!aAS-DECIX", "!gAS3333", "!maut-num,AS3333", "!r193.0.0.0/21,o"},
		"RADB": {"!iAS-HURRICANE", "!aAS-HURRICANE", "!gAS6939", "!maut-num,AS6939", "!r23.95.45.0/24,o"},
	}
	switch v := os.Getenv("RPSL_REALDATA_REGISTRY"); v {
	case "":
	case "RIPE", "RADB":
		specs = slices.DeleteFunc(specs, func(s SourceSpec) bool { return s.Name != v })
	default:
		t.Fatalf("RPSL_REALDATA_REGISTRY=%q: want RIPE or RADB", v)
	}
	keepTexts := []bool{false, true}
	switch v := os.Getenv("RPSL_REALDATA_KEEPTEXT"); v {
	case "":
	case "0", "1":
		keepTexts = []bool{v == "1"}
	default:
		t.Fatalf("RPSL_REALDATA_KEEPTEXT=%q: want 0 or 1", v)
	}
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	loadedNames := strings.Join(names, " and ")
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	ctx := context.Background()
	for _, keepText := range keepTexts {
		base := heap()
		begin := time.Now()
		var regs []*irrdq.Registry
		for _, s := range specs {
			r, st, err := loadDump(ctx, s, keepText, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("keep-route-text=%v: %s: %d objects read, %d of another source left out", keepText, s.Name, st.objects, st.other)
			regs = append(regs, r)
		}
		loaded := time.Since(begin)
		held := heap() - base
		// The reload, as a dump watcher does it: the new registry is built
		// while the old one still serves. A sampler records the highest
		// HeapAlloc it sees meanwhile, garbage included.
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
		again, _, err := loadDump(ctx, specs[0], keepText, 2)
		if err != nil {
			t.Fatal(err)
		}
		reload := time.Since(begin)
		close(stop)
		hi := <-sampled - base
		peak := heap() - base
		t.Logf("keep-route-text=%v: loaded %s in %v, heap %d MB; %s reloaded in %v; heap with both %s registries alive %d MB",
			keepText, loadedNames, loaded.Round(time.Second), held>>20, specs[0].Name, reload.Round(time.Second), specs[0].Name, peak>>20)
		t.Logf("keep-route-text=%v: highest heap sampled during the reload %d MB (garbage included)", keepText, hi>>20)
		snap, err := irrdq.NewSnapshot(append([]*irrdq.Registry{again}, regs[1:]...), irrdq.SnapshotOptions{})
		if err != nil {
			t.Fatal(err)
		}
		s := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
		s.Do(ctx, "!!")
		var cmds []string
		for _, s := range specs {
			cmds = append(cmds, queries[s.Name]...)
		}
		for _, cmd := range cmds {
			begin := time.Now()
			r, _ := s.Do(ctx, cmd)
			var b strings.Builder
			r.WriteTo(&b)
			if !strings.HasPrefix(b.String(), "A") {
				t.Errorf("keep-route-text=%v: %s answered %q", keepText, cmd, b.String())
			}
			t.Logf("%s: %d bytes in %v", cmd, b.Len(), time.Since(begin).Round(time.Millisecond))
		}
		runtime.KeepAlive(regs)
	}
}
