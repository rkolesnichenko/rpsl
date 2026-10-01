package consist

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestRealDataConsist (opt-in: RPSL_REALDATA) sweeps RIPE: every aut-num,
// or RPSL_CONSIST_SAMPLE of them (seeded), linted and checked against its
// forward peers in both families, each unordered pair once. It measures the load (time, heap with
// and without IndexPeers) and the sweep, and holds every unconditional
// not-imported finding to the two sides' clause spaces: its example lies in
// a pure export conjunct and in no import conjunct. Each call has its own
// budget: an aut-num's Lint and Peers 60s together, each Check 60s, each
// verify 30s (running out of it is counted as a verify timeout). A limit, a
// timeout or a pair whose filter cannot be evaluated is counted, and goes
// no further (a pair counted so is not among "pairs"); any other error
// fails.
func TestRealDataConsist(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ripe", "*.gz"))
	var wanted []string
	for _, f := range files {
		base := filepath.Base(f)
		if strings.Count(base, ".") <= 2 || strings.Contains(base, ".route") || strings.Contains(base, "-set") ||
			strings.Contains(base, ".aut-num") || strings.Contains(base, ".inet-rtr") {
			wanted = append(wanted, f)
		}
	}
	if len(wanted) == 0 {
		t.Skip("no RIPE dumps under RPSL_REALDATA")
	}
	load := func(index bool) (*resolve.DumpLoader, time.Duration, uint64) {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true, IndexPeers: index}
		for _, f := range wanted {
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Read(zr); err != nil {
				t.Fatal(err)
			}
			fh.Close()
		}
		took := time.Since(start)
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		return l, took, after.HeapAlloc - before.HeapAlloc
	}
	_, plainTook, plainHeap := load(false) // measured, then dropped
	l, idxTook, idxHeap := load(true)
	t.Logf("load: KeepPolicy %v, %d MB; with IndexPeers %v, %d MB", plainTook.Round(time.Second), plainHeap>>20, idxTook.Round(time.Second), idxHeap>>20)

	src := l.Source()
	seq, err := src.AutNums()
	if err != nil {
		t.Fatal(err)
	}
	ases := slices.Collect(seq)
	if n, _ := strconv.Atoi(os.Getenv("RPSL_CONSIST_SAMPLE")); n > 0 && n < len(ases) {
		r := rand.New(rand.NewPCG(1, 0))
		r.Shuffle(len(ases), func(i, j int) { ases[i], ases[j] = ases[j], ases[i] })
		ases = ases[:n]
		slices.Sort(ases)
	}
	c := &Checker{Eval: peval.Evaluator{Src: resolve.NewCache(src, 0)}, MaxRanges: 64}
	// Each unordered pair a peering names, from either side, is checked
	// once, by whichever side claims it first: the set of pairs does not
	// depend on the order, and a pair only one side names is checked too.
	type pairKey struct{ a, b types.ASN }
	var claimMu sync.Mutex
	claimed := map[pairKey]bool{}
	claim := func(a, b types.ASN) bool {
		k := pairKey{min(a, b), max(a, b)}
		claimMu.Lock()
		defer claimMu.Unlock()
		if claimed[k] {
			return false
		}
		claimed[k] = true
		return true
	}
	fams := []types.AddrFamily{{AFI: types.AFIv4, SAFI: types.SAFIUnicast}, {AFI: types.AFIv6, SAFI: types.SAFIUnicast}}

	var mu sync.Mutex
	stats := map[string]int{}
	count := func(k string, n int) { mu.Lock(); stats[k] += n; mu.Unlock() }
	start := time.Now()
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for _, as := range ases {
		wg.Add(1)
		sem <- struct{}{}
		go func(as types.ASN) {
			defer func() { <-sem; wg.Done() }()
			// Each call has a budget of its own — Lint with Peers, each
			// Check, each verify — so one slow call never starves the rest.
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			issues, err := c.Lint(ctx, as)
			if err != nil { // counted or failed, the aut-num goes no further
				if !counted(err, count) {
					t.Errorf("lint %s: %v", as, err)
				}
				return
			}
			for _, is := range issues {
				count("lint: "+is.Rule, 1)
			}
			pl, err := c.Peers(ctx, as)
			if err != nil {
				if !counted(err, count) {
					t.Errorf("peers %s: %v", as, err)
				}
				return
			}
			for _, peer := range pl.Forward {
				if !claim(as, peer) {
					continue // the pair is checked from peer's side
				}
				for _, af := range fams {
					p := Pair{A: as, B: peer, AF: af}
					cctx, ccancel := context.WithTimeout(context.Background(), 60*time.Second)
					rep, err := c.Check(cctx, p)
					ccancel()
					if err != nil { // not a pair checked: no directions to count
						if !counted(err, count) {
							t.Errorf("check %v: %v", p, err)
						}
						continue
					}
					count("pairs", 1)
					for _, d := range []Direction{rep.AtoB, rep.BtoA} {
						count("directions", 1)
						if len(d.Findings) == 0 {
							count("directions consistent", 1)
						}
						seen := map[string]bool{}
						for _, f := range d.Findings {
							k := f.Kind.String()
							if f.Kind == Undecided {
								k = "undecided: " + f.Why
							}
							if len(f.Given) > 0 {
								k += " (given)"
							}
							if !seen[k] {
								seen[k] = true
								count("directions with "+k, 1)
							}
							if f.Kind == NotImported && len(f.Given) == 0 {
								// verify has its own budget: the per-AS one may be
								// nearly spent by the Check that found f.
								vctx, vcancel := context.WithTimeout(context.Background(), 30*time.Second)
								msg, err := c.verify(vctx, d, f, af)
								vcancel()
								switch {
								case errors.Is(err, context.DeadlineExceeded):
									count("verify timeout", 1)
								case err != nil:
									t.Errorf("verify %v %v→%v: %v", af, d.From, d.To, err)
								case msg != "":
									t.Errorf("%v %v→%v: %s", af, d.From, d.To, msg)
								}
							}
						}
					}
				}
			}
		}(as)
	}
	wg.Wait()
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-60s %d\n", k, stats[k])
	}
	t.Logf("%d aut-nums swept in %s:\n%s", len(ases), time.Since(start).Round(time.Second), b.String())
}

// counted counts a limit, a timeout or a filter that cannot be evaluated
// for a session (Check's error; Lint reports it as lint/undecided) and
// reports true; nil is true too; any other error is false.
func counted(err error, count func(string, int)) bool {
	var tl *resolve.SetTooLargeError
	switch {
	case err == nil:
		return true
	case errors.As(err, &tl):
		count("limit: "+tl.Limit.String(), 1)
		return true
	case errors.Is(err, context.DeadlineExceeded):
		count("timeout", 1)
		return true
	case isLimit(err):
		count("limit: flatten", 1)
		return true
	case notDecidable(err):
		count("not decidable", 1)
		return true
	}
	return false
}

// verify holds an unconditional not-imported finding to the clause spaces:
// its example is in some pure export conjunct of From and in no import
// conjunct of To. It returns what contradicts that, or the error that kept
// it from deciding.
func (c *Checker) verify(ctx context.Context, d Direction, f Finding, af types.AddrFamily) (string, error) {
	exp, _, err := c.policies(ctx, c.session(d.From, d.To, netip.Addr{}, netip.Addr{}, af))
	if err != nil {
		return "", err
	}
	_, imp, err := c.policies(ctx, c.session(d.To, d.From, netip.Addr{}, netip.Addr{}, af))
	if err != nil {
		return "", err
	}
	in := false
	for _, cj := range sideOf(exp).conjs {
		if len(cj.sig) == 0 && cj.space.Contains(f.Example) {
			in = true
		}
	}
	if !in {
		return fmt.Sprintf("example %v is in no pure export conjunct", f.Example), nil
	}
	for _, cj := range sideOf(imp).conjs {
		if cj.space.Contains(f.Example) {
			return fmt.Sprintf("example %v is in an import conjunct (%v)", f.Example, cj.sig), nil
		}
	}
	return "", nil
}
