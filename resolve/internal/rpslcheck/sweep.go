package rpslcheck

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// parallel runs fn(i) for i in [0, n), at most conc at once, and returns
// when all have; fn writes its result into its own slot, so the order of
// the results never depends on conc.
func parallel(n, conc int, fn func(i int)) {
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

type lintResult struct {
	issues []consist.Issue
	peers  []types.ASN
	err    error
}

type checkResult struct {
	rep consist.Report
	err error
}

// runSweep audits the aut-nums of src, a dump's MemSource.
func runSweep(ctx context.Context, src resolve.PolicySource, afs []types.AddrFamily, sample int, seed uint64, conc int, w *writer, stderr io.Writer) int {
	pi, ok := src.(resolve.PolicyIndex)
	if !ok {
		fmt.Fprintln(stderr, "rpslcheck: -sweep: the source cannot list its aut-nums")
		return exitFailed
	}
	seq, err := pi.AutNums()
	if err != nil {
		fmt.Fprintf(stderr, "rpslcheck: -sweep: %v\n", err)
		return exitFailed
	}
	ases := slices.Collect(seq)
	if sample > 0 && sample < len(ases) {
		r := rand.New(rand.NewPCG(seed, 0))
		r.Shuffle(len(ases), func(i, j int) { ases[i], ases[j] = ases[j], ases[i] })
		ases = ases[:sample]
		slices.Sort(ases)
	}
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}}
	if !w.json {
		w.only = ast.Warning
	}
	// Phase 1: lint each aut-num and list its forward peers.
	lints := make([]lintResult, len(ases))
	parallel(len(ases), conc, func(i int) {
		lr := &lints[i]
		if lr.issues, lr.err = c.Lint(ctx, ases[i]); lr.err != nil {
			return
		}
		pl, err := c.Peers(ctx, ases[i])
		if err != nil && !isLimit(err) {
			lr.err = err
			return
		}
		lr.peers = pl.Forward
	})
	t := newTotals()
	t.autnums = len(ases)
	// Phase 2: each unordered pair once, in each family, in order.
	type pairKey struct{ a, b types.ASN }
	seen := map[pairKey]bool{}
	var pairs []consist.Pair
	for i, as := range ases {
		if err := lints[i].err; err != nil {
			fmt.Fprintf(stderr, "rpslcheck: %s: %v\n", as, err)
			return exitFailed
		}
		an, _ := src.AutNum(ctx, as, "")
		if w.lint(as, an, lints[i].issues) {
			t.warned = true
		}
		t.addIssues(as, lints[i].issues)
		for _, peer := range lints[i].peers {
			k := pairKey{min(as, peer), max(as, peer)}
			if seen[k] {
				continue
			}
			seen[k] = true
			for _, af := range afs {
				pairs = append(pairs, consist.Pair{A: k.a, B: k.b, AF: af})
			}
		}
	}
	slices.SortStableFunc(pairs, func(x, y consist.Pair) int {
		if c := cmp.Compare(x.A, y.A); c != 0 {
			return c
		}
		return cmp.Compare(x.B, y.B)
	})
	// Phase 3: check them.
	checks := make([]checkResult, len(pairs))
	parallel(len(pairs), conc, func(i int) {
		checks[i].rep, checks[i].err = c.Check(ctx, pairs[i])
	})
	for i, cr := range checks {
		switch {
		case isLimit(cr.err) || notDecidable(cr.err):
			t.limits++ // a limit, or a filter that cannot be evaluated for the pair
			if w.json {
				w.emit(struct {
					Type  string `json:"type"`
					A     string `json:"a"`
					B     string `json:"b"`
					AF    string `json:"af"`
					Error string `json:"error"`
				}{"limit", pairs[i].A.String(), pairs[i].B.String(), pairs[i].AF.String(), cr.err.Error()})
			}
			continue
		case cr.err != nil:
			fmt.Fprintf(stderr, "rpslcheck: %s and %s, %s: %v\n", pairs[i].A, pairs[i].B, pairs[i].AF, cr.err)
			return exitFailed
		}
		t.pairs++
		if w.report(ctx, src, cr.rep) {
			t.warned = true
		}
		t.addReport(cr.rep)
	}
	t.write(w)
	if t.warned {
		return exitWarning
	}
	return exitClean
}

// totals is what a sweep counts.
type totals struct {
	autnums, pairs, directions, consistent, limits int            // limits: pairs over a limit or not decidable
	kinds                                          map[string]int // directions with at least one finding of the kind ("undecided: <why>" by reason)
	rules                                          map[string]int // lint issues by rule
	warnings                                       map[types.ASN]int
	warned                                         bool
}

func newTotals() *totals {
	return &totals{kinds: map[string]int{}, rules: map[string]int{}, warnings: map[types.ASN]int{}}
}

func (t *totals) addIssues(as types.ASN, issues []consist.Issue) {
	for _, is := range issues {
		t.rules[is.Rule]++
		if is.Severity >= ast.Warning {
			t.warnings[as]++
		}
	}
}

func (t *totals) addReport(rep consist.Report) {
	for _, d := range []consist.Direction{rep.AtoB, rep.BtoA} {
		t.directions++
		if len(d.Findings) == 0 {
			t.consistent++
			continue
		}
		seen := map[string]bool{}
		for _, f := range d.Findings {
			k := f.Kind.String()
			if f.Kind == consist.Undecided {
				k = "undecided: " + f.Why
			}
			if !seen[k] {
				seen[k] = true
				t.kinds[k]++
			}
			if f.Severity >= ast.Warning {
				t.warnings[d.From]++
				t.warnings[d.To]++
			}
		}
	}
}

// top returns the n aut-nums with the most Warnings, most first, then by AS.
func (t *totals) top(n int) []types.ASN {
	var out []types.ASN
	for as := range t.warnings {
		out = append(out, as)
	}
	slices.SortFunc(out, func(a, b types.ASN) int {
		if c := cmp.Compare(t.warnings[b], t.warnings[a]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (t *totals) write(w *writer) {
	top := t.top(10)
	if w.json {
		type entry struct {
			AS       string `json:"as"`
			Warnings int    `json:"warnings"`
		}
		var tops []entry
		for _, as := range top {
			tops = append(tops, entry{as.String(), t.warnings[as]})
		}
		w.emit(struct {
			Type       string         `json:"type"`
			AutNums    int            `json:"autnums"`
			Pairs      int            `json:"pairs"`
			Directions int            `json:"directions"`
			Consistent int            `json:"consistent"`
			Kinds      map[string]int `json:"kinds"`
			Rules      map[string]int `json:"rules"`
			Limits     int            `json:"limits"`
			Top        []entry        `json:"top"`
		}{"totals", t.autnums, t.pairs, t.directions, t.consistent, t.kinds, t.rules, t.limits, tops})
		return
	}
	fmt.Fprintln(w.out, "totals")
	row := func(name string, n int) { fmt.Fprintf(w.out, "  %-40s %d\n", name, n) }
	row("aut-nums", t.autnums)
	row("pairs checked (per family)", t.pairs)
	row("directions", t.directions)
	row("directions consistent", t.consistent)
	for _, k := range sortedKeys(t.kinds) {
		row("directions with "+k, t.kinds[k])
	}
	for _, k := range sortedKeys(t.rules) {
		row(k, t.rules[k])
	}
	row("pairs over a limit or not decidable", t.limits)
	if len(top) > 0 {
		var parts []string
		for _, as := range top {
			parts = append(parts, fmt.Sprintf("%s (%d)", as, t.warnings[as]))
		}
		fmt.Fprintf(w.out, "  most warnings: %s\n", strings.Join(parts, ", "))
	}
}
