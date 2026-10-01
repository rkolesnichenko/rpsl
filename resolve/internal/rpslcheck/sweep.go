package rpslcheck

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

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
	issues  []consist.Issue
	linted  bool // issues are the aut-num's lint
	peers   []types.ASN
	err     error  // the sweep cannot go on
	timeout string // the lint or the peer list ran over its own budget: why
}

type checkResult struct {
	rep  consist.Report
	err  error
	over string // the check ran over its own budget: why
}

// budget is one Lint's or Check's own time budget within a sweep.
type budget struct {
	ctx    context.Context
	cancel context.CancelFunc
	d      time.Duration
	end    time.Time // zero: no budget
}

// newBudget derives a call's context from the run's: with a deadline d
// from now, or none when d is 0.
func newBudget(run context.Context, d time.Duration) budget {
	if d <= 0 {
		ctx, cancel := context.WithCancel(run)
		return budget{ctx: ctx, cancel: cancel}
	}
	ctx, cancel := context.WithTimeout(run, d)
	return budget{ctx: ctx, cancel: cancel, d: d, end: time.Now().Add(d)}
}

// over reports whether the call ended over its own budget while the run
// goes on: it failed on its deadline, or it ended after it without
// noticing — so whether a call is counted never depends on when its
// timer fired, and a sweep's output is the same for any -c.
func (b budget) over(run context.Context, err error) bool {
	if run.Err() != nil || b.end.IsZero() {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return err == nil && !time.Now().Before(b.end)
}

// overError is what a sweep reports for a call over its budget: the same
// text however the call ended.
func (b budget) overError() string { return fmt.Sprintf("over its time budget of %v", b.d) }

// runSweep audits the aut-nums of src, a dump's MemSource.
// Each aut-num's lint (with its peer list) and each pair's check runs under
// its own budget, checkTimeout (0: none): one that runs out is counted and
// the sweep goes on, while the run's own deadline or cancellation stops it.
func runSweep(ctx context.Context, src resolve.PolicySource, afs []types.AddrFamily, sample int, seed uint64, conc int, checkTimeout time.Duration, w *writer, stderr io.Writer) int {
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
		bg := newBudget(ctx, checkTimeout)
		defer bg.cancel()
		issues, err := c.Lint(bg.ctx, ases[i])
		switch {
		case bg.over(ctx, err):
			lr.timeout = bg.overError()
			return
		case err != nil:
			lr.err = err
			return
		}
		lr.issues, lr.linted = issues, true
		pl, err := c.Peers(bg.ctx, ases[i])
		switch {
		case bg.over(ctx, err):
			lr.timeout = bg.overError()
			return
		case err != nil && !isLimit(err):
			lr.err = err
			return
		}
		lr.peers = pl.Forward
	})
	if err := ctx.Err(); err != nil { // the run's own deadline, or cancelled
		fmt.Fprintf(stderr, "rpslcheck: %v\n", err)
		return exitFailed
	}
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
		if lints[i].linted {
			an, _ := src.AutNum(ctx, as, "")
			if w.lint(as, an, lints[i].issues) {
				t.warned = true
			}
			t.addIssues(as, lints[i].issues)
		}
		if why := lints[i].timeout; why != "" {
			t.timeouts++
			if w.json {
				w.emit(struct {
					Type  string `json:"type"`
					AS    string `json:"as"`
					Error string `json:"error"`
				}{"timeout", as.String(), why})
			}
		}
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
		bg := newBudget(ctx, checkTimeout)
		defer bg.cancel()
		checks[i].rep, checks[i].err = c.Check(bg.ctx, pairs[i])
		if bg.over(ctx, checks[i].err) {
			checks[i].over = bg.overError()
		}
	})
	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "rpslcheck: %v\n", err)
		return exitFailed
	}
	for i, cr := range checks {
		switch {
		case cr.over != "":
			t.timeouts++
			if w.json {
				w.emit(struct {
					Type  string `json:"type"`
					A     string `json:"a"`
					B     string `json:"b"`
					AF    string `json:"af"`
					Error string `json:"error"`
				}{"timeout", pairs[i].A.String(), pairs[i].B.String(), pairs[i].AF.String(), cr.over})
			}
			continue
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
	timeouts                                       int            // lints and checks over their own time budget
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
			Timeouts   int            `json:"timeouts"`
			Top        []entry        `json:"top"`
		}{"totals", t.autnums, t.pairs, t.directions, t.consistent, t.kinds, t.rules, t.limits, t.timeouts, tops})
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
	row("checks over their time budget", t.timeouts)
	if len(top) > 0 {
		var parts []string
		for _, as := range top {
			parts = append(parts, fmt.Sprintf("%s (%d)", as, t.warnings[as]))
		}
		fmt.Fprintf(w.out, "  most warnings: %s\n", strings.Join(parts, ", "))
	}
}
