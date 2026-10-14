# Streaming a sweep's output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `rpslcheck -sweep` write each aut-num's lint and each pair's
report as soon as it and every result before it are done, so a full RIPE
sweep no longer holds all of its output in memory. The output bytes stay
the same.

**Architecture:**
- A generic helper, `ordered`, in `resolve/internal/rpslcheck/sweep.go`
  replaces `parallel`.
  - It runs work at most `conc` at once.
  - No work starts `window` or more past the first result not yet written.
  - It hands each result to an `emit` callback in index order.
  - `emit` returning false stops the run.
- `runSweep`'s phase 1 (peers and lint) and phase 3 (checks) each run
  through `ordered`. Their `emit` callbacks do what today's write loops do
  for one result.
- Phase 2, building the pair list, is unchanged.

**Tech Stack:** Go 1.23 (module floor). `sync`, `context`, and generics
(already used in the repo).

**Spec:** `docs/superpowers/specs/2026-10-14-sweep-stream-design.md`. Read it
first; this plan argues from it.

## Global Constraints

- Go floor is 1.23: no `testing.B.Loop` and no APIs newer than 1.23.
  `for range n` (1.22) is fine.
- **The sweep's output is byte-identical to v0.27.0's for any `-c`.** Never
  edit a golden (`resolve/testdata/rpslcheck/*.golden`) to make a test pass.
  A difference is a bug.
- `streamWindow = 1024` (spec §3.2). It is raised to 4096 only by the Task 3
  ruling.
- No public API changes. Everything is in the internal package
  `resolve/internal/rpslcheck`, so `api/` does not change.
- `budget.over` keeps taking the run's context, never the context `ordered`
  hands to work, so a stop never counts as a timeout.
- Heavy runs (check.sh, sample and full sweeps):
  - Run them one at a time, never two at once.
  - Run each under `.superpowers/sdd/tools/memguard.sh` with `GOMAXPROCS=4`
    and `MEMGUARD_NORMAL_PRIORITY=1`.
- Commit after each task with a message in the repo's style
  (`area: what changed`).

## Review Focus

1. **An aut-num whose peer list fails with a non-limit error, mid-sweep.**
   - Expected: stdout holds every earlier aut-num's lint and nothing after
     it, and no totals.
   - Stderr names that AS, and the exit status is 3.
   - Test: Task 2, `TestSweepStopsAtError`.
2. **A sweep given `-timeout`.**
   - Expected: stderr is exactly the run's own error
     (`rpslcheck: context deadline exceeded`), never an aut-num's, and the
     exit status is 3.
   - Test: Task 2, an added assertion in `TestSweepCheckTimeout`.
3. **One very slow result at the head, with `-check-timeout 0`.**
   - Expected: no more than `window` results are ever started past it.
   - Test: Task 1, `TestOrderedWindowHoldsBack`.
4. **A stop while later work is blocked on its context.**
   - Expected: the work is cancelled, every goroutine has returned when
     `ordered` returns, and nothing after the stop is emitted.
   - Test: Task 1, `TestOrderedStopsWhereEmitSays`.
5. **Budgets running out under different `-c`.**
   - Expected: the same output for `-c 1` and `-c 8`.
   - Test: Task 2 re-runs the existing `TestSweepCheckTimeout` and
     `TestSweepIsDeterministic`. They must pass unchanged.

---

### Task 1: `ordered`, the in-order streaming runner

**Files:**
- Modify: `resolve/internal/rpslcheck/sweep.go`. Add `ordered` and
  `streamWindow` after `parallel` (lines 23-38). `parallel` stays until
  Task 2.
- Create: `resolve/internal/rpslcheck/ordered_test.go`

**Interfaces:**
- Produces:
  - `func ordered[R any](ctx context.Context, n, conc, window int, work func(ctx context.Context, i int) R, emit func(i int, r R) bool) bool`
  - `const streamWindow = 1024`
  - Task 2 consumes both.

- [ ] **Step 1: Write the failing tests**

Create `resolve/internal/rpslcheck/ordered_test.go`:

```go
package rpslcheck

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 1000 {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// Every result is emitted once, in index order, whatever conc and window
// are and however long each work takes; no work starts window or more past
// the results already emitted.
func TestOrderedEmitsInOrder(t *testing.T) {
	const n = 300
	for _, conc := range []int{1, 4, 16} {
		for _, window := range []int{1, 3, 64} {
			r := rand.New(rand.NewPCG(uint64(conc), uint64(window)))
			delay := make([]time.Duration, n)
			for i := range delay {
				delay[i] = time.Duration(r.IntN(300)) * time.Microsecond
			}
			var got []int
			var emitted atomic.Int64
			ok := ordered(context.Background(), n, conc, window, func(_ context.Context, i int) int {
				if e := emitted.Load(); int64(i) >= e+int64(window) {
					t.Errorf("conc %d window %d: work %d started with %d emitted", conc, window, i, e)
				}
				time.Sleep(delay[i])
				return i * 10
			}, func(i, v int) bool {
				if v != i*10 {
					t.Errorf("conc %d window %d: emit(%d, %d)", conc, window, i, v)
				}
				got = append(got, i)
				emitted.Add(1)
				return true
			})
			if !ok {
				t.Errorf("conc %d window %d: ordered returned false", conc, window)
			}
			if len(got) != n {
				t.Fatalf("conc %d window %d: %d emitted, want %d", conc, window, len(got), n)
			}
			for i, v := range got {
				if v != i {
					t.Fatalf("conc %d window %d: emitted out of order: %v", conc, window, got)
				}
			}
		}
	}
}

// Review Focus 3: while the head result is still running, no more than
// window works start, however many workers are free.
func TestOrderedWindowHoldsBack(t *testing.T) {
	const n, conc, window = 50, 16, 4
	release := make(chan struct{})
	var started atomic.Int64
	result := make(chan []int, 1)
	go func() {
		var got []int
		ordered(context.Background(), n, conc, window, func(_ context.Context, i int) int {
			started.Add(1)
			if i == 0 {
				<-release
			}
			return i
		}, func(i, _ int) bool {
			got = append(got, i)
			return true
		})
		result <- got
	}()
	waitFor(t, func() bool { return started.Load() == window })
	time.Sleep(50 * time.Millisecond) // time for a wrongly dispatched work to start
	if s := started.Load(); s != window {
		t.Fatalf("%d works started while work 0 runs, want %d", s, window)
	}
	close(release)
	select {
	case got := <-result:
		if len(got) != n {
			t.Fatalf("%d emitted, want %d", len(got), n)
		}
		for i, v := range got {
			if v != i {
				t.Fatalf("emitted out of order: %v", got)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordered did not finish after work 0 was released")
	}
}

// Review Focus 4: emit returning false stops the run there. Nothing after
// it is emitted, running work sees its context cancelled, and ordered
// returns false only after every work has returned.
func TestOrderedStopsWhereEmitSays(t *testing.T) {
	const n, k = 100, 10
	var active, cancelled atomic.Int64
	afterK := make(chan struct{})
	var once sync.Once
	var got []int
	finished := make(chan bool, 1)
	go func() {
		finished <- ordered(context.Background(), n, 4, 8, func(ctx context.Context, i int) int {
			active.Add(1)
			defer active.Add(-1)
			switch {
			case i == k:
				<-afterK // emit k only once some later work is running
			case i > k:
				once.Do(func() { close(afterK) })
				<-ctx.Done() // only the stop can end this work
				cancelled.Add(1)
			}
			return i
		}, func(i, _ int) bool {
			got = append(got, i)
			return i != k
		})
	}()
	select {
	case ok := <-finished:
		if ok {
			t.Error("ordered returned true after emit stopped it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordered did not return: the stop did not cancel the running work")
	}
	if len(got) != k+1 || got[k] != k {
		t.Errorf("emitted %v, want 0..%d", got, k)
	}
	if a := active.Load(); a != 0 {
		t.Errorf("%d works still running after ordered returned", a)
	}
	if cancelled.Load() == 0 {
		t.Error("no running work saw its context cancelled")
	}
}

// The caller's context ending stops dispatch: ordered returns false, and
// what it emitted is still a prefix in order.
func TestOrderedRunContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const n = 1000
	var got []int
	ok := ordered(ctx, n, 4, 8, func(_ context.Context, i int) int { return i }, func(i, _ int) bool {
		got = append(got, i)
		if i == 20 {
			cancel()
		}
		return true
	})
	if ok {
		t.Error("ordered returned true though its context ended")
	}
	if len(got) >= n {
		t.Errorf("all %d emitted after the context ended", n)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("emitted out of order: %v", got)
		}
	}
}

func TestOrderedEdges(t *testing.T) {
	for _, c := range []struct{ n, conc, window int }{
		{0, 4, 8},   // nothing to do
		{3, 16, 64}, // n below conc and window
		{50, 1, 1},  // one at a time
		{50, 8, 1},  // a window of one serializes even with free workers
	} {
		var got []int
		ok := ordered(context.Background(), c.n, c.conc, c.window, func(_ context.Context, i int) int { return i }, func(i, _ int) bool {
			got = append(got, i)
			return true
		})
		if !ok || len(got) != c.n {
			t.Errorf("%+v: ok %v, %d emitted", c, ok, len(got))
			continue
		}
		for i, v := range got {
			if v != i {
				t.Errorf("%+v: emitted out of order: %v", c, got)
				break
			}
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd resolve && go test -count=1 -run TestOrdered ./internal/rpslcheck`

Expected: FAIL to compile with `undefined: ordered`.

- [ ] **Step 3: Write `ordered` and `streamWindow`**

In `resolve/internal/rpslcheck/sweep.go`, after `parallel` (it ends at line
38), add:

```go
// streamWindow is how many results a sweep's phase may hold while they wait
// for an earlier one still running: a slow aut-num or pair stops new work
// once this many after it are done, so what is held is bounded whatever
// -check-timeout is.
const streamWindow = 1024

// ordered runs work(ctx, i) for i in [0, n), at most conc at once and none
// window or more past the first result not yet emitted. It passes each
// result to emit in index order, as soon as it and every result before it
// are done, so what it emits never depends on conc or window.
//
// When emit returns false, ordered cancels the ctx it gave the work still
// running, starts no more, waits for the running work to end, and returns
// false. It returns true only when it emitted all n results: false without
// emit stopping it means ctx ended before every index started. emit is
// called under ordered's mutex, one call at a time. conc and window must be
// at least 1.
func ordered[R any](ctx context.Context, n, conc, window int, work func(ctx context.Context, i int) R, emit func(i int, r R) bool) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		next    int // the first index not yet emitted
		stopped bool
		slots   = make([]R, window) // index i waits in slots[i%window]
		done    = make([]bool, window)
		running = make(chan struct{}, conc)   // a token per work running
		held    = make(chan struct{}, window) // a token per index started and not yet emitted
	)
dispatch:
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		select {
		case held <- struct{}{}:
		case <-ctx.Done():
			break dispatch
		}
		select {
		case running <- struct{}{}:
		case <-ctx.Done():
			break dispatch
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := work(ctx, i)
			<-running
			mu.Lock()
			defer mu.Unlock()
			if stopped {
				return
			}
			slots[i%window], done[i%window] = r, true
			for next < n && done[next%window] {
				k := next % window
				r := slots[k]
				var zero R
				slots[k], done[k] = zero, false
				if !emit(next, r) {
					stopped = true
					cancel()
					return
				}
				next++
				<-held // after emit: no index starts window past what was emitted
			}
		}(i)
	}
	wg.Wait()
	return !stopped && next == n
}
```

- [ ] **Step 4: Run the tests under `-race` to verify they pass**

Run: `cd resolve && go test -race -count=3 -run TestOrdered ./internal/rpslcheck`

Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add resolve/internal/rpslcheck/sweep.go resolve/internal/rpslcheck/ordered_test.go
git commit -m "rpslcheck: ordered, an in-order runner with a bounded window"
```

---

### Task 2: Stream phases 1 and 3 of `runSweep`

**Files:**
- Modify: `resolve/internal/rpslcheck/sweep.go`:
  - delete `parallel` (lines 23-38);
  - update the `lintResult` comment (lines 40-47);
  - change `runSweep` (lines 92-260): its doc comment and body from
    `c := &consist.Checker{…}` through `t.write(w)`.
- Modify: `resolve/internal/rpslcheck/rpslcheck_test.go`:
  - add `TestSweepStopsAtError` after `TestSweepPeersBeforeLint`;
  - strengthen the `-timeout 1ns` case of `TestSweepCheckTimeout`
    (lines 210-212);
  - add the imports `errors` and `github.com/rkolesnichenko/rpsl/types`.

**Interfaces:**
- Consumes (Task 1): `ordered[R any](ctx, n, conc, window, work, emit) bool`
  and `streamWindow`.
- Produces: no new names. `runSweep`'s signature is unchanged.

- [ ] **Step 1: Write the tests that pin today's failure behaviour**

These describe today's stdout and stderr for a failed sweep (spec §3.5,
§3.6), so they pass before the rewrite as well. They hold the rewrite to
those exact bytes.

In `rpslcheck_test.go`, add `"errors"` to the standard-library imports and
`"github.com/rkolesnichenko/rpsl/types"` to the module imports. After
`TestSweepPeersBeforeLint`, add:

```go
// failingAutNum is a MemSource whose aut-num lookups fail, for one AS, with
// an error that is not a limit.
type failingAutNum struct {
	*resolve.MemSource
	as types.ASN
}

var errBoom = errors.New("boom")

func (s failingAutNum) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	if as == s.as {
		return nil, errBoom
	}
	return s.MemSource.AutNum(ctx, as, source)
}

// Review Focus 1 (spec §3.5): an aut-num that cannot be read stops the
// sweep where it is reached in order. Every aut-num before it is written,
// nothing after it is, and there are no totals.
func TestSweepStopsAtError(t *testing.T) {
	const objs = `aut-num: AS65001
as-name: ONE
import: from AS65009 accept ANY
mnt-by: MNT-A
source: RIPE

aut-num: AS65003
as-name: THREE
mnt-by: MNT-A
source: RIPE

aut-num: AS65004
as-name: FOUR
import: from AS65008 accept ANY
mnt-by: MNT-A
source: RIPE
`
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, IndexPeers: true}
	if err := l.Read(strings.NewReader(objs)); err != nil {
		t.Fatal(err)
	}
	src := failingAutNum{l.Source(), 65003}
	afs, _ := families("both")
	for _, conc := range []int{1, 8} {
		var out, errw bytes.Buffer
		code := runSweep(context.Background(), src, afs, 0, 1, conc, 0, false, nil, newWriter(&out, true), &errw)
		if code != exitFailed {
			t.Errorf("-c %d: exit %d, want %d", conc, code, exitFailed)
		}
		if !strings.Contains(out.String(), `"as":"AS65001"`) {
			t.Errorf("-c %d: AS65001's lint, before the failing aut-num, is not written:\n%s", conc, out.String())
		}
		if strings.Contains(out.String(), `"as":"AS65004"`) || strings.Contains(out.String(), `"type":"totals"`) {
			t.Errorf("-c %d: written past the failing aut-num:\n%s", conc, out.String())
		}
		if e := errw.String(); !strings.HasPrefix(e, "rpslcheck: AS65003: ") || !strings.Contains(e, "boom") {
			t.Errorf("-c %d: stderr %q, want the failing aut-num's error", conc, e)
		}
	}
}
```

In `TestSweepCheckTimeout`, replace:

```go
	if _, errw, code := run(t, "-dump", fixture, "-sweep", "-timeout", "1ns"); code != exitFailed {
		t.Errorf("-timeout 1ns: exit %d, want %d; stderr %s", code, exitFailed, errw)
	}
```

with:

```go
	// Review Focus 2 (spec §3.6): the run's own deadline is reported as
	// the run's error, never as an aut-num's.
	if _, errw, code := run(t, "-dump", fixture, "-sweep", "-timeout", "1ns"); code != exitFailed || errw != "rpslcheck: context deadline exceeded\n" {
		t.Errorf("-timeout 1ns: exit %d, want %d; stderr %q, want the run's own error", code, exitFailed, errw)
	}
```

- [ ] **Step 2: Run them on today's code**

Run: `cd resolve && go test -count=1 -run 'TestSweepStopsAtError|TestSweepCheckTimeout' ./internal/rpslcheck`

Expected: `ok`. If either fails, today's behaviour is not what the spec
says. Stop and report it; do not change the tests to fit.

- [ ] **Step 3: Delete `parallel` and update `lintResult`'s comment**

Delete the whole `parallel` function and its comment (lines 23-38). Replace
the `lintResult` declaration's comment line (`type lintResult struct {`
keeps its fields) by putting this comment above it:

```go
// lintResult is one aut-num's phase-1 result. It is held only until the
// aut-num is written; then only its peers and via are kept.
```

- [ ] **Step 4: Rewrite `runSweep`'s doc comment and its phases**

Replace `runSweep`'s doc comment (the block above `func runSweep`) with:

```go
// runSweep audits the aut-nums of src, a dump's MemSource.
// Each aut-num's peer list, its lint, and each pair's check runs under its
// own budget, checkTimeout (0: none): one that runs out is counted and the
// sweep goes on, while the run's own deadline or cancellation stops it. The
// peer list comes first, so a lint that runs out never drops a pair. The
// pairs are each aut-num's Forward peers — and its ViaSets with setPeers;
// without it, a ViaSets peer no pair covers is counted, not checked.
//
// Each result is written as soon as it and every one before it are done
// (ordered), and then dropped, so a sweep holds at most streamWindow
// results per phase. A sweep that stops early — an aut-num's or a pair's
// error, or the run's own deadline — exits with exitFailed after the
// results already written.
```

In the body, replace everything from the line
`c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: setPeers, ASPAs: aspas, Memo: consist.NewMemo()}`
through `t.write(w)` (inclusive) with:

```go
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: setPeers, ASPAs: aspas, Memo: consist.NewMemo()}
	if !w.json {
		w.only = ast.Warning
	}
	t := newTotals()
	t.autnums = len(ases)
	// failed records that an emit has said on stderr why the sweep stops;
	// when ordered stops without one, the run's own context ended.
	failed := false
	fail := func(format string, args ...any) bool {
		fmt.Fprintf(stderr, format, args...)
		failed = true
		return false
	}
	stopped := func() int {
		if !failed {
			fmt.Fprintf(stderr, "rpslcheck: %v\n", ctx.Err())
		}
		return exitFailed
	}
	// Phase 1: list each aut-num's forward peers, then lint it, each under
	// its own budget: the pairs never depend on whether the lint finished.
	// Each aut-num is written as soon as it and every one before it are
	// done; only its peers are kept.
	peers := make([][]types.ASN, len(ases))
	via := make([][]types.ASN, len(ases))
	if !ordered(ctx, len(ases), conc, streamWindow, func(wctx context.Context, i int) (lr lintResult) {
		pb := newBudget(wctx, checkTimeout)
		pl, err := c.Peers(pb.ctx, ases[i])
		over := pb.over(ctx, err)
		pb.cancel()
		switch {
		case over:
			lr.timeouts = append(lr.timeouts, "peers: "+pb.overError())
		case err != nil && !isLimit(err):
			lr.err = err
			return lr
		case setPeers:
			lr.peers = slices.Concat(pl.Forward, pl.ViaSets)
		default:
			lr.peers, lr.via = pl.Forward, pl.ViaSets
		}
		lb := newBudget(wctx, checkTimeout)
		defer lb.cancel()
		issues, err := c.Lint(lb.ctx, ases[i])
		switch {
		case lb.over(ctx, err):
			lr.timeouts = append(lr.timeouts, "lint: "+lb.overError())
		case err != nil:
			lr.err = err
		default:
			lr.issues, lr.linted = ofFamilies(issues, afs), true
		}
		return lr
	}, func(i int, lr lintResult) bool {
		as := ases[i]
		if err := ctx.Err(); err != nil { // the run's own deadline, or cancelled
			return fail("rpslcheck: %v\n", err)
		}
		if lr.err != nil {
			return fail("rpslcheck: %s: %v\n", as, lr.err)
		}
		if lr.linted {
			an, _ := src.AutNum(ctx, as, "")
			if w.lint(as, an, lr.issues) {
				t.warned = true
			}
			t.addIssues(as, lr.issues)
		}
		for _, why := range lr.timeouts {
			t.timeouts++
			if w.json {
				w.emit(struct {
					Type  string `json:"type"`
					AS    string `json:"as"`
					Error string `json:"error"`
				}{"timeout", as.String(), why})
			}
		}
		peers[i], via[i] = lr.peers, lr.via
		return true
	}) {
		return stopped()
	}
	// Phase 2: each unordered pair once, in each family, in order.
	type pairKey struct{ a, b types.ASN }
	seen := map[pairKey]bool{}
	var pairs []consist.Pair
	for i, as := range ases {
		for _, peer := range peers[i] {
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
	for i, as := range ases {
		for _, peer := range via[i] {
			if !seen[pairKey{min(as, peer), max(as, peer)}] {
				t.viaSets++
			}
		}
	}
	slices.SortStableFunc(pairs, func(x, y consist.Pair) int {
		if c := cmp.Compare(x.A, y.A); c != 0 {
			return c
		}
		return cmp.Compare(x.B, y.B)
	})
	// Phase 3: check them, each pair written as soon as it and every one
	// before it are done.
	if !ordered(ctx, len(pairs), conc, streamWindow, func(wctx context.Context, i int) (cr checkResult) {
		bg := newBudget(wctx, checkTimeout)
		defer bg.cancel()
		cr.rep, cr.err = c.Check(bg.ctx, pairs[i])
		if bg.over(ctx, cr.err) {
			cr.over = bg.overError()
		}
		return cr
	}, func(i int, cr checkResult) bool {
		if err := ctx.Err(); err != nil {
			return fail("rpslcheck: %v\n", err)
		}
		p := pairs[i]
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
				}{"timeout", p.A.String(), p.B.String(), p.AF.String(), cr.over})
			}
			return true
		case isLimit(cr.err) || notDecidable(cr.err):
			t.limits++ // a limit, or a filter that cannot be evaluated for the pair
			if w.json {
				w.emit(struct {
					Type  string `json:"type"`
					A     string `json:"a"`
					B     string `json:"b"`
					AF    string `json:"af"`
					Error string `json:"error"`
				}{"limit", p.A.String(), p.B.String(), p.AF.String(), cr.err.Error()})
			}
			return true
		case cr.err != nil:
			return fail("rpslcheck: %s and %s, %s: %v\n", p.A, p.B, p.AF, cr.err)
		}
		t.pairs++
		if w.report(ctx, src, cr.rep) {
			t.warned = true
		}
		t.addReport(cr.rep)
		return true
	}) {
		return stopped()
	}
	t.write(w)
```

The lines after `t.write(w)` (the `t.warned` exit status) stay as they
are. `sync` is still imported (by `ordered`). Run `gofmt -l .` from
`resolve` and expect no output.

- [ ] **Step 5: Run the package's tests under `-race`**

Run: `cd resolve && go test -race -count=1 ./internal/rpslcheck`

Expected: `ok`. These must all pass unchanged: `TestGoldens`,
`TestSweepIsDeterministic`, `TestSweepCheckTimeout`,
`TestSweepPeersBeforeLint`, `TestSweepCountsUndecidable`, `TestSetPeers`,
`TestLintFollowsFamilies`, `TestSweepStopsAtError` and `TestOrdered*`. A
golden difference is a bug in the rewrite: never regenerate a golden.

- [ ] **Step 6: Vet and build the command**

Run: `cd resolve && go vet ./internal/rpslcheck && go build ./cmd/rpslcheck && echo built`

Expected: no vet output, then `built`.

- [ ] **Step 7: Commit**

```bash
git add resolve/internal/rpslcheck/sweep.go resolve/internal/rpslcheck/rpslcheck_test.go
git commit -m "rpslcheck: a sweep writes each result as soon as it and those before it are done"
```

---

### Task 3: Measure, rule on the window, document

**Split execution:**
- The controller runs Steps 1-4 itself: they are heavy runs, one at a time,
  and an implementer must not start them.
- An implementer does Step 5 with the figures the controller passes in.
- Every figure in the docs comes from `summary.log` lines these steps
  write.

**Files:**
- Create (git-ignored, not committed):
  - `.superpowers/sdd/sweep-stream/measure-sample.sh`
  - `.superpowers/sdd/sweep-stream/measure-full.sh`
  - `.superpowers/sdd/sweep-stream/compare-full.sh`
- Modify:
  - `docs/rpslcheck.md:200-210`, the memo and memory paragraph;
  - `CHANGELOG.md`, `## [Unreleased]`.

**Interfaces:**
- Consumes: the `rpslcheck` built from Task 2's commit, and the v0.27.0
  release binary.

- [ ] **Step 1: Build both binaries**

```bash
cd /Users/roman/DEV/rpsl
D=.superpowers/sdd/sweep-stream
mkdir -p $D/rel
gh release download v0.27.0 -p 'rpslcheck_v0.27.0_darwin_arm64.tar.gz' -D $D/rel --clobber
tar -xzf $D/rel/rpslcheck_v0.27.0_darwin_arm64.tar.gz -C $D/rel
cp $D/rel/rpslcheck $D/rpslcheck-v0.27.0
(cd resolve && go build -o ../$D/rpslcheck-stream ./cmd/rpslcheck)
$D/rpslcheck-v0.27.0 -v; $D/rpslcheck-stream -v
```

Expected: `rpslcheck v0.27.0`, then the branch build's version line.

- [ ] **Step 2: Sample runs, alternating, and the byte comparison**

Create `.superpowers/sdd/sweep-stream/measure-sample.sh`:

```zsh
#!/bin/zsh
# rpslcheck -sweep -sample 2000 -c 4 -json over RIPE's nine dumps: v0.27.0
# and the streaming build, alternating, twice each, one at a time under
# memguard (no GOMEMLIMIT, as the v0.27.0 figures were taken).
R=/Users/roman/DEV/rpsl
D=$R/.superpowers/sdd/sweep-stream
G=$R/.superpowers/sdd/tools/memguard.sh
SUM=$D/summary.log
export GOMAXPROCS=4 MEMGUARD_NORMAL_PRIORITY=1

dumps=()
for f in $R/.data/ripe/*.gz; do
	b=${f:t}
	nd=${#${b//[^.]/}}
	if (( nd <= 2 )) || [[ $b == *.route* || $b == *-set* || $b == *.aut-num* || $b == *.inet-rtr* ]]; then
		dumps+=(-dump $f)
	fi
done

run() {
	local name=$1 rc try
	shift
	for try in 1 2 3 4 5 6; do
		$G 6 3600 /usr/bin/time -l "$@" > $D/$name.out 2> $D/$name.err
		rc=$?
		if [[ $rc == 3 ]] && grep -q 'NOT STARTED' $D/$name.out $D/$name.err; then
			echo "$name not started (try $try)" >> $SUM
			sleep 300
			continue
		fi
		break
	done
	echo "$name exit=$rc | $(grep -h -E 'memguard: peak| real |maximum resident' $D/$name.out $D/$name.err | sed 's/^ *//' | tr '\n' ' ')" >> $SUM
}

for r in 1 2; do
	run sample-base$r $D/rpslcheck-v0.27.0 -sweep -sample 2000 -c 4 -json $dumps
	run sample-stream$r $D/rpslcheck-stream -sweep -sample 2000 -c 4 -json $dumps
done
for r in 1 2; do
	if cmp -s <(grep -v '^memguard\|^MEM' $D/sample-base$r.out) <(grep -v '^memguard\|^MEM' $D/sample-stream$r.out); then
		echo "sample $r: identical ($(grep -vc '^memguard\|^MEM' $D/sample-base$r.out) lines)" >> $SUM
	else
		echo "sample $r: DIFFERS" >> $SUM
	fi
done
echo DONE-SAMPLE >> $SUM
```

Run it in the background, with `chmod +x` and nohup, and wait for
`DONE-SAMPLE` in `summary.log`.

Expected:
- Both `sample r: identical` lines, and every `exit=1`. Exit 1 is
  Warnings, as in every earlier sample run.
- Wall time: the mean of the two `sample-stream` `real` figures is within
  2% of the mean of the two `sample-base` figures.

If the output differs, it is a bug: go back to Task 2.

- [ ] **Step 3: Rule on the window**

If the streaming mean is more than 2% slower:
- set `const streamWindow = 4096` in `sweep.go`;
- re-run `go test -race -count=1 ./internal/rpslcheck`;
- commit (`rpslcheck: a sweep's window is 4096 results`);
- rebuild `rpslcheck-stream` and run Step 2 again.

Record the ruling in the ledger with both means either way.

- [ ] **Step 4: The full sweep and its comparison with `main`'s**

Create `.superpowers/sdd/sweep-stream/measure-full.sh`:

```zsh
#!/bin/zsh
# The full RIPE sweep with the streaming build (the memo always on),
# GOMEMLIMIT=5GiB under a 7 GB guard, then compared with main's full output.
R=/Users/roman/DEV/rpsl
D=$R/.superpowers/sdd/sweep-stream
G=$R/.superpowers/sdd/tools/memguard.sh
SUM=$D/summary.log
export GOMAXPROCS=4 MEMGUARD_NORMAL_PRIORITY=1 GOMEMLIMIT=5GiB

dumps=()
for f in $R/.data/ripe/*.gz; do
	b=${f:t}
	nd=${#${b//[^.]/}}
	if (( nd <= 2 )) || [[ $b == *.route* || $b == *-set* || $b == *.aut-num* || $b == *.inet-rtr* ]]; then
		dumps+=(-dump $f)
	fi
done

name=full-stream
for try in 1 2 3 4 5 6 7 8 9 10 11 12; do
	$G 7 14400 /usr/bin/time -l $D/rpslcheck-stream -sweep -c 4 -json $dumps > $D/$name.out 2> $D/$name.err
	rc=$?
	if [[ $rc == 3 ]] && grep -q 'NOT STARTED' $D/$name.out $D/$name.err; then
		echo "$name not started (try $try)" >> $SUM
		sleep 300
		continue
	fi
	break
done
echo "$name exit=$rc | $(grep -h -E 'memguard: peak| real |maximum resident' $D/$name.out $D/$name.err | sed 's/^ *//' | tr '\n' ' ')" >> $SUM
$D/compare-full.sh $R/.superpowers/sdd/sweep-memo/full-main.out $D/$name.out >> $SUM
echo DONE-FULL >> $SUM
```

Create `.superpowers/sdd/sweep-stream/compare-full.sh`:

```zsh
#!/bin/zsh
# compare-full.sh MAIN STREAM: every line equal, in order, except the
# timeout records, the issues of an aut-num that timed out in either run,
# and the totals; then the totals' counts side by side.
a=$1 b=$2
pat=${0:A:h}/full-skip.txt
{
	grep -h -o '"type":"timeout","as":"AS[0-9]*"' $a $b | sed 's/.*"as":"\(AS[0-9]*\)"/{"type":"issue","as":"\1",/' | sort -u
	echo '{"type":"timeout",'
	echo '{"type":"totals",'
} > $pat
echo "full: skipping the issues of $(grep -c '"issue"' $pat) aut-nums that timed out in either run"
echo "full: pair timeouts: $(grep -c '"type":"timeout","a":' $a) and $(grep -c '"type":"timeout","a":' $b)"
if cmp -s <(grep -v '^memguard\|^MEM' $a | grep -v -F -f $pat) <(grep -v '^memguard\|^MEM' $b | grep -v -F -f $pat); then
	echo "full: identical apart from timeouts ($(grep -v '^memguard\|^MEM' $a | grep -v -F -f $pat | wc -l | tr -d ' ') lines)"
else
	echo "full: DIFFERS"
fi
for k in autnums pairs via_sets_skipped directions consistent no_policy limits timeouts; do
	echo "totals $k: $(grep '"type":"totals"' $a | grep -o "\"$k\":[0-9]*") vs $(grep '"type":"totals"' $b | grep -o "\"$k\":[0-9]*")"
done
```

`chmod +x` both, and run `measure-full.sh` with nohup in the background.
Watch `summary.log` with a bounded monitor; `main`'s full sweep took 100
minutes.

Expected:
- `full-stream exit=1`, not killed by the guard.
- `full: identical apart from timeouts`.
- Equal totals for `autnums`, `pairs`, `via_sets_skipped`, `directions`,
  `consistent`, `no_policy` and `limits`.
- `timeouts` may differ: the memo changes which lints run out.
- If the pair-timeout counts are not both 0, a `DIFFERS` may come from
  those pairs' direction records. Investigate it before calling it a bug.

If the guard stops it, record the peak and the time it reached. The full
figure is then unknown, and the docs say so.

- [ ] **Step 5: Document (implementer, with the figures from summary.log)**

The controller passes in:
- `FULL_WALL`: `full-stream`'s `real`, in minutes;
- `FULL_RSS`: its `maximum resident set size`, in MB;
- `FULL_PEAK`: memguard's peak;
- `WINDOW`: the ruled window, 1024 or 4096, written with a thousands
  comma (`1,024` or `4,096`).

In `docs/rpslcheck.md`, replace this paragraph (lines 200-210), from
"`rpslcheck` shares a `consist.Memo`" through "the machine is short of
memory.":

```markdown
`rpslcheck` shares a `consist.Memo` across a run's checks in every mode (decoded
aut-nums and normalized filters; it changes no answer). Measured on RIPE's nine
dumps with `-sweep -sample 2000 -c 4`, GOMAXPROCS 4: 280.5 s and 3,247 MB max
RSS without the memo, 155.7 s and 4,023 MB with it, byte-identical JSON.

A sweep writes each aut-num's lint, and each pair's report, as soon as it and
every one before it are done, and keeps none of them after; at most WINDOW
results wait for an earlier one still running, whatever `-check-timeout` is.
The output is the same as if everything were written at the end. A full RIPE
sweep (`-sweep -c 4 -json`, GOMAXPROCS 4, `GOMEMLIMIT=5GiB`) took FULL_WALL
minutes with FULL_RSS MB max RSS; before, it held every lint until linting
ended, and it took 100 minutes and 6,264 MB without the memo and did not fit
under 7 GB with it. A sweep that stops before its end — an aut-num's or a
pair's error, `-timeout`, an interrupt — exits 3 and leaves the results it had
already written on stdout; its JSON then has no `totals` record. `rpslcheck`
sets no `GOMEMLIMIT` itself; set one if the machine is short of memory.
```

In `CHANGELOG.md`, under `## [Unreleased]`, add:

```markdown
### Changed

- `rpslcheck -sweep` writes each aut-num's lint and each pair's report as soon
  as it and every one before it are done, instead of holding them until the
  phase ends; at most WINDOW wait at once, whatever `-check-timeout` is. The
  output is unchanged. A full sweep of RIPE's dumps (`-c 4 -json`, GOMAXPROCS 4,
  GOMEMLIMIT=5GiB) took FULL_WALL minutes with FULL_RSS MB max RSS; before, it
  took 100 minutes and 6,264 MB without the memo and did not fit under 7 GB
  with it.
- A sweep that stops early (an aut-num's or a pair's error, `-timeout`, an
  interrupt) leaves the results it had already written on stdout. It still
  exits 3, and its JSON has no `totals` record.
```

Replace `WINDOW`, `FULL_WALL` and `FULL_RSS` with the passed-in figures.
`grep -n 'WINDOW\|FULL_' docs/rpslcheck.md CHANGELOG.md` must print nothing
afterwards.

If Step 4 did not finish:
- replace the full-sweep sentence in both files with one saying the full
  sweep was stopped by the memory guard at FULL_PEAK MB after FULL_WALL
  minutes;
- keep the rest.

- [ ] **Step 6: Run the docs test and commit**

Run: `cd resolve && go test -count=1 -run 'Docs' ./... > /tmp/docs-test.txt 2>&1; echo rc=$?`

Expected: `rc=0`. If it is not, read `/tmp/docs-test.txt`. `rpslcheck`'s
docs are not checked by a test today, so this only guards the other docs
tests.

```bash
git add docs/rpslcheck.md CHANGELOG.md
git commit -m "docs: rpslcheck's sweep streams its output; full-sweep figures"
```

---

## After the tasks (controller)

1. Final whole-branch review on the most capable model. Fix its Critical
   and Important findings.
2. `FUZZTIME=15s scripts/check.sh` under memguard, with a 7 GB cap and
   GOMAXPROCS=4. It must print `check: ok`.
3. Engine purity and leaf isolation (CLAUDE.md Commands). They are
   unaffected, but cheap to check.
4. Push the branch and open the PR. Merging needs the user's word.
