# Streaming a sweep's output

Status: proposed · 2026-10-14 · planned v0.27.1 · branch `sweep-stream`

## 1. Summary

`rpslcheck -sweep` keeps every aut-num's lint issues until all the lints
have finished, and every pair's report until all the checks have finished.
Only then does it write them, in order. Over RIPE this retention is most of
the sweep's heap. `main`'s full sweep peaks at 6,264 MB. With v0.27.0's memo
added, the full sweep could not be measured on a 36 GB machine with IDEs
open.

This design writes each result as soon as it and every result before it are
done, then drops it. The output is the same bytes in the same order, and
nothing changes in the API.

## 2. Measurements behind it

All from `.superpowers/sdd/sweep-memo/measurements.md` (RIPE's nine dumps,
GOMAXPROCS=4, every run alone under a memory guard).

- **`main`'s full sweep** (`-sweep -c 4 -json`, GOMEMLIMIT=5GiB):
  - 6,003.8 s wall, max RSS 6,264 MB.
  - 2,754,644,083 bytes of JSON: 10,169,683 `issue` records, 954,052
    direction records and 43 `timeout` records. All 43 timeouts are lint
    timeouts.
- **The memo's full sweep:**
  - Under a 7 GB guard it was killed at 1,075 s (peak 7,182 MB).
  - Under an 8 GB guard it was stopped at 1,437 s on system memory pressure
    (RSS 6,929 MB).
  - Both were still linting.
- **Heap profile of the memo run at t=1,088 s** (5.76 GB in use):
  - `ofFamilies`: 2.45 GB. This is the filtered issue slices held in
    `lints[i].issues`.
  - `fmt.Sprintf`: 1.01 GB, from the issues' messages.
  - `linter.add`: 0.88 GB.
  - Together that is about 4.3 GB of retained lint output.
  - The memo's own share, site by site against a run without it: about
    0.45 GB.
- **Phase 3's retention** (`checks[i].rep` for every pair, held until all
  checks finish) is not measured. No run lasted long enough to reach it.

## 3. Decisions

1. **The output stays byte-identical, for any `-c`.** Results are written
   in the order they are written today (by index), so `TestGoldens`,
   `TestSweepIsDeterministic` and the bytes of a sample run hold unchanged.
2. **A window bounds what waits.** A result can finish before an earlier one
   that is still running. It then waits until every result before it has
   been written. A worker may start result `i` only while `i` is less than
   `next + window`, where `next` is the first result not yet written.
   - So at most `window` results are held at once, whatever `-check-timeout`
     is. With `-check-timeout 0` (no budget), one 13-minute lint would
     otherwise hold back everything finished during those 13 minutes.
   - The window's size is `streamWindow = 1024` results, the same in phase 1
     and phase 3.
   - The value is checked by measurement (§7). If the sample's wall time
     regresses more than 2% against v0.27.0, the plan raises it to 4096 and
     measures again.
3. **The phases stay.** The pair list needs every aut-num's peers before it
   can be deduplicated and sorted: a pair (A, B) can be named only by B's
   aut-num. So phase 3 still starts after phase 1 ends. Streaming happens
   within each phase, and the order of what is written is unchanged: every
   aut-num's lint and lint-timeout records, then every pair's records, then
   the totals.
4. **A failed run can leave written output.** Today a run that fails in
   phase 1 writes nothing to stdout. Phase 1 can fail on the run's own
   `-timeout`, on an interrupt, or on an aut-num's error. With streaming,
   the results already written stay written. The exit status (3) and the
   stderr line are unchanged.
   - A JSON consumer can tell a run that did not finish: its last record is
     not `totals`.
   - The docs say so.
   - A run that fails in phase 3 today already leaves phase 1's output.
5. **An aut-num's error stops the sweep where it does today.** When writing
   reaches an aut-num whose peer list or lint failed with an error that is
   not a limit, the sweep prints today's stderr line and stops. It cancels
   the work in flight, starts no more, and returns 3.
   - Today the sweep stops at the same aut-num, after every lint has
     finished. So stdout is identical: every lint before it, and nothing
     after it.
   - The same holds for a pair's error in phase 3.
6. **The run's own cancellation is reported as today.** When writing
   reaches a slot whose work failed because the run's context ended (a
   `-timeout`, an interrupt), the sweep reports the run's error
   (`rpslcheck: context deadline exceeded`), not the aut-num's. Every slot
   is checked against the run's context first.

## 4. Design

All of it is in `resolve/internal/rpslcheck/sweep.go`.

### 4.1 `ordered`

This replaces `parallel` in the sweep. `parallel` stays if anything else
uses it, and goes otherwise.

```go
// ordered runs work(ctx, i) for i in [0, n), at most conc at once and none
// more than window past the first result not yet written. It passes each
// result to emit in index order, as soon as it and every result before it
// are done. When emit returns false, ordered cancels ctx for the work still
// running, starts no more, waits for the running work to end, and returns
// false. Results after the one that stopped it are discarded. emit is
// called under ordered's mutex, one call at a time, so it needs no lock of
// its own.
func ordered[R any](ctx context.Context, n, conc, window int,
	work func(ctx context.Context, i int) R,
	emit func(i int, r R) bool) bool
```

- **Implementation:**
  - A `window`-slot ring of results, plus a `done` flag per slot.
  - One mutex, plus `next`.
  - Two semaphores: `conc` workers running, and `window` results that are
    started but not yet written.
  - A worker stores its result, then under the mutex drains every finished
    slot from `next` onward, calling `emit` for each in order. It releases
    one window token per result it writes.
  - The dispatcher acquires a window token, then a worker token, before it
    starts `i`. Since tokens come back in index order, `i < next + window`
    holds by construction.
- **Stopping:** after `emit` returns false, nothing more is emitted. The
  dispatcher waits for each token in a `select` on `ctx.Done()`, so a stop
  ends dispatch even while it waits for a window token that will never come
  back. Every running worker sees `ctx` cancelled, and its result is
  dropped.
- **The run's context ending** also cancels `ctx`. The workers then fail
  with the run's error, and `emit` reports it at the first slot it reaches
  (§3.6).
- **`ordered` returns true only when all `n` results were emitted.** If the
  run's context ended and dispatch stopped before every index started,
  `ordered` returns false even though no `emit` stopped it. The work it did
  start may all have succeeded. The sweep then checks the run's context
  and, if it ended, prints the run's error and returns 3, unless `emit`
  already printed it.
- **Context:** `ctx` is a child of the run's context that `ordered` cancels
  on stop. The budgets (`newBudget`) derive from it. `budget.over` keeps
  taking the run's context, so a stop does not count anything as a timeout.

### 4.2 Phase 1

`work` is today's closure body, returning a `lintResult`. `emit` does what
phase 2's loop does today for one aut-num, at the moment it is reached:

1. If the run's context has ended, print the run's error and stop (§3.6).
2. If the slot has an error, print `rpslcheck: <AS>: <err>` and stop (§3.5).
3. If the lint finished, write the lint (`w.lint`) and add its issues to
   the totals.
4. Write the slot's `timeout` records (JSON) and count them.
5. Keep only what the pair list needs: the aut-num's `peers` and `via`, in
   two slices indexed like today's `lints`. Drop the issues.

The pair list is built after `ordered` returns, as today. It uses the kept
`peers`, `seen` and the `via` count.

### 4.3 Phase 3

`work` runs one `Check` under its budget and returns a `checkResult`.
`emit` does what today's final loop does for one pair:

1. Write the `timeout` or `limit` record and count it.
2. If the pair has an error, print it to stderr and stop.
3. Otherwise write the report, add it to the totals, and drop it.

The totals are written after `ordered` returns, as today.

### 4.4 What is held afterwards

- **During phase 1:** at most `window` `lintResult`s with their issues, the
  `peers` and `via` slices for every aut-num (AS numbers only), and the
  totals.
- **During phase 3:** the pair list (954,052 pair-families over RIPE),
  at most `window` reports, and the totals.

## 5. Considered and not chosen

- **No window; rely on `-check-timeout`.** With the default 1-minute budget,
  what waits is bounded by what finishes in a minute. But `-check-timeout 0`
  is a supported mode, and the window costs one semaphore.
- **Spilling results to a temporary file and replaying it in order.** This
  costs disk (2.75 GB for RIPE in JSON) and a second pass, and it brings
  temporary-file failure modes. The window gives the same memory bound
  without them.
- **Writing in completion order.** This would break `-c` determinism and
  every golden.
- **Shrinking `consist.Issue`**, for example by not keeping formatted
  messages. It would reduce what is held, but memory would still grow with
  the registry. It could be done separately, and it touches `consist`'s API.

## 6. Tests

All in `resolve/internal/rpslcheck`.

- **`ordered`'s unit tests** (`TestOrdered*`):
  - **Order:** results are emitted in index order for `conc` 1, 4 and 16,
    with work whose durations are random and seeded.
  - **Window:** with `window` 4 and work 0 blocked until released, at most 4
    works ever start, counted with an atomic counter. Releasing work 0
    lets the rest run, and everything is emitted in order.
  - **Stop:** `emit` returning false at index k means no index above k is
    emitted. Every running work's `ctx` is cancelled. `ordered` returns
    false after every worker has returned (no goroutine is left, checked
    with a WaitGroup in the test's work).
  - **Edge cases:** n = 0, n smaller than `conc` or `window`, and
    `window` = 1.
- **Existing tests, unchanged:** `TestGoldens`, `TestSweepIsDeterministic`
  (`-c 1` against `-c 8`), `TestSweepCheckTimeout`, `TestSweepPeersBeforeLint`,
  `TestSweepCountsUndecidable`, `TestSetPeers` and `TestLintFollowsFamilies`.
  The output is meant to be identical, so none of them changes.
- **A failed run** (`TestSweepStopsAtError`): a fixture with an aut-num whose
  lint fails with a non-limit error, through a `PolicySource` wrapper that
  fails one AS. Stdout holds every earlier aut-num's lint and nothing after
  it. Stderr holds the line `rpslcheck: <AS>: <err>`, and the exit status
  is 3.
- **The run's own deadline:** `TestSweepCheckTimeout`'s `-timeout 1ns` case
  keeps exit 3. A new assertion checks that stderr names the context error
  and no aut-num.
- **Race:** check.sh runs the package under `-race`.

## 7. Verification

Every run is alone, under `.superpowers/sdd/tools/memguard.sh`, with
GOMAXPROCS=4.

1. **Sample:** `rpslcheck -sweep -sample 2000 -c 4 -json` over the nine RIPE
   dumps, against the v0.27.0 binary.
   - The output must be byte-identical.
   - The wall time must be within 2% of v0.27.0's on the same machine,
     measured in this session. If it is not, raise the window (§3.2).
   - Report the max RSS.
2. **Full sweep with the memo** (GOMEMLIMIT=5GiB, 7 GB guard): the run the
   memo could not finish. Report the wall time, the user CPU, max RSS and
   the peak.
   - Compare it with `main`'s full output
     (`.superpowers/sdd/sweep-memo/full-main.out`).
   - The memo changes which lints time out (§2 of the measurements), so the
     comparison drops:
     - the `timeout` records;
     - the `issue` records of every aut-num that timed out in either run;
     - the `totals` record.
   - Every other line must be identical, in the same order.
   - The totals' pair and direction counts must be equal.
3. **`FUZZTIME=15s scripts/check.sh`** must report `check: ok`.

## 8. Docs

- **`docs/rpslcheck.md`:**
  - Replace the paragraph on the sweep holding lint issues until linting
    ends with the new behaviour: results are written as they finish, in
    order, and at most 1,024 wait at once. Give the measured full-sweep
    figures from §7.2.
  - Add that a sweep stopped by an error, `-timeout` or an interrupt
    leaves the results already written. Its JSON then has no `totals`
    record.
- **`CHANGELOG.md`, Unreleased → Changed:** the sweep writes results as
  they finish, with §7's figures. Under the same heading, note the partial
  output on failure.

## 9. Risks

- **A window too small for skewed work** costs wall time. One very slow
  aut-num at `next` stops dispatch once 1,024 later ones are done. With the
  default budget this lasts at most about a minute per slow item. §7.1
  measures the cost.
- **One aut-num with millions of issues** is still held whole. AS50952 had
  2,232,178 issues with no budget. The window bounds the count of results
  held, not their size. Writing one aut-num's issues as they are found
  would need `consist` to stream `Lint`'s issues, and that is out of scope.
- **Phase 3's share is unknown** until §7.2 runs.
