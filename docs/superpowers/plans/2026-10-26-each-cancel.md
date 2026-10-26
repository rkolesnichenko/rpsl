# `each` stops at a cancelled context — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Expander.each` starts no Source call once it sees the context cancelled. Its three
callers return the context's error and never read a skipped slot.

**Architecture:**
- **`each`.** It takes the context and returns `ctx.Err()` once every started call has returned.
  - The serial path checks the context before each call.
  - The parallel path waits on a semaphore slot or `ctx.Done()`, and checks the context again
    after it takes a slot.
- **Callers.** `fetchLevel`, `fetchClaims` and `fetchRoutes` check that error before reading
  results. `fetchRoutes` gains the check; today it has none.
- **Scope.** All of it is in `resolve/expander.go`, plus one new test file.

**Tech Stack:** Go 1.23 (multi-module, go.work). Run the resolve module's tests from `resolve/`.

**Spec:** `docs/superpowers/specs/2026-10-26-each-cancel-design.md`. Read it first. Its
"The change" and "Tests" sections are the requirements this plan implements.

## Global Constraints

- No exported API change. `go run ./internal/apisurface -check` (from the repo root) passes,
  and `api/` stays untouched.
- No result changes when the context is not cancelled. `TestConcurrencyDoesNotChangeResults`
  and `TestConcurrencyWithClaims` pass unchanged.
- Engine purity holds: `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki`
  shows no `net`.
- Heavy runs (check.sh, real data) go one at a time, never beside each other:
  - under `/Users/roman/DEV/rpsl/.superpowers/sdd/tools/memguard.sh 8 <timeout_s> <cmd>`;
  - with `MEMGUARD_NORMAL_PRIORITY=1`, `GOMAXPROCS=4` and `GOMEMLIMIT` set.
- Commit messages follow the repo's style: a lower-case package prefix, as in
  `resolve: share one MaxVisited budget across a normalization`.
- zsh: redirect a command's output to a file and print `$?` on the next line. Never pipe a test
  run into `tail` or `grep` and read the status from that.

## Review Focus

1. **A skipped `fetchResult` reaching `discover`.** It must never be read. The test is
   discovery's own row: on cancellation, `ExpandAS` returns `context.Canceled` and does not
   panic (Task 1, `TestEachStopsAtCancel` "sets").
2. **Cancellation while every slot is full.** The launching loop must not start a call after
   `ctx.Done()`, whichever case Go's `select` picks. The test is each parallel row's exact count
   of 4, run 20 times under `-race` (Task 1, Step 4).
3. **A cancelled routes batch where some started call failed.** It returns `ctx.Err()`, not the
   Source's error and not nil. The test is `TestFetchRoutesReturnsCancel` (Task 1).
4. **A context already cancelled before the batch.** It makes zero calls and returns
   `context.Canceled`. `discover` checks the context before each level, so `each` is reached here
   only through `fetchClaims` and `fetchRoutes`. Covered by a "pre-cancelled" case in
   `TestFetchRoutesReturnsCancel` (Task 1).
5. **No cancellation at all.** Results are unchanged at every Concurrency. Covered by the
   existing tests in Global Constraints; Task 2 runs them as part of check.sh.

---

### Task 1: `each` honours the context, with its tests and docs

**Files:**
- Create: `resolve/cancel_test.go` (package `resolve`)
- Modify: `resolve/expander.go`:
  - `each` (about lines 431–455);
  - `fetchLevel` (about 422–429);
  - `fetchClaims` (about 466–492);
  - `fetchRoutes` (about 665–702);
  - the `Concurrency` field's comment (about 49–54).
- Modify: `CHANGELOG.md` `## [Unreleased]`

**Interfaces:**
- Produces: `func (e *Expander) each(ctx context.Context, n int, do func(i int)) error`.
- Consumes from existing tests: `corpus(t, texts...) *MemSource` and
  `asSet(name, members...) string` (expander_test.go), `mustSet` and `types.Ref`.

- [ ] **Step 1: Write the failing tests in `resolve/cancel_test.go`**

  **`batchSrc`**
  - It wraps `*MemSource`.
  - It counts calls to one method, `method` (`"GetSet"`, `"MembersByRef"` or
    `"OriginatedRoutes"`). For `GetSet` and `MembersByRef` it counts only sets whose name starts
    with `AS-S`. For `OriginatedRoutes` it counts every call.
  - On each counted call it runs `onCall func()`, then delegates.
  - It uses a mutex for the count.

  **`cancelAt(src *batchSrc, n int, cancel func())`**
  - The n-th counted call calls `cancel()` and then releases every waiting call.
  - Calls before the n-th wait for that release, with a 5 s fallback as `inFlight` has.
  - Calls after it pass straight through.
  - With n = 1 it is "the first call cancels".

  **The three graphs, each a batch of 40**
  - `"sets"`: `AS-TOP` whose members are `AS-S0`…`AS-S39`. Each `AS-Si` is
    `members: AS<100+i>`. The test calls `ExpandAS(AS-TOP)`.
  - `"claims"`: the same, but each `AS-Si` also has `mbrs-by-ref: MNT-A`, and there is a
    `mntner: MNT-A`. The test calls `ExpandAS(AS-TOP)`.
  - `"routes"`: `AS-FLAT` with `members: AS100, …, AS139`. The test calls
    `ExpandPrefixes(AS-FLAT)`.

  **`TestEachStopsAtCancel`**
  - It runs every graph at each pair of `(Concurrency, n)`: `(1, 1)` and `(4, 4)`.
  - Each case uses a fresh `context.WithCancel`, wired through `cancelAt`.
  - Assert `errors.Is(err, context.Canceled)`.
  - Assert the count is exactly `n`. Write the message as
    `"%s at Concurrency %d: %d of 40 calls, want %d"`.

  **`TestFetchRoutesReturnsCancel`**
  - Build the `"routes"` graph with `g, err := e.discover(context.Background(), ref, false)`, with
    `e.Concurrency = 4`.
  - **Case 1:** call `e.fetchRoutes(cctx, g)`, where the first `OriginatedRoutes` call cancels
    `cctx`. Want `context.Canceled`.
  - **Case 2:** in the same Source, have that first call also return `errors.New("routes failed")`.
    Still want `context.Canceled`.
  - **Case 3 (pre-cancelled):** call it with a context cancelled before the call. Want
    `context.Canceled` and a count of 0.

- [ ] **Step 2: Run them and see them fail on today's code**

  Run (from `resolve/`): `go test -count=1 -run 'TestEachStopsAtCancel|TestFetchRoutesReturnsCancel' . > <scratchpad>/t1.txt 2>&1; echo $?`

  Expected: exit 1.
  - Every `TestEachStopsAtCancel` case reports `40 of 40 calls`.
  - In `TestFetchRoutesReturnsCancel`, case 1 and case 3 get nil (MemSource ignores the
    context), and case 2 gets "routes failed".

  If a count is not 40, stop: the test is not measuring the batch.

- [ ] **Step 3: Implement**

  **`each(ctx context.Context, n int, do func(i int)) error`**
  - Serial path: check `ctx.Err()` before each `do(i)` and stop at the first non-nil.
  - Parallel path: acquire a slot with `select { case sem <- struct{}{}: case <-ctx.Done(): }`
    and stop on `Done`. After taking a slot, check `ctx.Err()` again. If it is set, release the
    slot and stop.
  - Return `ctx.Err()` after `wg.Wait()`.
  - Rewrite the doc comment to say what is skipped, what is waited for, and what is returned.
    Drop "Checking ctx.Err() afterwards is the caller's job."

  **Callers**
  - `fetchLevel`: `return out, e.each(ctx, …)`.
  - `fetchClaims`: use `each`'s error in place of its own `ctx.Err()` check, so cancellation
    still wins over the per-set errors.
  - `fetchRoutes`: return `each`'s error before the loop over `errs`.
  - `discover`: leave it unchanged. Its `fetchLevel` error check already comes before any slot is
    read.

  **`Concurrency` comment.** Add one sentence: a cancelled context stops new fetches, and fetches
  already started finish.

  **CHANGELOG.** Under `## [Unreleased]`, add `### Fixed` with one entry:

  > `resolve`: once the context is cancelled, an expansion starts no further Source call (a
  > batch of a level's sets, claims or routes made every remaining call before; the answer was
  > the context's error either way).

- [ ] **Step 4: Run the new tests, the cancel and concurrency tests, under `-race`, 20 times**

  Run (from `resolve/`): `GOMAXPROCS=4 go test -race -count=20 -run 'TestEachStopsAtCancel|TestFetchRoutesReturnsCancel|TestClaimsPassHonoursCancel|TestContextCancellation|TestExpandContextCancellationMidWalk|TestConcurrency' . > <scratchpad>/t1r.txt 2>&1; echo $?`

  Expected: exit 0, and `ok` for the package.

- [ ] **Step 5: Run the whole resolve package once**

  Run (from `resolve/`): `GOMAXPROCS=4 GOMEMLIMIT=4GiB go test -count=1 . > <scratchpad>/t1all.txt 2>&1; echo $?`

  Expected: exit 0.

- [ ] **Step 6: Commit**

  ```bash
  git add resolve/cancel_test.go resolve/expander.go CHANGELOG.md
  git commit -m "resolve: start no fetch after the context is cancelled"
  ```

### Task 2: Verification (the controller runs this; it is not dispatched)

**Files:** none changed, unless a step finds a fault.

- [ ] **Step 1: Full check, under the guard**

  Run from the repo root:

  `MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 GOMEMLIMIT=6GiB scripts/check.sh > <scratchpad>/check.txt 2>&1; echo $?`

  Expected: 0, `check: ok`, and no `api/` diff.

- [ ] **Step 2: Real data, main against the branch, one run at a time**

  1. `git worktree add <scratchpad>/rpsl-main main`.
  2. In each tree, from `resolve/` and under the guard as above:

     `RPSL_REALDATA=/Users/roman/DEV/rpsl/.data RPSL_CONSIST_SAMPLE=2000 GOMAXPROCS=4 GOMEMLIMIT=6GiB go test -count=1 -timeout 60m -run TestRealDataConsist -v ./consist > <scratchpad>/<tree>-consist.txt 2>&1; echo $?`

     The sample is seeded (`rand.NewPCG(1, 0)`), so both trees check the same aut-nums.
  3. Compare the summary counts. Every count that is not a time-budget count must be equal.
     Report the over-budget counts of both trees side by side. Stop and report if any other
     count differs.
  4. `git worktree remove <scratchpad>/rpsl-main`.

- [ ] **Step 3: Independent review**

  Dispatch a fresh reviewer on the most capable model with `git diff main...each-cancel` and
  the spec. Fix its Critical and Important findings, then re-run Task 1 Step 4 and Task 2
  Step 1. Report to the user. Push and open a PR only when the user says so.
