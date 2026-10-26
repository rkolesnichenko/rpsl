# `each` stops launching calls once the context is cancelled — design

Approved by the user 2026-10-26.

## Why

`Expander.each` (resolve/expander.go) runs the engine's batched Source calls, up to
`Concurrency` at a time. It has three callers:

| Caller | Source call | What it fetches |
|---|---|---|
| `fetchLevel` | `GetSet` | one breadth-first level of discovery |
| `fetchClaims` | `MembersByRef` | every discovered set with a `mbrs-by-ref:`, in one batch |
| `fetchRoutes` | `OriginatedRoutes` | each distinct member AS once |

`each` never looks at the context. Once the context is cancelled, it still starts every remaining
call of the batch, and the caller then returns `ctx.Err()`, so the answer is right but the work is
wasted. A probe on 2026-10-26 (main at b74543a, a throwaway test in a scratch worktree, since
removed) cancelled the context inside the first call of a 40-call batch. The batch still made
**40 of 40** calls, at Concurrency 1 and at Concurrency 4, for both `GetSet` (one level of 40
sets) and `OriginatedRoutes` (an as-set of 40 ASes). Every run returned `context canceled`.

How much that costs depends on the Source:

- `irrd`'s Source checks the context before it queries (resolve/irrd/irrd.go, pipeline.go), so
  each wasted call fails fast. The cost is one goroutine and one semaphore slot per call.
- `MemSource` and `Corpus` ignore the context, so every remaining lookup runs in full. This is
  the path `rpslcheck` and `consist` take, and their per-check time budgets cancel by deadline. A
  check over its budget keeps doing lookups until the batch is done.
- A third-party Source that ignores the context does all the work, possibly over the network.

This was found by the second review of PR #38 and left as a follow-up.

## Goals

1. Once `each` sees the context cancelled, it starts no further call. Calls already started run
   to completion, and `each` still waits for every one of them before it returns.
2. Every caller of `each` returns the context's error when it was cancelled. A skipped call
   leaves its slot at the zero value, and no caller may read that as an answer.
3. Results are unchanged whenever the context is not cancelled, at every `Concurrency`.
4. A regression test for each caller, at Concurrency 1 and at a Concurrency above 1. Each test
   fails on today's main.

## Non-goals

- Interrupting a call that has already started. That is the Source's job, through the context
  it is given.
- Making `MemSource` or `Corpus` check the context. Their lookups are in memory, and with this
  change none starts after a cancellation is seen anyway.
- The other worker pools: rpslq, rpslcheck's sweep, rpsld and irrdserver. They were not
  audited for this, and this change does not touch them.
- Any exported API change. `api/*.txt` must not change.

## Anti-goals

- A cancelled expansion that returns success, or an answer built from skipped (zero) slots.
- A goroutine still running after `each` returns. Callers read the result slices right after
  it.
- A result that depends on `Concurrency` or on scheduling when the context is not cancelled
  (`TestConcurrencyDoesNotChangeResults` and `TestConcurrencyWithClaims` hold this today and
  must keep passing unchanged).

## The change

### `each`

The new signature is `each(ctx context.Context, n int, do func(i int)) error`. It returns
`ctx.Err()` after every started call has returned. The review of PR #38 had made `each` return
nothing, because its callers checked the context themselves. Now `each` may skip calls, so
returning the error makes that impossible to miss at a call site.

- **Serial path** (`Concurrency` ≤ 1, or n ≤ 1): check `ctx.Err()` before each call and stop at
  the first non-nil.
- **Parallel path:** acquiring a semaphore slot waits on either the slot or `ctx.Done()`,
  whichever comes first, and stops on `ctx.Done()`. Go's `select` picks at random when both are
  ready, so after taking a slot, check `ctx.Err()` once more. If it is set, give the slot back
  and stop. Without that check, a cancelled batch could still start a call whenever a slot
  happened to be free.

The guarantee is: no call starts once `each` has seen the cancellation. A goroutine that was
spawned before that, but has not yet been scheduled, still makes its call, so up to
`Concurrency` calls can start after the moment of cancellation. In the tests below the
cancellation happens while every slot holds a call already in progress, so nothing is
spawned-but-pending and the counts are exact.

### Callers

A skipped slot is a new state: a zero `fetchResult` has neither a set nor an error, and a zero
claims or routes slot looks like an empty answer. A zero slot is never a valid entry, so every
caller checks `each`'s error before it reads any slot.

- **`fetchLevel`** returns `out, e.each(ctx, …)`. That is the same error it returns today.
  `discover` already checks that error before it reads a slot (expander.go, right after the
  `fetchLevel` call). That check must stay first: building a node from a zero `fetchResult`
  calls `nestedRefs` on a nil set and panics.
- **`fetchClaims`** uses `each`'s error in place of its own `ctx.Err()` check. A cancellation
  still comes before the first per-set error.
- **`fetchRoutes`** checks `each`'s error **before** it reads `errs`. Today it returns the first
  per-AS error and relies on the evaluator's walk to notice the cancellation later. With
  skipped slots it would otherwise store nil routes for unfetched ASes and return nil. The walk
  would still refuse, but the function must not depend on that. So a cancelled batch now
  returns the context's error even when some started call failed with its own error. This
  matches `fetchClaims`.

### Docs

- Update `each`'s doc comment: what it skips, what it waits for, and what it returns. Drop
  "Checking ctx.Err() afterwards is the caller's job."
- Add one sentence to the `Concurrency` field's comment: a cancelled context stops new fetches,
  and fetches already started finish.
- Add a CHANGELOG `[Unreleased]` / Fixed entry.

CLAUDE.md needs no change. The `Concurrency` invariant it states ("must not change a result")
is unaffected.

## Tests

The tests go in package `resolve`, as `claims_test.go` is. Each test uses a counting Source over
a `MemSource`, which ignores the context, so every call that starts is visible. The probe's
shape is enough: a batch of 40, an `AS-TOP` whose members are 40 defined sets, and an as-set of
40 ASes.

| Test | Concurrency | Setup | Asserts | On main |
|---|---|---|---|---|
| discovery, serial | 1 | `GetSet` of the 40-set level cancels on its first call | exactly 1 of that level's calls; `context.Canceled` | 40 |
| discovery, parallel | 4 | each call waits until 4 are in flight (a barrier, as `inFlight`), and the 4th cancels before releasing them | exactly 4; `context.Canceled` | 40 |
| claims, serial and parallel | 1 and 4 | as above, over `MembersByRef` (40 sets with `mbrs-by-ref:`) | exactly 1 and exactly 4; `context.Canceled` | 40 |
| routes, serial and parallel | 1 and 4 | as above, over `OriginatedRoutes` | exactly 1 and exactly 4; `context.Canceled` | 40 |
| `fetchRoutes` direct | 4 | call `fetchRoutes` on a discovered graph with a context the Source cancels | returns `context.Canceled`, not nil | nil |

The last test calls the unexported function because, through `ExpandPrefixes`, the walk hides
the missing check.

Test mechanics:

- **Count only the batch under test.** `AS-TOP` itself is fetched first, as a level of one,
  through the serial path. A counter or barrier that includes that call waits for a 4th call that
  never comes. The probe counted only names starting `AS-S`. Do the same.
- **A new barrier hook.** `inFlight` replaces `claimCounter.onClaims` and only waits, so
  "wait until 4 are in flight, then the 4th cancels before releasing them" needs a new helper, or
  `inFlight` extended. It must work for all three Source methods. Keep a timeout fallback, as
  `inFlight` has, so a broken `each` fails the count instead of hanging.
- **The existing cancel tests stay.** `TestClaimsPassHonoursCancel` (one set with claims) and
  `TestClaimsPassHonoursCancelWideLevel` (three) assert only the error, and they keep passing.
  Neither has a batch big enough to count skipped calls, so the new claims rows are new tests,
  not edits of these.

Each test must be seen failing on main before the fix. Run them 20 times under `-race`, as the
barrier test in PR #38 was.

## Verification before done

- `scripts/check.sh` under the memory guard (`GOMAXPROCS=4`, `GOMEMLIMIT`, 8 GB cap).
- Real data. The cancellation that real runs hit is consist's per-check deadline, so run
  `TestRealDataConsist` with `RPSL_CONSIST_SAMPLE` on main and on the branch, alone and under the
  guard, with the same `RPSL_CONSIST_SAMPLE` value on both (the builder picks it).
  - Every count that does not depend on a time budget must be equal.
  - Counts of checks over their budget may differ, since they depend on timing. Report both.

## Left to the builder

- The helper type and test names, and whether the three callers share one parameterised test.
- Whether the serial and parallel paths share the "may I start call i?" check.

## Release

**My call:** this goes on a branch with the CHANGELOG under `[Unreleased]`. It ships as v0.30.2
only when you ask; nothing in routecheck needs it.
