# A call's own filter memo

Status: proposed · 2026-10-15 · planned v0.28.0 · branch `call-memo`

## 1. Summary

In a `-c 4` sweep, AS31117's and AS1101's lints run past the 60 s budget,
although each lints in seconds alone. The cause is the shared filter memo:
one lint reuses a few large normalized IXP filters hundreds of times, the
memo holds them, and other workers' lints evict them between sessions, so
the lint normalizes them again and again. This design gives each call (one
`Lint`, `Check` side or `Peers`) a filter memo of its own, layered over the
shared one: what the call has computed or fetched, it keeps until it
returns, whatever the shared memo evicts meanwhile. It changes no result.

Two changes:

1. `resolve.NewFilterMemoOver(shared, maxRanges)`: a `FilterMemo` that
   answers from itself, then from `shared`, and stores what it computes in
   both (§4.1).
2. `consist.Checker.eval` gives each evaluator such a layer over
   `Memo.filters`; without `Checker.Memo`, its own memo's bound rises from
   1<<18 to `defaultMemoRanges` (1<<21), the bound one IXP lint needs (§4.2).

## 2. Measurements behind it

RIPE's dumps of 2026-09-27, current main (v0.27.2), one process at a
time under memguard; a throwaway probe test in `resolve/consist`
(session scratchpad `p31117/`). Every run below gave AS31117's same 8,207
issues (same hash).

| AS31117's lint | time | allocated | filter misses |
|---|---|---|---|
| alone, fresh `Memo` (cold) | 7.7 s | 5.3 GB | 13 |
| alone, same `Memo` again (warm) | 6.5 s | 4.0 GB | 0 new |
| alone, no `Checker.Memo` | 75 s | 80 GB | — |
| alone, GOMAXPROCS 4, memory limit 256 MB above the live heap | 17.3 s | 5.3 GB | 13 |
| beside AS1101, AS47147, AS202827 linted in a loop, GOMAXPROCS 4, default `Memo` | **2m21s** | 338 GB | 10,052 (whole memo) |
| the same with `MemoOptions{Ranges: 1<<24}` | **10.6 s** | 19 GB | 6,868 (whole memo) |

- Alone, AS31117's 13 filter answers weigh 1,928,317 of the default
  2,097,152 bound; its 67 sessions look them up 1,521 times.
- In the concurrent run with the default memo, AS1101 timed out every time
  (60 s) and AS202827 took 38–48 s; with the 16M memo they took 3.4–5.5 s
  and 4.3–6.3 s. Peak RSS: 3,765 MB vs 5,635 MB; the large memo held
  8,933,594 ranges.
- AS47147 took 47 s even with the 16M memo: its time is its own
  `lint/shadowed` work, which this design does not touch.
- Without `Checker.Memo`, each evaluator's memo is bounded at 1<<18, and an
  answer over a quarter of the bound (65,536) is never stored: AS31117's
  IXP filters are larger, so every session normalizes them again.
- A heap held at its memory limit slows the lint 2.2× (GC), not 8×: GC near
  `GOMEMLIMIT` is a secondary cost, out of scope here.

Conclusion: the timeouts come from evicting the answers a running call
still needs. LRU over a cyclic working set slightly larger than its share of
the bound misses on every access, hence the cliff (7 s → 141 s), not a
gradual slowdown.

## 3. Decisions

- **Exact or nothing**, as for `FilterMemo`: the layer returns the answer
  recomputation would, under the same key. It stores only what the shared
  memo would store (successes and the three input-determined errors; never
  a context error, a Source failure or an answer that read the peer).
- **A call keeps what it uses.** A call's layer holds pointers to the same
  immutable answers the shared memo holds; it costs memory only for answers
  the shared memo has evicted while the call runs.
- **Explicitly bounded.** The layer is a `FilterMemo` with its own bound, in
  the same units and with the same quarter rule. `consist` sets it to the
  shared memo's bound (`MemoOptions.Ranges`, default 1<<21): one call keeps
  at most what the whole shared memo could. No new option: `Ranges` lowers
  both. A call whose own working set exceeds the bound still thrashes, as
  today.
- **The shared memo sees one access per call.** A hit in the layer does
  not touch the shared memo: it takes no shared lock and does not refresh
  the shared LRU. The shared memo's recency then means "recently used by a
  new call", which is what sharing across calls needs.
- **Opt-in stays opt-in.** Callers of `resolve` that set `Expander.Memo`
  themselves are unchanged; only `consist` builds layers.

## 4. Design

### 4.1 `resolve.NewFilterMemoOver`

```go
// NewFilterMemoOver returns a FilterMemo bounded as NewFilterMemo(maxRanges)
// is, layered over shared: a lookup it cannot answer itself is answered from
// shared when shared holds the key, and the answer is then kept in the layer
// too; an answer computed through it is stored in the layer and in shared,
// each by its own rules. A hit in the layer does not touch shared. Use one
// for one call's evaluations, so that what shared evicts while the call runs
// is not computed again; shared must serve the same snapshot (see
// FilterMemo). A nil shared is NewFilterMemo(maxRanges).
func NewFilterMemoOver(shared *FilterMemo, maxRanges int) *FilterMemo
```

Implementation: a `shared *FilterMemo` field.

- `get(k)`: the layer's own entry → hit. Otherwise, if `shared != nil`,
  `shared.get(k)`; on a hit, `store` the same `*filterAnswer` in the layer
  (its own pool bound, quarter rule and LRU) and count a hit. Otherwise a
  miss.
- `put`/`putASNs`: build the answer once; `store` it in the layer, then in
  `shared` (each applies `memoizable`, the duplicate check and the quarter
  rule itself). The weight is computed once.
- Locking: the layer's mutex, released before `shared`'s is taken, so the
  two are never held together.
- `Stats`: the layer's own lookups (a hit answered from `shared` counts as
  the layer's hit, and as a hit in `shared`'s stats). `shared`'s counters
  see one lookup per call per key.

### 4.2 `consist`

`Checker.eval`:

```go
case c.Memo != nil:
	e.Src = memoSource{PolicySource: e.Src, m: c.Memo}
	e.Expander.Memo = resolve.NewFilterMemoOver(c.Memo.filters, c.Memo.ranges)
default:
	e.Src = &policyMemo{...}
	if e.Expander.Memo == nil {
		e.Expander.Memo = resolve.NewFilterMemo(defaultMemoRanges)
	}
```

- `Memo` records its `ranges` bound (set in `NewMemoWith`).
- `callMemoRanges` (1<<18) is removed; its comment's reasoning moves to
  `eval`'s doc.
- The evaluator, and so the layer, lives as long as it does today: `Lint`
  one for all its sessions and one each for its peer list, set walk and
  router walk; `Check` one per side (`policies`); `Peers` one.
- `Checker.Memo`'s doc: each call keeps the filter answers it uses for its
  duration; the shared memo bounds what is kept across calls.

`rpslcheck` needs no change.

## 5. Considered and not chosen

- **A larger default bound** (16M in §2): fixes these lints, but holds
  ~1.9 GB more for every sweep whether or not it needs it, moves the cliff
  rather than removing it, and does nothing for `Checker` without `Memo`.
- **Pinning in the shared LRU** (reference counts from calls in flight):
  the same memory as a layer, but every hit takes the shared lock to pin
  and unpin, and eviction must skip pinned entries — more state in the one
  structure every worker contends on.
- **A scan-resistant policy** (segmented LRU, 2Q, TinyLFU): keeps some
  calls' working sets, but four IXP lints need ~8.9M ranges against a 2.1M
  bound, so some still thrash, and which ones depends on timing.
- **Fewer workers**: avoids the contention by giving up the parallelism.

## 6. Tests

Written first, each failing on main where it can:

1. `resolve` (filtermemo_test.go), over a counting Source:
   - `TestFilterMemoOverKeepsEvicted`: a filter normalized through layer
     L over shared S; S then filled through another layer until it evicts
     that answer; the filter again through L: a hit, no Source fetch. (On
     main, with L replaced by S, the second normalization fetches again.)
   - `TestFilterMemoOverShares`: an answer computed through layer A is a
     hit in layer B over the same S, and B fetches nothing.
   - `TestFilterMemoOverStoresOnlyWhatSharedWould`: a context error, a
     Source failure and a peer-reading answer are stored in neither; a
     `*SetTooLargeError` in both; an answer over a quarter of the layer's
     bound in neither layer nor (same bound) shared.
   - Same for `ExpandAS` answers (the expansion pool).
   - Concurrent use of one layer and of several layers over one S under
     `-race`.
2. `consist`:
   - Result neutrality: `Lint` and `Check` over the consist model and the
     lint fixtures give the same issues with no `Memo`, with
     `NewMemo()`, and with `NewMemoWith(MemoOptions{Ranges: R})` for an R
     small enough to evict between sessions, run concurrently on one
     `Checker`.
   - `TestPeerReadsGoThroughAccessor` and the existing memo tests unchanged.
3. Benchmark `BenchmarkLintBesideOthers`: the IXP lint fixture of
   `BenchmarkLintIXP`, linted while other goroutines lint different
   aut-nums on the same `Checker` with a bound below their joint working
   set. Before/after with `scripts/bench.sh`.
4. `api/resolve.txt`: `NewFilterMemoOver` added (`RPSL_API_UPDATE=1`).

## 7. Verification

- The probe of §2 on the branch: AS31117 beside the three others with the
  default `Memo` (expected near the 10.6 s of the large memo, not 2m21s;
  AS1101 under 60 s), and alone without `Memo` (expected near 7.7 s, not
  75 s), with peak RSS for each.
- A full RIPE `rpslcheck -sweep -c 4 -json`, GOMAXPROCS 4,
  `GOMEMLIMIT=5GiB`, against v0.27.2's run: output identical outside
  timeouts; lint timeouts 3 → 1 (AS47147) expected; wall time and peak RSS
  reported (v0.27.2: 2,092 s, 6,680 MB). Gate: peak RSS under the 8 GB
  guard. If it grows by more than ~1 GB, stop and revisit the bound
  (a separate `MemoOptions` field for the layer) before going on.
- The consist sample (`RPSL_CONSIST_SAMPLE=2000`) counts identical to
  `.superpowers/sdd/sweep-profile/run2.log.counts`.
- `GOMAXPROCS=4 FUZZTIME=15s scripts/check.sh` under memguard.

## 8. Docs

- `docs/rpslcheck.md` (the paragraph at line ~198): the real cause of the
  AS1101/AS31117 timeouts, the remaining one (AS47147), new figures.
- CHANGELOG `[Unreleased]`: `NewFilterMemoOver` (Added); `consist` calls
  keep their answers, the no-`Memo` bound (Changed); correct v0.27.2's
  "why it runs past 60 s in the sweep was not determined" with the cause,
  in the new entry (the released entry stays as released).
- `FilterMemo`'s and `Checker.Memo`'s doc comments; CLAUDE.md's
  "`Checker.Memo` is result-neutral" bullet gains the layer.

## 9. Risks

- **Memory.** Worst case, each call in flight keeps up to two pools of
  `Ranges` beyond the shared memo: with `-c 4` and the default, ~16.8M
  ranges, on the order of 5 GB at the ~330 bytes of RSS a held range cost
  in §2 (1,870 MB more for 6.0M more ranges; a rough figure, GC timing
  included).
  Typical is far less — only what the shared memo evicted while that call
  runs — and the thrash it replaces allocated 338 GB of garbage. §7's
  sweep decides.
- **Without `Checker.Memo`**, each evaluator now holds up to 1<<21 per pool
  instead of 1<<18 for its lifetime; library callers running many calls at
  once hold that much per call. Measured in §7 (AS31117 alone).
- **The shared memo's statistics change meaning**: it counts one lookup per
  call per key, so its hit rate falls although no work is added. Any
  figure quoted from `Memo.Stats` before this change is not comparable.
- **A call that alone needs more than the bound** still thrashes; none of
  RIPE's aut-nums is known to (AS31117, the largest measured, uses 92%).
