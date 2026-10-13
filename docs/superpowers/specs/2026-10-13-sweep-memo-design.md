# A sweep-wide memo for consistency checking

Status: proposed · 2026-10-13 · planned v0.27.0 · branch `sweep-perf`

## 1. Summary

`rpslcheck -sweep` repeats the same work in every `Check`. A provider's
aut-num is decoded again for each of its peers, its filters are normalized
again (the same as-sets expanded again), and the same prefix spaces are
built again. This design adds an opt-in memo that lives as long as a
`Checker` and shares that work across calls. It changes no result: every
answer with the memo is the answer without it.

Three pieces:

1. `resolve.FilterMemo`: `NormalizeFilter`'s answers, shared between
   Expanders that differ only in `AFI`, limits and `Peer`, keyed by the
   filter's whole structure, the AFI and the effective limits. An answer that read the peer is never shared; the normalizer
   records whether it did (§4.2).
2. A cached `PrefixSpace` inside each `Conjunct` that `NormalizeFilter`
   builds, so every copy of a memoized conjunct shares one (§4.3).
3. `consist.Memo`: a bounded LRU of decoded aut-nums and inet-rtrs, and the
   `FilterMemo`, for a `Checker`'s calls (§4.4). `rpslcheck` turns it on.

## 2. Measurements behind it

All on RIPE's dumps of 2026-09-27, a seeded sample of 2,000 aut-nums
(`RPSL_CONSIST_SAMPLE=2000`), GOMAXPROCS=4, at commit `a3fff21` (which
already removed two wasted sorts, §9).

- Shaped as `rpslcheck -sweep` runs it (no `Cache`, Forward peers, each
  pair once, both families; a throwaway test): 3m56s wall over 4 workers;
  the aut-nums' own times sum to 15m44s, 5m0s in `Lint` and 10m43s in
  `Check`. AS1299 alone (3,411 peers, 6,806 checks, 6,827 policy lines)
  took 3m10s.
- CPU profile of that run: `Check` 258.6 s, of which
  - decoding aut-nums (`policyEntry.decode`): 64.5 s (25%) — `policyMemo`
    lives for one call, so AS1299 is decoded once per check;
  - `types.SpaceOf` under `consist.sideOf`: 86.0 s (33%);
  - `NormalizeFilter`: 67.8 s (26%) — AS1299's export to each peer names
    the same customer as-set, expanded again every time.
  Iterating and flattening the attributes is under 5%.
- `rpslcheck` checks pairs sorted by A, then B (sweep.go phase 2), so one
  aut-num's checks as side A run consecutively: a small LRU of decoded
  aut-nums catches the repeats.

The upper bound of the gain is the 84% above; the real gain is measured in
§7, not promised here.

## 3. Decisions

- **Exact or nothing.** The memo returns what recomputation would. Where
  that cannot be known cheaply (an answer that read the peer), it does not
  cache.
- **Opt-in.** `Expander.Memo` and `Checker.Memo` are nil by default, and
  nil is today's behaviour. No other caller (peval directly, rtconfig,
  rpslq, irrdq) changes.
- **Keyed by filter structure, not by attribute.** Two aut-nums importing
  "AS-FOO" share one answer. The key is `memoText`, a rendering of the whole
  tree (every AND/OR/NOT and binary AS expression bracketed, a community
  test's operator, Raw and Values and an AS-path regexp's Raw and tree
  verbatim), plus the AFI and the effective MaxDepth, MaxPrefixes,
  MaxVisited and MaxConjuncts. (Amended after the final review:
  `policy.Filter.String()` is not unique per filter — it drops grouping that
  the normalizer's limit accounting depends on, and collapses community
  spellings — so a String-keyed hit could change a limit error into a
  success. A filter with a node memoText does not know is not memoized.)
- **Bounded memory, by what grows.** The `FilterMemo` is bounded by the
  prefix ranges it holds, the aut-num LRU by entry count. Defaults are
  chosen from the measurement in §7, not guessed.
- **Errors.** Successes are cached, and so are the three errors that
  follow from the inputs alone: `*SetTooLargeError`, `*NotEnumerableError`,
  `*AnySetError`. A context error or a `Source` failure never is: a check
  over its time budget must not poison the next one.

## 4. Design

### 4.1 `resolve.FilterMemo`

```go
// FilterMemo shares NormalizeFilter's answers between Expanders that
// differ only in AFI and Peer: the same Src, limits and Concurrency, and no
// Exclude. An answer is keyed by the filter's text and AFI; one whose
// normalization read Peer (PeerAS, a set template, a regexp naming the
// peer, at any depth, inside filter-sets too) is never stored, so a hit is
// always the answer NormalizeFilter would compute. Successes are stored,
// and the errors that follow from the filter and the registry alone
// (*SetTooLargeError, *NotEnumerableError, *AnySetError); a context error
// or a Source failure never is. It holds at most maxRanges prefix ranges in
// all, evicting the least recently used answers; an answer larger than a
// quarter of that is not stored. A NormalFilter it returns is shared: the
// caller must not modify it. Safe for concurrent use.
type FilterMemo struct{ /* mu; entries map[filterKey]*list.Element; lru; held, max int; hits, misses */ }

// NewFilterMemo returns a FilterMemo holding at most maxRanges prefix
// ranges (prefixes and negated prefixes of every conjunct it stores).
func NewFilterMemo(maxRanges int) *FilterMemo

// FilterMemoStats is a FilterMemo's counters, for measurement and tests.
type FilterMemoStats struct {
	Hits, Misses   int // lookups answered from the memo / computed
	PeerDependent  int // computed answers not stored because they read Peer
	Entries, Held  int // answers stored; prefix ranges they hold
}

func (m *FilterMemo) Stats() FilterMemoStats

type Expander struct {
	// … existing fields …

	// Memo, when set, answers NormalizeFilter from a FilterMemo shared
	// with other Expanders (see FilterMemo for which may share one). It is
	// ignored when Exclude is set. EvalFilter and set expansion do not
	// read it.
	Memo *FilterMemo
}
```

Key (as amended): `filterKey{text string; afi types.AFI; depth, prefixes,
visited, conjuncts int}`, text from `memoText(f)`. Lookup in `NormalizeFilter`:
when `e.Memo != nil && e.Exclude.empty()`, compute the key; on a hit
return the stored `(NormalFilter, error)`; on a miss normalize, then store
unless the normalizer read the peer or the error is not one of the three.
Two goroutines missing the same key both compute; the second store is a
no-op. That is duplicate work, never a wrong answer.

### 4.2 Knowing whether an answer read the peer

`Expander.Peer` is read in exactly four places today, all inside one
normalization: `FilterPeerAS` and a filter's set template
(expand_more.go:391-403), an AS expression's set template
(expand_more.go:644), and binding a regexp (normalize.go:456). Each becomes
a call to one accessor on the evaluator, which records the read:

```go
// peer returns Expander.Peer and records that the answer depends on it.
func (ev *filterEval) peer() types.ASN { ev.usedPeer = true; return ev.e.Peer }
```

The normalizer's two evaluators (`ev` and `noEx`) and the normalizer
itself (the regexp) each record; the answer read the peer if any did.
Reading it with `Peer == 0` counts too (the `ErrUnboundPeer` answer
depends on the peer being unbound). A filter-set is inlined through the
same evaluators, so a read inside one is recorded. To keep a fifth read
from bypassing the accessor, a test (§6) fails on any `.e.Peer` or
`.ev.e.Peer` in resolve's non-test sources outside `peer()`.

### 4.3 A `Conjunct`'s space, computed once

```go
type Conjunct struct {
	// … existing fields …
	space *spaceOnce // set by NormalizeFilter; nil for a Conjunct built by hand
}

type spaceOnce struct {
	once sync.Once
	s    types.PrefixSpace
}

// Space is unchanged in meaning: computed once per conjunct NormalizeFilter
// built, and shared by its copies; computed each call for one built by hand.
func (c Conjunct) Space() types.PrefixSpace
```

`finish` sets `space: &spaceOnce{}` on each conjunct it keeps. Copies of a
`Conjunct` (a memoized `NormalFilter` handed to many checks) share the
pointer, so `consist.sideOf` builds each space once per memoized answer.
No exported API changes (the field is unexported; `Conjunct` already has
one, `any`).

### 4.4 `consist.Memo`

```go
// Memo shares work between a Checker's calls: decoded aut-nums and
// inet-rtrs (a bounded LRU) and normalized filters (a resolve.FilterMemo).
// It changes no answer. It holds data read from Checker.Eval.Src, so it
// serves one Checker, or Checkers with the same Eval; it never notices a
// change in the Source, so build a new one for a new snapshot. Safe for
// concurrent use.
type Memo struct{ /* objects lru; filters *resolve.FilterMemo */ }

// MemoOptions bounds a Memo. Zero fields take the defaults (§7).
type MemoOptions struct {
	AutNums int // decoded aut-nums and inet-rtrs held
	Ranges  int // prefix ranges the filter memo holds
}

func NewMemo() *Memo                       // NewMemoWith(MemoOptions{})
func NewMemoWith(o MemoOptions) *Memo
func (m *Memo) Stats() MemoStats

type MemoStats struct {
	AutNumHits, AutNumMisses int
	Filters                  resolve.FilterMemoStats
}

type Checker struct {
	// … existing fields …

	// Memo, when set, shares decoded objects and normalized filters across
	// this Checker's calls (Check, Lint, Peers). nil: each call stands
	// alone. Results are the same either way.
	Memo *Memo
}
```

`Checker.eval()`: with `c.Memo == nil`, as today (a per-call `policyMemo`).
With a memo, `Src` is wrapped by a `policyMemo` backed by the shared LRU
instead of a per-call map, and `Expander.Memo` is set to
`c.Memo.filters` (Exclude is already cleared in `eval`). Lint's peer
existence check keeps going to `c.Eval.Src` directly, so the LRU never
fills with peers that are only looked up (v0.26.1's review finding).
`PolicyIndex` is still asserted on `c.Eval.Src`.

### 4.5 `rpslcheck`

All three modes set `Checker.Memo = consist.NewMemo()`: one AS checked
against thousands of peers is a sweep in miniature. No new flag; the memo
is result-neutral, and the goldens hold that (§6).

## 5. Considered and not chosen

- **Caching by (aut-num, attribute, term).** Shares less (not across
  aut-nums) and needs peval to expose term identity. Filter text needs
  neither.
- **Caching peer-dependent answers per peer.** Each such answer is used by
  one pair; it would only grow memory.
- **Caching every decoded aut-num.** 707 MB for RIPE (CLAUDE.md); the
  sorted pair order makes a small LRU enough.
- **`resolve.Cache` around the Source.** It caches Source answers, which a
  MemSource already serves from maps; the expansion work is above it. The
  real-data test's use of it only adds locking.
- **Fixing the Lint/Check quadratic in peval** (indexing attributes by
  peer). Iteration is under 5% of `Check` now; not worth the complexity.

## 6. Tests

- `resolve`: `TestFilterMemoMatches` — over the filter model's random
  filters (filter_model_test.go's generator: sets, filter-sets, PeerAS,
  templates, regexps naming the peer, NOT, AND/OR), normalize each for
  several peers and both AFIs with one shared memo and without; `String()`,
  `Missing()` and the error must be equal every time, and a filter that
  names the peer must show `PeerDependent` growing, never a hit.
- `resolve`: a cancelled context's error is not stored (cancel, then a live
  call computes and succeeds); a failing Source's error is not stored.
- `resolve`: eviction — with a small bound, answers stay equal and `Held`
  never exceeds it; an oversized answer is computed and not stored.
- `resolve`: the accessor guard — no `.e.Peer` read outside `peer()` in
  resolve's non-test files (a source scan, like apisurface's checks).
- `resolve`: `Conjunct.Space` on a memoized conjunct equals `SpaceOf` of
  its ranges; a hand-built `Conjunct` still works.
- `resolve`: `FuzzNormalizeFilter` gains the property "normalizing twice
  through one memo gives the same answer as without it".
- `consist`: the consistency model (resolve/consist_model_test.go, `TestModelConsist*`) runs every
  seed with and without a shared `Memo`, reports equal; `Lint` likewise.
- `consist`: `-race` with Checks from many goroutines through one `Memo`.
- `rpslcheck`: `TestGoldens` unchanged with the memo on (all modes).
- Benchmark: `BenchmarkCheckProvider` — one aut-num exporting one as-set to
  N peers, every pair checked; with and without the memo.

## 7. Verification and defaults

- RIPE seeded sample (2,000): `TestRealDataConsist` with `Checker.Memo`
  set; every count equal to today's (94,660 directions, 47,330 pairs, …).
- `rpslcheck -sweep -sample 2000` over RIPE's dumps: wall time and peak
  RSS with and without the memo, at -c 4, under memguard.
- Defaults: run the full RIPE sweep once with the memo unbounded and record
  peak RSS and `Stats().Filters.Held`; set `Ranges` so the memo's share
  stays under 1 GB at that measurement, and `AutNums` at 256 unless the
  hit rate says otherwise. Both figures, and the full sweep's time before
  and after, go in CHANGELOG and docs/rpslcheck.md.

## 8. Docs

CLAUDE.md (engine traps: the memo is result-neutral, never shares an
answer that read the peer, never stores a context or Source error),
design doc §8.12, docs/rpslcheck.md (cost section), CHANGELOG, `api/`
golden (new `resolve` and `consist` signatures).

## 9. Already done on this branch

`a3fff21`: `Conjunct.Space` no longer sorts (SpaceOf ignores order;
`TestSpaceOfOrderIndependent`), and `finish` builds a conjunct's text for
deduplication only when two conjuncts could print the same. Sample sweep
counts unchanged; that test's CPU in its sweep loop 628 s → 453 s.

## 10. Risks

- **A missed peer read** would serve one peer's answer to another. The
  accessor, the source-scan test and the model test with peer-dependent
  filters all guard it.
- **A caller mutating a shared `NormalFilter`.** consist and peval only
  read; the implementation plan greps every use of a returned
  `NormalFilter` in consist and peval before enabling the memo.
- **Memory.** Bounded; defaults set from the full-sweep measurement.
