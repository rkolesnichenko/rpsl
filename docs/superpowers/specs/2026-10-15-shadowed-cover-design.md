# A lint/shadowed cover that keeps large spaces apart

Status: proposed · 2026-10-15 · planned v0.29.0 · branch `shadowed-cover`

## 1. Summary

RIPE's AS47147 lints in 42.5 s alone and took 50.3 s beside three other IXP
lints in a `-c 4` probe: the slowest lint in a RIPE sweep, close to the 60 s
budget. 87% of its lint's CPU is `lint/shadowed`, almost all of it in IPv6
import sessions whose clauses name large, overlapping IXP route-server
as-sets. Each such session builds the union of those sets again
(`PrefixSpace.Union` of two large spaces) and tests each clause against it
(`PrefixSpace.Subset`, which builds the whole difference first). This design
makes both cheap. It changes no result.

Three changes:

1. `types`: `PrefixSpace.Subset` decides containment by walking the two
   tries and stopping at the first prefix of `s` that `t` lacks, allocating
   nothing, instead of building `s.Minus(t)`.
2. `types`: a new `PrefixSpace.SubsetOfUnion(ts ...PrefixSpace) bool`
   decides whether `s` lies in the union of `ts` without building the union,
   in one walk over all of them. `Subset(t)` is `SubsetOfUnion(t)`.
3. `consist`: the `lint/shadowed` cover (`sigCover`) folds a small earlier
   space into one union, as today, and keeps a large one apart (up to 16 per
   signature); a clause is tested with `SubsetOfUnion(folded, large...)`.

## 2. Measurements behind it

RIPE's dumps of 2026-09-27, v0.28.0 (0a76557), GOMAXPROCS 4, one process at
a time under memguard; throwaway probes in `.superpowers/sdd/p47147/`
(lint probe, per-policy and per-clause traces, micro-tests), prototypes in a
scratch worktree.

**Where AS47147's time goes** (alone, fresh `Memo`: 42.5 s cold, 43.3 s warm,
351 peers, 30,652 issues, hash 2216ffda0acec5df):

- `cover.shadowed` 29.1 s of the lint's 33.3 s of profiled CPU:
  `PrefixSpace.Union` 16.2 s, `PrefixSpace.Subset` (via `Minus`) 12.8 s;
  25.6 GB allocated, GC 8.2 s CPU. Evaluation (`peval`) about 2 s.
- By direction and family (traced): IPv6 import 40.9 s of 44.9 s in
  `lint/shadowed`, over 271 sessions averaging 10.8 clauses (up to 50),
  cover up to 46,141 ranges; IPv6 export 2.5 s, IPv4 import 1.5 s, IPv4
  export 0.0 s. Lint's sentinel session is not involved.
- 150 of AS47147's 244 `mp-import:` lines are
  `afi ipv6.unicast from AS-<X> accept AS-<X>`. Six of those sets are
  41,125–45,993 ranges each (AS-DECIX, AS-DECIX-MUC, AS-DECIX-HAM,
  AS-DECIX-DUS, AS-VIX-RS, AS-SWISSIX-RS); a peer in several of them gets
  all of them in its session: AS-DECIX's clause is in 260 of the 271.
- Micro-test (random IPv6 spaces): against a 46,000-range space, a Union
  or Subset with a 10-range space takes about 8 µs (untouched subtrees are
  shared), but a Subset that must walk a large space whole — measured as
  the 46,000-range space against itself, which v0.28.0 does not
  short-circuit — takes 18.5 ms, linear in its size (0.54 ms at 1,000
  ranges).
- Reuse across sessions is real but tangled: 2,889 clause checks hold 1,473
  distinct (earlier clauses, clause) pairs, because each peer's own small
  clauses fall between the large ones; restricted to the large clauses,
  2,095 checks hold 209 distinct pairs.

**Prototypes** (same probe; every run gave the same 30,652 issues and hash):

| AS47147's lint, alone | cold | allocated | GC CPU | `lint/shadowed` |
|---|---|---|---|---|
| v0.28.0 | 42.5 s | 25.6 GB | 8.2 s | 29.1 s |
| early-exit `Subset` only | 30.2 s | 25.1 GB | 8.3 s | 18.7 s |
| `SubsetOfUnion` over every earlier space (a plain list) | 13.0 s | 5.8 GB | 1.7 s | 5.9 s |
| `SubsetOfUnion`, small spaces folded, large kept apart (this design) | 14.1 s | 6.8 GB | 2.2 s | 6.4 s |

The plain list is quadratic in the number of clauses: n random small
disjoint clauses checked in turn took 3.3 s at n = 5,000 and 70 s at
n = 20,000, against 11 ms and 57 ms today. The hybrid (fold below 1,024
trie nodes, keep up to 16 large) against today, same micro-tests:

| sequence | today | hybrid |
|---|---|---|
| 1,000 small | 4.6 ms | 3.6 ms |
| 20,000 small | 50.9 ms | 61.9 ms |
| 12 large of 40,000 ranges, overlapping | 166.7 ms | 0.16 ms |
| 60 large of 5,000 | 202.9 ms | 113.0 ms |
| 400 large of 2,000 | 716.5 ms | 643.5 ms |
| 10 large among 1,990 small | 115.9 ms | 8.7 ms |
| whole pool, then 11 covered of 40,000 | 252.2 ms | 157.4 ms |
| whole pool, then 39 covered of 20,000 | 593.0 ms | 791.6 ms |
| pool in 8 parts, then 39 covered | 611.5 ms | 797.6 ms |

Other lints, alone, cold, v0.28.0 → hybrid (same issues and hashes):
AS31117 7.7 s → 2.1 s, AS202827 5.2 s → 2.7 s, AS1101 4.4 s → 1.6 s.

## 3. Decisions

- **Exact, as today.** `Subset` and `SubsetOfUnion` answer exactly what
  `s.Minus(union).IsEmpty()` answers; the cover's verdicts are unchanged.
- **Never build a union only to test containment in it.** That is where the
  time and the 25 GB went.
- **Keep folding small spaces.** A union with a small space is cheap and
  keeps a long sequence of small clauses linear, as v0.27.2 made it.
- **Bounded worst case.** A signature keeps at most 16 large spaces apart;
  past that they fold, as today. A test then walks the clause against at
  most 17 spaces: the measured worst case above is 1.34× today's, against
  3× faster for AS47147.
- **The policy lives where it is used.** `types` gains one method; which
  spaces count as large, and how many are kept, are `consist`'s, private.
  "Large" is counted in ranges through `Ranges()`, stopping at 1,024 (the
  prototype counted trie nodes; §7 re-measures with ranges).
- **No reuse across sessions.** It would need keying by clause identity and
  by which small clauses fell between; once the large unions are gone, the
  remaining per-session work (6.4 s for AS47147) does not justify it.

## 4. Design

### 4.1 `types`

```go
// Subset reports whether every prefix in s is also in t.
func (s PrefixSpace) Subset(t PrefixSpace) bool { return s.SubsetOfUnion(t) }

// SubsetOfUnion reports whether every prefix in s is in at least one of
// ts: s.Subset of their union, without building it. It walks s's trie
// beside all of ts', stops at the first prefix of s none of them holds,
// and allocates nothing but a work list of trie nodes.
func (s PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool
```

Implementation: `merge(opMinus, …)` reduced to "is the result empty", over
a list of right-hand nodes:

- `subsetUnion(a, bs, d, width, inA, inB)`: nothing inherited and `a` nil →
  true; nothing inherited on `a`'s side and `a` is one of `bs` (the same
  node) → true; no `bs` and nothing inherited → false (a node in canonical
  form is never empty).
- The right-hand mask is the OR of `inB` and every `b`'s mask; when `a` and
  every `b` are leaves, the answer is `fa &^ fb == 0`; otherwise this
  node's own prefix must pass (`(fa &^ fb) & one(d) == 0`) and both
  children recurse with the inherited masks and, as `bs`, the non-nil
  children of `bs`.
- The children's `bs` lists are windows of one work slice, appended for a
  call and truncated on return.

`lift` is not needed: it moves a mask between levels without changing
whether a result is empty.

### 4.2 `consist`

```go
// sigCover is the earlier conjuncts whose tests are a subset of sig,
// earlier[:n] of them taken in: small spaces folded into one union, large
// ones (at least coverLarge ranges, at most coverKeep of them) kept apart,
// since a union of two large overlapping spaces is the costly part.
type sigCover struct {
	sig    []string
	folded types.PrefixSpace
	large  []types.PrefixSpace
	n      int
}

const (
	coverLarge = 1024 // ranges
	coverKeep  = 16
)
```

- `shadowed` takes each new earlier conjunct in with `add`: `large` if it
  has at least `coverLarge` ranges and `large` has room, `folded` otherwise;
  then tests `union(g).SubsetOfUnion(append([]PrefixSpace{folded}, large...)...)`.
- `cover`'s doc (which cites AS47147's 122 s) gains the new reason.

## 5. Considered and not chosen

- **Early-exit `Subset` alone**: 42.5 → 30.2 s; the Unions remain (16 s,
  25 GB). Kept as part of this design, not alone.
- **A plain list of earlier spaces**: 13.0 s for AS47147, but quadratic in
  the clauses (70 s for 20,000 small ones).
- **Reusing covers across sessions** (§3).
- **A `merge` shortcut for identical subtrees**: helps only where two spaces
  share structure; the IXP sets are different spaces.
- **A `types.SpaceUnion` accumulator** holding the policy: more API for one
  caller.

## 6. Tests

Written first, each failing on main where it can:

1. `types`:
   - `TestSubsetOfUnionAgainstMinus`: random expressions from the model
     generator, 0–5 right-hand spaces, some built to contain `s`; the answer
     equals `s.Minus(union).IsEmpty()` (both answers occur). Includes
     inherited masks (`^+`, `^n-m`), IPv4 and IPv6, empty spaces, `s` among
     `ts` (the same node), and no `ts`.
   - `TestSpaceAgainstBruteForce` already holds `Subset` to the oracle.
   - `FuzzPrefixSpace`: also checks `SubsetOfUnion` of the second
     expression split in two against `Subset` of it whole.
   - `TestSubsetAllocatesNothing` (`testing.AllocsPerRun`, two large
     overlapping spaces, `Subset` false and true): 0 allocations on main
     fails.
2. `consist`:
   - `TestCoverMatchesNaive` keeps its random clause sequences and gains
     sequences mixing spaces over `coverLarge` ranges with small ones, and
     more than `coverKeep` large ones (the folding path).
   - Lint results unchanged: the existing lint and consist model tests.
3. Benchmarks (`scripts/bench.sh`): `BenchmarkShadowedLarge` (sessions of
   six large overlapping IPv6 spaces among small ones, as AS47147's) and
   `BenchmarkShadowedManySmall` (20,000 small clauses: must not regress).
4. `api/types.txt`: `SubsetOfUnion` added (`RPSL_API_UPDATE=1`).

## 7. Verification

- The probe of §2: AS47147, AS31117, AS202827 and AS1101 alone (each with
  the same issues and hash as v0.28.0), and AS47147 beside the other three
  (v0.28.0: 50.3 s).
- A full RIPE `rpslcheck -sweep -c 4 -json`, GOMAXPROCS 4,
  `GOMEMLIMIT=5GiB`, against v0.28.0 on the same dumps: output identical;
  lint timeouts 0; wall time and max RSS (`/usr/bin/time`) reported
  (v0.28.0: 2,008 s, 6,773 MB).
- The consist sample (`RPSL_CONSIST_SAMPLE=2000`) counts identical to
  `.superpowers/sdd/sweep-profile/run2.log.counts`.
- `GOMAXPROCS=4 FUZZTIME=15s scripts/check.sh` under memguard.

## 8. Docs

- CHANGELOG `[Unreleased]`: `SubsetOfUnion` (Added); `Subset` allocates
  nothing and stops early, `lint/shadowed` (Changed), with §7's figures.
- `docs/rpslcheck.md` (the paragraph on AS47147, line ~200) and
  `docs/rpsl-go-design.md` (the `sigCover` sentence, line ~1102).

## 9. Risks

- **A long run of large spaces** past `coverKeep` folds them, as today: no
  worse than today plus at most 17 spaces per test (1.34× in the worst
  measured case).
- **The "large" threshold is a guess** from one aut-num; it only moves cost
  between the two measured shapes, never a result. §7's sweep decides.
- **Counting ranges to 1,024 per earlier conjunct** costs a short walk per
  conjunct per session; the prototype's node count did the same and is
  included in its 14.1 s.
