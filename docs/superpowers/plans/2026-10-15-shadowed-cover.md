# A lint/shadowed cover that keeps large spaces apart — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `lint/shadowed` cheap for aut-nums whose sessions hold several large, overlapping IXP clauses (RIPE's AS47147: 42.5 s alone, 87% of it in `lint/shadowed`), without changing a result.

**Architecture:** `types.PrefixSpace.Subset` decides containment by an allocation-free walk that stops at the first missing prefix; a new `PrefixSpace.SubsetOfUnion(ts...)` decides containment in a union without building it. `consist`'s `sigCover` keeps folding small earlier spaces into one union but keeps up to 16 large ones (at least 1,024 ranges) apart, and tests a clause with `SubsetOfUnion`.

**Tech Stack:** Go 1.23 floor; `types` (leaf module) and `resolve/consist` (resolve module); memguard-guarded real-data runs on RIPE's dumps.

**Spec:** `docs/superpowers/specs/2026-10-15-shadowed-cover-design.md` (approved 2026-10-15). Read it first; this plan argues from it.

## Global Constraints

- `go.mod` floors stay at go 1.23; no new dependency.
- No result changes: `Subset` and `SubsetOfUnion` answer exactly what `s.Minus(union).IsEmpty()` answers; every lint and check output is unchanged.
- Leaf isolation: `cd types && go list -deps ./... | grep rkolesnichenko` shows only `github.com/rkolesnichenko/rpsl/types`.
- Engine purity: `cd resolve && go list -deps . ./consist` must not include `net`.
- API surface: `api/types.txt` gains exactly `func (PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool`; regenerate with `RPSL_API_UPDATE=1 go run ./internal/apisurface -check` from the repo root and review the diff; `go run ./internal/apisurface -check` must pass.
- `coverLarge = 1024` (ranges) and `coverKeep = 16` are `consist`'s private constants; `types` holds no policy.
- Heavy runs (real data, check.sh with fuzz) one at a time, under `.superpowers/sdd/tools/memguard.sh`, `GOMAXPROCS=4`, never beside each other.
- Every figure written into docs or the CHANGELOG comes from a command run on this branch in this work; anything not measured is called unknown.
- Commit only on branch `shadowed-cover`; push and PR only after the user says so.

## Review Focus

1. Inherited lengths: a range above a node (`10.0.0.0/8^+` over `10.1.0.0/16`) must count on either side, including when `s`'s own node is one of `ts`' (the same-node shortcut is only valid with nothing inherited on `s`'s side). → Task 1, `TestSubsetOfUnionAgainstMinus` (the model generator draws ranges above its universe; `s` itself is among `ts` in a quarter of the cases) and `TestSubsetOfUnionEdges`.
2. Families: `s` with IPv4 and IPv6 parts against `ts` holding only one family, or empty spaces among `ts`. → Task 1, `TestSubsetOfUnionEdges`.
3. No `ts` at all, or an empty `s`. → Task 1, `TestSubsetOfUnionEdges`.
4. More than `coverKeep` large spaces under one signature: the extras fold into the union, and verdicts stay exact. → Task 2, `TestCoverKeepsLargeApart`.
5. A large earlier space whose tests are not a subset of the clause's must not cover it. → Task 2, `TestCoverMatchesNaiveLarge` (random signatures over two tests).

---

### Task 0: Branch

- [ ] **Step 1: Create the branch and commit the spec and this plan**

```bash
cd /Users/roman/DEV/rpsl
git checkout -b shadowed-cover main
git add docs/superpowers/specs/2026-10-15-shadowed-cover-design.md docs/superpowers/plans/2026-10-15-shadowed-cover.md
git commit -m "docs: shadowed-cover spec and plan"
git status --short
```
Expected: one commit on `shadowed-cover`; `git status` clean.

---

### Task 1: `types`: an early-exit `Subset` and `SubsetOfUnion`

**Files:**
- Modify: `types/prefixspace_ops.go` (the `Subset` line and below it)
- Modify: `types/prefixspace_model_test.go` (`FuzzPrefixSpace`)
- Create: `types/prefixspace_subset_test.go`
- Modify: `api/types.txt` (generated)

**Interfaces:**
- Consumes: nothing new.
- Produces: `func (s PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool`; `Subset(t)` keeps its signature and answers.

- [ ] **Step 1: Write the failing tests**

Create `types/prefixspace_subset_test.go`:

```go
package types

import (
	"math/rand/v2"
	"testing"
)

// SubsetOfUnion answers as Minus of the union does, and Subset as Minus:
// random expressions from the model generator (both families, ranges
// reaching above the universe, so inherited lengths), up to five right-hand
// spaces, a quarter of the cases completed to contain s and a quarter
// holding s itself (the same nodes).
func TestSubsetOfUnionAgainstMinus(t *testing.T) {
	yes, no := 0, 0
	for seed := uint64(0); seed < 5000; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x50))
		s := randomExpr(r, 3).space(t)
		var ts []PrefixSpace
		var u PrefixSpace
		for k := r.IntN(6); k > 0; k-- {
			x := randomExpr(r, 3).space(t)
			ts = append(ts, x)
			u = u.Union(x)
		}
		switch r.IntN(4) {
		case 0: // the rest of s: now a subset
			rest := s.Minus(u)
			ts = append(ts, rest)
			u = u.Union(rest)
		case 1: // s itself
			ts = append(ts, s)
			u = u.Union(s)
		}
		want := s.Minus(u).IsEmpty()
		if want {
			yes++
		} else {
			no++
		}
		if got := s.SubsetOfUnion(ts...); got != want {
			t.Fatalf("seed %d: %v SubsetOfUnion %v = %v, Minus says %v", seed, s, ts, got, want)
		}
		if got := s.Subset(u); got != want {
			t.Fatalf("seed %d: %v Subset %v = %v, Minus says %v", seed, s, u, got, want)
		}
	}
	if yes < 500 || no < 500 {
		t.Fatalf("%d subsets and %d not in 5000: the test draws too few of one", yes, no)
	}
}

func TestSubsetOfUnionEdges(t *testing.T) {
	v4 := spaceOf(t, "10.0.0.0/24^+")
	v6 := spaceOf(t, "2001:db8::/32")
	both := v4.Union(v6)
	cases := []struct {
		name string
		s    PrefixSpace
		ts   []PrefixSpace
		want bool
	}{
		{"empty in nothing", PrefixSpace{}, nil, true},
		{"empty in something", PrefixSpace{}, []PrefixSpace{v4}, true},
		{"something in nothing", v4, nil, false},
		{"something in empty spaces", v4, []PrefixSpace{{}, {}}, false},
		{"itself", v4, []PrefixSpace{v4}, true},
		{"itself among others", v4, []PrefixSpace{v6, v4}, true},
		{"the other family", v4, []PrefixSpace{v6}, false},
		{"both families, split", both, []PrefixSpace{v6, v4}, true},
		{"both families, one missing", both, []PrefixSpace{v4, {}}, false},
		{"inherited from a shorter range", spaceOf(t, "10.1.0.0/16"), []PrefixSpace{spaceOf(t, "10.0.0.0/8^+")}, true},
		{"inherited on s's side", spaceOf(t, "10.0.0.0/8^+"), []PrefixSpace{spaceOf(t, "10.0.0.0/8^9-32")}, false},
		{"lengths split across two", spaceOf(t, "10.0.0.0/24^24-25"), []PrefixSpace{spaceOf(t, "10.0.0.0/24"), spaceOf(t, "10.0.0.0/24^25")}, true},
		{"a /23 is not its two /24s", spaceOf(t, "10.0.0.0/23"), []PrefixSpace{spaceOf(t, "10.0.0.0/24"), spaceOf(t, "10.0.1.0/24")}, false},
	}
	for _, c := range cases {
		if got := c.s.SubsetOfUnion(c.ts...); got != c.want {
			t.Errorf("%s: %v SubsetOfUnion %v = %v, want %v", c.name, c.s, c.ts, got, c.want)
		}
		var u PrefixSpace
		for _, x := range c.ts {
			u = u.Union(x)
		}
		if got := c.s.Subset(u); got != c.want {
			t.Errorf("%s: %v Subset %v = %v, want %v", c.name, c.s, u, got, c.want)
		}
	}
}

// Subset allocates nothing, whether it answers true or false, on two large
// overlapping spaces (Minus built the whole difference first).
func TestSubsetAllocatesNothing(t *testing.T) {
	x := SpaceOf(benchRanges(20_000, 24, 32)...)
	y := SpaceOf(benchRanges(20_000, 24, 28)...)
	if !y.Subset(x) || x.Subset(y) {
		t.Fatalf("fixture: want y in x and x not in y")
	}
	for _, c := range []struct {
		name string
		f    func()
	}{{"true", func() { _ = y.Subset(x) }}, {"false", func() { _ = x.Subset(y) }}} {
		if n := testing.AllocsPerRun(10, c.f); n != 0 {
			t.Errorf("Subset answering %s: %v allocations, want 0", c.name, n)
		}
	}
}
```

In `types/prefixspace_model_test.go`, `FuzzPrefixSpace`, replace

```go
		checkExpr(t, "fuzz", randomExpr(r, depth), randomExpr(r, 2))
```

with

```go
		e, other := randomExpr(r, depth), randomExpr(r, 2)
		checkExpr(t, "fuzz", e, other)
		// SubsetOfUnion of other split in two answers as Subset of it whole.
		s, o, h := e.space(t), other.space(t), randomExpr(r, 2).space(t)
		if got, want := s.SubsetOfUnion(o.Intersect(h), o.Minus(h)), s.Subset(o); got != want {
			t.Fatalf("fuzz: %v SubsetOfUnion(%v split by %v) = %v, Subset %v", e, other, h, got, want)
		}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/roman/DEV/rpsl/types && go test -count=1 -run 'TestSubset|TestSpaceAgainstBruteForce' . 2>&1 | tail -5
```
Expected: build failure, `s.SubsetOfUnion undefined` (and `c.s.SubsetOfUnion undefined`).

A build failure does not show `TestSubsetAllocatesNothing` failing for its own reason, so Step 3a first adds a `SubsetOfUnion` built on the old `Subset`, which makes the package build and leaves `Subset` as it is.

- [ ] **Step 3a: `SubsetOfUnion` on the old `Subset`, to see the allocation test fail**

Add to `types/prefixspace_ops.go`, below `Subset`:

```go
func (s PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool {
	var u PrefixSpace
	for _, t := range ts {
		u = u.Union(t)
	}
	return s.Subset(u)
}
```

```bash
cd /Users/roman/DEV/rpsl/types && go test -count=1 -run 'TestSubsetAllocatesNothing' . 2>&1 | tail -4
go test -count=1 -run 'TestSubsetOfUnion' . 2>&1 | tail -2
```
Expected: `TestSubsetAllocatesNothing` FAILS with "Subset answering true: N allocations, want 0" (N > 0) and the same for false; `TestSubsetOfUnion*` PASS (the stub is exact, only slow).

- [ ] **Step 3b: The real implementation**

In `types/prefixspace_ops.go`, replace

```go
// Subset reports whether every prefix in s is in t: s.Minus(t).IsEmpty().
func (s PrefixSpace) Subset(t PrefixSpace) bool { return s.Minus(t).IsEmpty() }
```

and Step 3a's stub with

```go
// Subset reports whether every prefix in s is in t, as s.Minus(t).IsEmpty()
// would, but stops at the first prefix of s that t lacks and allocates
// nothing.
func (s PrefixSpace) Subset(t PrefixSpace) bool {
	return subsetNode(s.v4, t.v4, 0, 32, lenMask{}, lenMask{}) &&
		subsetNode(s.v6, t.v6, 0, 128, lenMask{}, lenMask{})
}

// SubsetOfUnion reports whether every prefix in s is in at least one of
// ts: s.Subset of their union, without building it. It walks s's trie
// beside all of ts', stops at the first prefix of s none of them holds, and
// allocates only a work list of trie nodes.
func (s PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool {
	if len(ts) == 1 {
		return s.Subset(ts[0])
	}
	var work []*spaceNode
	for _, t := range ts {
		if t.v4 != nil {
			work = append(work, t.v4)
		}
	}
	if !subsetUnion(s.v4, work, 0, 32, lenMask{}, lenMask{}, &work) {
		return false
	}
	work = work[:0]
	for _, t := range ts {
		if t.v6 != nil {
			work = append(work, t.v6)
		}
	}
	return subsetUnion(s.v6, work, 0, 128, lenMask{}, lenMask{}, &work)
}

// subsetNode reports whether merge(opMinus, a, b, d, width, inA, inB) would
// be empty, without building it: false at the first prefix a holds and b
// does not. A canonical node is never empty, so a node of a with nothing
// inherited against nothing at all is a difference.
func subsetNode(a, b *spaceNode, d, width int, inA, inB lenMask) bool {
	if inA.isZero() {
		if a == nil || a == b {
			return true
		}
		if b == nil && inB.isZero() {
			return false
		}
	}
	fa, fb := inA, inB
	if a != nil {
		fa = fa.or(a.mask)
	}
	if b != nil {
		fb = fb.or(b.mask)
	}
	fa, fb = fa.and(geMask[d]), fb.and(geMask[d])
	if leaf(a) && leaf(b) {
		return fa.andNot(fb).isZero()
	}
	if !fa.andNot(fb).and(one(d)).isZero() {
		return false
	}
	if d < width {
		ia, ib := fa.and(geMask[d+1]), fb.and(geMask[d+1])
		return subsetNode(kid(a, 0), kid(b, 0), d+1, width, ia, ib) &&
			subsetNode(kid(a, 1), kid(b, 1), d+1, width, ia, ib)
	}
	return true
}

// subsetUnion is subsetNode against the union of bs, nodes at depth d. bs
// is a window of *work; each child's nodes are appended after it for the
// child's call and dropped on return, so the walk needs one list whatever
// its depth.
func subsetUnion(a *spaceNode, bs []*spaceNode, d, width int, inA, inB lenMask, work *[]*spaceNode) bool {
	if inA.isZero() {
		if a == nil || slices.Contains(bs, a) {
			return true
		}
		if len(bs) == 0 && inB.isZero() {
			return false
		}
	}
	fa, fb := inA, inB
	if a != nil {
		fa = fa.or(a.mask)
	}
	leaves := leaf(a)
	for _, b := range bs {
		fb = fb.or(b.mask)
		leaves = leaves && leaf(b)
	}
	fa, fb = fa.and(geMask[d]), fb.and(geMask[d])
	if leaves {
		return fa.andNot(fb).isZero()
	}
	if !fa.andNot(fb).and(one(d)).isZero() {
		return false
	}
	if d < width {
		ia, ib := fa.and(geMask[d+1]), fb.and(geMask[d+1])
		for i := range 2 {
			start := len(*work)
			for _, b := range bs {
				if k := b.child[i]; k != nil {
					*work = append(*work, k)
				}
			}
			end := len(*work)
			ok := subsetUnion(kid(a, i), (*work)[start:end:end], d+1, width, ia, ib, work)
			*work = (*work)[:start]
			if !ok {
				return false
			}
		}
	}
	return true
}
```

Add `"slices"` to `types/prefixspace_ops.go`'s imports (it has none today: add `import "slices"` below `package types`).

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/roman/DEV/rpsl/types
go test -count=1 -race . 2>&1 | tail -2
go test -count=1 -run '^$' -fuzz '^FuzzPrefixSpace$' -fuzztime 60s . 2>&1 | tail -2
go vet . && gofmt -l .
```
Expected: `ok`; fuzz `PASS` / `ok`; vet silent; gofmt lists nothing.

- [ ] **Step 5: Update the API golden and check isolation**

```bash
cd /Users/roman/DEV/rpsl
RPSL_API_UPDATE=1 go run ./internal/apisurface -check
git diff api/
go run ./internal/apisurface -check; echo "apisurface=$?"
cd types && go list -deps ./... | grep rkolesnichenko
```
Expected: the only `api/` change is the line `func (PrefixSpace) SubsetOfUnion(ts ...PrefixSpace) bool` in `api/types.txt`; `apisurface=0`; the grep prints only `github.com/rkolesnichenko/rpsl/types`.

- [ ] **Step 6: Commit**

```bash
cd /Users/roman/DEV/rpsl
git add types/prefixspace_ops.go types/prefixspace_subset_test.go types/prefixspace_model_test.go api/types.txt
git commit -m "types: Subset stops early and allocates nothing; SubsetOfUnion"
```

---

### Task 2: `consist`: the cover keeps large spaces apart

**Files:**
- Modify: `resolve/consist/lint.go` (`cover`, `sigCover`, `shadowed`: lines ~502-554)
- Modify: `resolve/consist/lint_test.go` (new tests and helper)
- Modify: `resolve/consist/bench_test.go` (new benchmarks)

**Interfaces:**
- Consumes: `func (s types.PrefixSpace) SubsetOfUnion(ts ...types.PrefixSpace) bool` (Task 1).
- Produces: nothing exported. Private: `coverLarge`, `coverKeep`, `rangesAtLeast(types.PrefixSpace, int) bool`, `sigCover.folded`, `sigCover.large`, `(*sigCover).take(types.PrefixSpace)`, `(*sigCover).covers(types.PrefixSpace) bool`.

- [ ] **Step 1: Write the benchmarks and their helper**

Append to `resolve/consist/lint_test.go` (add `"net/netip"` to its imports):

```go
// scattered returns n exact /24s, for i = start..start+n-1, spread over the
// IPv4 space by a multiplicative hash so that neighbours never merge into
// one range.
func scattered(start, n int) []types.PrefixRange {
	rs := make([]types.PrefixRange, 0, n)
	for i := start; i < start+n; i++ {
		a := uint32(i) * 2654435761 &^ 0xff
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), 0}), 24)
		r, _ := types.NewPrefixRange(p, 24, 24)
		rs = append(rs, r)
	}
	return rs
}
```

Append to `resolve/consist/bench_test.go`:

```go
// benchCover runs lint/shadowed's cover over one session's clauses, as
// linter.policy does: ask about each clause, then add it.
func benchCover(b *testing.B, clauses []types.PrefixSpace) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cov cover
		for _, s := range clauses {
			cs := []conj{{space: s}}
			cov.shadowed(cs)
			cov.add(cs)
		}
	}
}

// BenchmarkShadowedLarge is one of RIPE's AS47147's IPv6 import sessions in
// shape: six large, heavily overlapping spaces (its IXP route-server sets)
// between small ones.
func BenchmarkShadowedLarge(b *testing.B) {
	var cl []types.PrefixSpace
	for i := 0; i < 6; i++ {
		cl = append(cl, types.SpaceOf(scattered(i*5000, 40_000)...), types.SpaceOf(scattered(1_000_000+i, 1)...))
	}
	benchCover(b, cl)
}

// BenchmarkShadowedManySmall is a long policy of small clauses, the shape
// v0.27.2 made linear: it must stay so.
func BenchmarkShadowedManySmall(b *testing.B) {
	cl := make([]types.PrefixSpace, 20_000)
	for i := range cl {
		cl[i] = types.SpaceOf(scattered(i, 1)...)
	}
	benchCover(b, cl)
}
```

- [ ] **Step 2: Measure before**

```bash
mkdir -p /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover
cd /Users/roman/DEV/rpsl/resolve/consist
GOMAXPROCS=4 go test -run '^$' -bench 'BenchmarkShadowed' -benchmem -count 3 . > /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/bench-before.txt 2>&1; echo "bench=$?"
grep Benchmark /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/bench-before.txt
```
Expected: `bench=0`; three lines for each benchmark.

- [ ] **Step 3: Write the failing tests**

Append to `resolve/consist/lint_test.go`:

```go
// A signature's cover keeps its first coverKeep large spaces apart and
// folds later large ones, and every small one, into one union; verdicts
// stay exact either way.
func TestCoverKeepsLargeApart(t *testing.T) {
	large := func(i int) types.PrefixSpace { return types.SpaceOf(scattered(i*2000, coverLarge+100)...) }
	small := func(i int) types.PrefixSpace { return types.SpaceOf(scattered(1_000_000+i, 1)...) }
	if !rangesAtLeast(large(0), coverLarge) || rangesAtLeast(small(0), 2) {
		t.Fatal("fixture: large(i) must hold at least coverLarge ranges, small(i) one")
	}
	var cov cover
	for i := 0; i < coverKeep+4; i++ {
		cs := []conj{{space: large(i)}, {space: small(i)}}
		if cov.shadowed(cs) {
			t.Fatalf("clause %d: shadowed, want not (each brings new ranges)", i)
		}
		cov.add(cs)
	}
	if !cov.shadowed([]conj{{space: large(coverKeep + 2)}}) || !cov.shadowed([]conj{{space: large(3).Union(small(7))}}) {
		t.Fatal("an earlier large space is not covered")
	}
	if cov.shadowed([]conj{{space: large(coverKeep + 4)}}) {
		t.Fatal("a new large space is covered")
	}
	sc := cov.bySig[""]
	if len(sc.large) != coverKeep {
		t.Fatalf("%d large spaces kept apart, want %d", len(sc.large), coverKeep)
	}
	if !large(coverKeep).Subset(sc.folded) || !small(0).Subset(sc.folded) || large(0).Subset(sc.folded) {
		t.Fatal("folded holds the wrong spaces: want large ones past coverKeep and every small one, not the first large")
	}
}

// cover answers as shadowedNaive does over random sequences mixing large
// spaces (over coverLarge ranges, overlapping), parts of earlier large ones
// and small ones, under random signatures over two tests.
func TestCoverMatchesNaiveLarge(t *testing.T) {
	tests := []string{"<^AS1>", "community(65000:1)"}
	shadows, not, kept := 0, 0, 0
	for seed := uint64(0); seed < 20; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x1a))
		var cov cover
		var earlier []conj
		var bigs [][]types.PrefixRange
		for range 24 {
			var sig []string
			for _, x := range tests {
				if r.IntN(3) == 0 {
					sig = append(sig, x)
				}
			}
			var rs []types.PrefixRange
			switch k := r.IntN(5); {
			case k < 2: // a new large space
				rs = scattered(r.IntN(8)*700, coverLarge+r.IntN(400))
				bigs = append(bigs, rs)
			case k == 2 && len(bigs) > 0: // part of an earlier large one
				b := bigs[r.IntN(len(bigs))]
				rs = b[:len(b)/2+r.IntN(len(b)/2)]
			default:
				rs = scattered(r.IntN(6000), 1+r.IntN(3))
			}
			cs := []conj{{sig: sig, space: types.SpaceOf(rs...)}}
			want := shadowedNaive(cs, earlier)
			if got := cov.shadowed(cs); got != want {
				t.Fatalf("seed %d after %d conjuncts: cover %v, naive %v", seed, len(earlier), got, want)
			}
			if want {
				shadows++
			} else {
				not++
			}
			for _, sc := range cov.bySig {
				if len(sc.large) > 0 {
					kept++
				}
			}
			cov.add(cs)
			earlier = append(earlier, cs...)
		}
	}
	if shadows == 0 || not == 0 || kept == 0 {
		t.Fatalf("shadowed %d, not %d, covers holding a large space %d: the test draws too few of one", shadows, not, kept)
	}
	t.Logf("shadowed %d, not %d, covers holding a large space %d", shadows, not, kept)
}
```

- [ ] **Step 4: Run them to verify they fail**

```bash
cd /Users/roman/DEV/rpsl/resolve/consist && go test -count=1 -run 'TestCover' . 2>&1 | tail -6
```
Expected: build failure: `undefined: coverLarge`, `undefined: rangesAtLeast`, `undefined: coverKeep`, `sc.large undefined`, `sc.folded undefined`.

- [ ] **Step 5: Implement**

In `resolve/consist/lint.go`, replace from `// cover is the conjuncts of a policy's earlier clauses` through the end of `func (c *cover) shadowed` with:

```go
// cover is the conjuncts of a policy's earlier clauses, for lint/shadowed.
// Per signature asked about, it keeps the earlier conjuncts whose tests are
// a subset of it, brought up to date when next asked, so a policy of n
// clauses takes each conjunct into each signature's cover once rather than
// rebuilding every cover for every clause (quadratic: RIPE's AS47147 spent
// 122 s of a 200 s lint there). A clause is then tested against the cover
// without building its union: building it cost AS47147 most of the rest
// (its IXP route-server sets, 41-46k ranges each, in most of its sessions).
type cover struct {
	earlier []conj
	bySig   map[string]*sigCover
}

// The cover's bounds, from AS47147's sessions: a union with a small space
// is cheap (shared subtrees), with a large overlapping one costly, and a
// test walks every space kept apart, so only the large ones are, and at
// most coverKeep of them (past that they fold, as small ones do).
const (
	coverLarge = 1024 // ranges: a space with at least this many is large
	coverKeep  = 16
)

// sigCover is earlier[:n]'s conjuncts whose tests are a subset of sig:
// the first coverKeep large spaces in large, the rest folded into one
// union.
type sigCover struct {
	sig    []string
	folded types.PrefixSpace
	large  []types.PrefixSpace
	n      int
}

// take adds an earlier conjunct's space.
func (sc *sigCover) take(s types.PrefixSpace) {
	if len(sc.large) < coverKeep && rangesAtLeast(s, coverLarge) {
		sc.large = append(sc.large, s)
		return
	}
	sc.folded = sc.folded.Union(s)
}

// covers reports whether every prefix in s is in the cover.
func (sc *sigCover) covers(s types.PrefixSpace) bool {
	if len(sc.large) == 0 {
		return s.Subset(sc.folded)
	}
	ts := make([]types.PrefixSpace, 0, len(sc.large)+1)
	return s.SubsetOfUnion(append(append(ts, sc.folded), sc.large...)...)
}

// rangesAtLeast reports whether s holds at least n ranges, counting no
// further.
func rangesAtLeast(s types.PrefixSpace, n int) bool {
	c := 0
	for range s.Ranges() {
		if c++; c >= n {
			return true
		}
	}
	return false
}

// shadowed reports whether every route cs accepts is accepted by the earlier
// conjuncts: per signature T of cs, its space lies in the union of the
// earlier conjuncts whose tests are a subset of T (a route passing T passes
// them).
func (c *cover) shadowed(cs []conj) bool {
	bySig := map[string][]conj{}
	for _, cj := range cs {
		k := strings.Join(cj.sig, "\x00")
		bySig[k] = append(bySig[k], cj)
	}
	for k, g := range bySig {
		sc := c.bySig[k]
		if sc == nil {
			if c.bySig == nil {
				c.bySig = map[string]*sigCover{}
			}
			sc = &sigCover{sig: g[0].sig}
			c.bySig[k] = sc
		}
		for _, e := range c.earlier[sc.n:] {
			if subset(e.sig, sc.sig) {
				sc.take(e.space)
			}
		}
		sc.n = len(c.earlier)
		if !sc.covers(union(g)) {
			return false
		}
	}
	return true
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/roman/DEV/rpsl/resolve/consist
go test -count=1 -v -run 'TestCover' . 2>&1 | grep -E '^(---|ok|FAIL)|shadowed [0-9]'
go test -count=1 -race . ../peval 2>&1 | tail -2
go vet . && gofmt -l .
cd .. && go list -deps . ./consist | grep -x net; echo "net-grep=$? (1 = absent)"
```
Expected: `TestCoverMatchesNaive`, `TestCoverKeepsLargeApart`, `TestCoverMatchesNaiveLarge` PASS (record the logged counts in the ledger); `-race` `ok` for both; vet and gofmt silent; `net-grep=1`.

- [ ] **Step 7: Measure after**

```bash
cd /Users/roman/DEV/rpsl/resolve/consist
GOMAXPROCS=4 go test -run '^$' -bench 'BenchmarkShadowed' -benchmem -count 3 . > /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/bench-after.txt 2>&1; echo "bench=$?"
grep Benchmark /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/bench-after.txt
```
Expected: `bench=0`; `BenchmarkShadowedLarge` far below its before figure (the prototype's 12-large micro-test went from 167 ms to 0.16 ms); `BenchmarkShadowedManySmall` within 25% of before (the prototype measured 51 → 62 ms on 20,000 small). If ManySmall is more than 25% slower, stop and report both figures rather than tuning.

- [ ] **Step 8: Commit**

```bash
cd /Users/roman/DEV/rpsl
git add resolve/consist/lint.go resolve/consist/lint_test.go resolve/consist/bench_test.go
git commit -m "consist: lint/shadowed tests a clause without building the cover's union"
```

---

### Task 3: Real-data verification

Runs one at a time under memguard; about 2 hours (two full sweeps of ~35 min). Logs and outputs in `.superpowers/sdd/shadowed-cover/` (git-ignored).

**Files:**
- Create (untracked): `.superpowers/sdd/shadowed-cover/verify.sh`, `.superpowers/sdd/shadowed-cover/compare.sh`
- Uses (untracked): the probe `.superpowers/sdd/call-memo/zz_probe31117_test.go` (lints one aut-num cold and warm; `PROBE_WITH` lints others beside it)

**Interfaces:**
- Consumes: branch head after Task 2; tag `v0.28.0`; `.superpowers/sdd/tools/memguard.sh`; baseline counts `.superpowers/sdd/sweep-profile/run2.log.counts`.
- Produces: `summary.log` with every figure Task 4 writes into docs.

- [ ] **Step 1: Build both rpslcheck binaries and both probe binaries**

```bash
R=/Users/roman/DEV/rpsl; V=$R/.superpowers/sdd/shadowed-cover; P=$R/.superpowers/sdd/call-memo/zz_probe31117_test.go
git -C $R worktree add $V/wt-v0.28.0 v0.28.0
(cd $V/wt-v0.28.0/resolve && go build -o $V/rpslcheck-v0.28.0 ./cmd/rpslcheck); echo "old=$?"
cp $P $V/wt-v0.28.0/resolve/consist/ && (cd $V/wt-v0.28.0/resolve/consist && go test -c -o $V/probe-v0.28.0.test .); echo "oldprobe=$?"
git -C $R worktree remove --force $V/wt-v0.28.0
(cd $R/resolve && go build -o $V/rpslcheck-branch ./cmd/rpslcheck); echo "new=$?"
cp $P $R/resolve/consist/ && (cd $R/resolve/consist && go test -c -o $V/probe-branch.test .); echo "newprobe=$?"; rm $R/resolve/consist/zz_probe31117_test.go
git -C $R status --short
```
Expected: `old=0 oldprobe=0 new=0 newprobe=0`; `git status` clean.

- [ ] **Step 2: Write `verify.sh`**

```zsh
#!/bin/zsh
# shadowed-cover verification, one heavy run at a time under memguard.
R=/Users/roman/DEV/rpsl
V=$R/.superpowers/sdd/shadowed-cover
G=$R/.superpowers/sdd/tools/memguard.sh
SUM=$V/summary.log
: > $SUM
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
	local name=$1 cap=$2 tmo=$3 rc try
	shift 3
	for try in 1 2 3 4 5 6; do
		$G $cap $tmo /usr/bin/time -l "$@" > $V/$name.out 2> $V/$name.err
		rc=$?
		if [[ $rc == 3 ]] && grep -q 'NOT STARTED' $V/$name.out $V/$name.err; then
			echo "$name not started (try $try)" >> $SUM
			sleep 300
			continue
		fi
		break
	done
	echo "$name exit=$rc | $(grep -h -E 'memguard: peak|SUCCESS|FAILURE|MEMLIMIT|PRESSURE|SWAP|LOWMEM|TIMEOUT| real |maximum resident' $V/$name.out $V/$name.err | sed 's/^ *//' | tr '\n' ' ')" >> $SUM
}

# 1. The probe: four lints alone on each build, then AS47147 beside the other three.
cd $V
for b in v0.28.0 branch; do
	for as in AS47147 AS31117 AS202827 AS1101; do
		run probe-$b-$as 6 1800 env RPSL_REALDATA=$R/.data PROBE_OUT=$V/probe-$b-$as.log PROBE_AS=$as $V/probe-$b.test -test.count=1 -test.timeout 25m -test.run TestZZProbeOne
		grep -h -E '^(cold|warm) peers' $V/probe-$b-$as.log | sed "s/^/$b $as /" >> $SUM
	done
	run probe-$b-conc 7 1800 env RPSL_REALDATA=$R/.data PROBE_OUT=$V/probe-$b-conc.log PROBE_AS=AS47147 PROBE_WITH=AS1101,AS31117,AS202827 $V/probe-$b.test -test.count=1 -test.timeout 25m -test.run TestZZProbeOne
	grep -h -E '^conc' $V/probe-$b-conc.log | sed "s/^/$b /" >> $SUM
done

# 2. The consist sample against its baseline counts.
cd $R/resolve
run consist-sample 6 3000 env GOMEMLIMIT=4GiB RPSL_REALDATA=$R/.data RPSL_CONSIST_SAMPLE=2000 go test -count=1 -v -timeout 50m -run TestRealDataConsist ./consist
grep -E '^ +[a-z].* +[0-9]+$' $V/consist-sample.out | sed -E 's/^ +//; s/ +/ /g' | sort > $V/consist-sample.counts
if cmp -s $V/consist-sample.counts <(sed -E 's/^ +//; s/ +/ /g' $R/.superpowers/sdd/sweep-profile/run2.log.counts | sort); then
	echo "consist-sample counts: identical to baseline ($(wc -l < $V/consist-sample.counts) lines)" >> $SUM
else
	echo "consist-sample counts: DIFFER from baseline" >> $SUM
fi

# 3. Full RIPE sweeps, v0.28.0 then the branch.
cd $V
run full-v0.28.0 8 7200 env GOMEMLIMIT=5GiB $V/rpslcheck-v0.28.0 -sweep -c 4 -json $dumps
run full-branch 8 7200 env GOMEMLIMIT=5GiB $V/rpslcheck-branch -sweep -c 4 -json $dumps
zsh $V/compare.sh

# 4. check.sh with fuzz.
cd $R
run check-fuzz 7 3600 env FUZZTIME=15s scripts/check.sh
tail -3 $V/check-fuzz.out >> $SUM
echo "done" >> $SUM
```

`rpslcheck -sweep` exits 1 when it reports a Warning: `exit=1` with `FAILURE (exit 1)` in memguard's line is the expected outcome for the full sweeps. Any other memguard verdict (MEMLIMIT, PRESSURE, SWAP, LOWMEM, TIMEOUT) is a failure.

- [ ] **Step 3: Write `compare.sh`**

```zsh
#!/bin/zsh
# Compare the two full sweeps: every record except timeouts and totals, the
# issue records of an aut-num that timed out in either run, then the totals.
V=/Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover
A=$V/full-v0.28.0.out
B=$V/full-branch.out
OUT=$V/summary.log
export LC_ALL=C
ases=($(grep -h '^{"type":"timeout"' $A $B | sed -E 's/.*"as":"(AS[0-9]+)".*/\1/' | sort -u))
echo "timed out in either run: ${ases:-none}" >> $OUT
echo "v0.28.0 timeouts: $(grep -c '^{"type":"timeout"' $A)  branch timeouts: $(grep -c '^{"type":"timeout"' $B)" >> $OUT
pat='^\{"type":"timeout"|^\{"type":"totals"|^memguard|^SUCCESS|^FAILURE|^MEM'
for a in $ases; do pat="$pat|^\\{\"type\":\"issue\",\"as\":\"$a\""; done
grep -v -E "$pat" $A > $V/cmp-a.txt
grep -v -E "$pat" $B > $V/cmp-b.txt
echo "lines: v0.28.0 $(wc -l < $V/cmp-a.txt) branch $(wc -l < $V/cmp-b.txt)" >> $OUT
if cmp -s $V/cmp-a.txt $V/cmp-b.txt; then
	echo "RESULT: identical outside timed-out aut-nums" >> $OUT
else
	echo "RESULT: DIFFER" >> $OUT
	diff $V/cmp-a.txt $V/cmp-b.txt | head -40 >> $OUT
fi
if cmp -s <(grep -h '^{"type":"totals"' $A) <(grep -h '^{"type":"totals"' $B); then
	echo "TOTALS: identical" >> $OUT
else
	echo "TOTALS: DIFFER" >> $OUT
	echo "totals v0.28.0: $(grep -h '^{"type":"totals"' $A | cut -c1-900)" >> $OUT
	echo "totals branch:  $(grep -h '^{"type":"totals"' $B | cut -c1-900)" >> $OUT
fi
rm -f $V/cmp-a.txt $V/cmp-b.txt
```

- [ ] **Step 4: Run it in the background and wait for its notification**

```bash
chmod +x /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/*.sh
zsh /Users/roman/DEV/rpsl/.superpowers/sdd/shadowed-cover/verify.sh
```
Run with the Bash tool's `run_in_background: true`. Nothing else heavy runs meanwhile.

- [ ] **Step 5: Read `summary.log` and apply the gates**

Pass requires all of:
- Each probe pair (`v0.28.0 ASx cold` vs `branch ASx cold`): same `issues=` and `hash=`; the branch's AS47147 cold lint well below v0.28.0's (prototype: 42.5 → 14.1 s); none of the other three slower than v0.28.0 by more than 10%.
- `conc`: the branch's AS47147 well below 60 s and below v0.28.0's run in the same file; no `context deadline exceeded`.
- `consist-sample counts: identical to baseline`.
- `RESULT: identical outside timed-out aut-nums`, `TOTALS: identical` (expected: no timeouts in either run; if v0.28.0 has timeouts the branch has none of its own beyond them and their issues are reported).
- **Memory gate:** `full-branch`'s `maximum resident set size` (time(1), bytes) ≤ `full-v0.28.0`'s + 1,073,741,824. If over: STOP, report both figures, do not continue to Task 4.
- `check-fuzz`: exit 0, memguard `SUCCESS`, `check: ok`.

If any gate fails, stop and report; do not adjust the code to the figures.

---

### Task 4: Docs and CHANGELOG, from Task 3's figures

**Files:**
- Modify: `docs/rpslcheck.md` (the paragraph at ~198-211)
- Modify: `docs/rpsl-go-design.md` (the `sigCover` sentence at ~1102-1103)
- Modify: `CHANGELOG.md` (`## [Unreleased]`)

Every number below comes from `.superpowers/sdd/shadowed-cover/summary.log` or `bench-*.txt` (max RSS from time(1)'s `maximum resident set size`, in MiB); write the measured values over each `<…>`, never estimates.

- [ ] **Step 1: `docs/rpslcheck.md`**

Replace the sentence

```
AS47147, whose large IXP clauses make
`lint/shadowed` costly, took 50.3 s beside the other three.
```

(it is wrapped across two lines: "AS47147, whose large IXP clauses make" ending one line) with

```
Since v0.29.0 `lint/shadowed` tests a clause
against the earlier ones without building their union: AS47147, whose IPv6
sessions hold several IXP route-server sets of 41-46k ranges each, lints in
<branch AS47147 cold> s alone (v0.28.0: <v0.28.0 AS47147 cold> s) and
<branch conc> s beside the other three (v0.28.0: <v0.28.0 conc> s).
```

and replace "The sweep took 2,008 s with 6,773 MB max RSS (v0.27.2, same dumps and machine: 2,142 s, 5,962 MB)." with "At v0.29.0 the sweep took <wall> s with <rss> MB max RSS (v0.28.0, same dumps and machine: <wall0> s, <rss0> MB)." Keep the paragraph's ~80-column wrapping.

- [ ] **Step 2: `docs/rpsl-go-design.md`**

After "instead of rebuilding it per clause, which was quadratic in the clauses." add: "Since v0.29.0 a cover keeps up to 16 large spaces (at least 1,024 ranges) apart from the union of the rest, and a clause is tested against them with `PrefixSpace.SubsetOfUnion`, never building a union of two large spaces: AS47147's lint went from <v0.28.0 AS47147 cold> s to <branch AS47147 cold> s." Keep the ~80-column wrapping.

- [ ] **Step 3: CHANGELOG `[Unreleased]`**

```markdown
### Added

- `types`: `PrefixSpace.SubsetOfUnion(ts...)` reports whether a space lies
  in the union of others without building the union.

### Changed

- `types`: `PrefixSpace.Subset` stops at the first prefix the other space
  lacks and allocates nothing, instead of building the whole difference.
- `resolve/consist`: `lint/shadowed` keeps up to 16 large earlier spaces
  (at least 1,024 ranges) apart from the union of the rest and tests a clause
  with `SubsetOfUnion`, so it never unions two large overlapping spaces.
  RIPE's AS47147, whose IPv6 import sessions hold several IXP route-server
  sets of 41-46k ranges each, lints in <branch AS47147 cold> s alone where
  v0.28.0 took <v0.28.0 AS47147 cold> s, and <branch conc> s beside three
  other IXP lints (v0.28.0: <v0.28.0 conc> s); AS31117 <a> → <b> s, AS202827
  <a> → <b> s, AS1101 <a> → <b> s. Full RIPE sweep (`rpslcheck -sweep -c 4
  -json`, GOMAXPROCS 4, `GOMEMLIMIT=5GiB`), against v0.28.0 on the same
  dumps: <wall0> s → <wall> s, max RSS <rss0> → <rss> MB, output identical.
  No result changes.
```

- [ ] **Step 4: Check and commit**

```bash
cd /Users/roman/DEV/rpsl && git diff --stat
git diff -U0 docs/rpslcheck.md docs/rpsl-go-design.md CHANGELOG.md | grep '^+' | grep -E '<[a-z0-9 .]+>'; echo "unfilled=$? (1 = none)"
git add docs/rpslcheck.md docs/rpsl-go-design.md CHANGELOG.md
git commit -m "docs: shadowed-cover — AS47147's lint, new sweep figures"
```
Expected: the diff touches only these three files; `unfilled=1`.

---

### Task 5: Whole-branch review

- [ ] **Step 1: Independent reviewer on the full diff**

Dispatch a reviewer agent (most capable model) on `git diff main...shadowed-cover` with the spec, this plan, the ledger's rulings and `summary.log`. Ask specifically for: exactness of `subsetNode`/`subsetUnion` against `merge(opMinus)` (inherited masks, the same-node shortcut, leaves, families), the work list's windows (no aliasing between a node's two children), `sigCover.take`'s order of checks, docs figures matching `summary.log`, and duplicated or misplaced code.

- [ ] **Step 2: Fix Critical and Important findings**

Each fix: a test first where it is behaviour, then the change, `go test -race .` in `types/` and `go test -race ./consist` in `resolve/`, commit. If a fix touches `prefixspace_ops.go` or `lint.go`'s cover, re-run `scripts/check.sh` (without fuzz, under memguard 6) before reporting.

- [ ] **Step 3: Report to the user and stop**

Report the commits, `summary.log`'s gates, check.sh's result and the reviewer's findings with their dispositions. Pushing, the PR and the v0.29.0 release are separate requests.
