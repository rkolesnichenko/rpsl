# Sweep-wide memo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `consist.Checker` share decoded aut-nums, normalized filters and their prefix spaces across calls, so `rpslcheck` stops redoing identical work per pair, without changing any result.

**Architecture:** `resolve.FilterMemo` caches `NormalizeFilter` answers keyed by filter text and AFI, never storing an answer that read `Expander.Peer` (the normalizer records every read through one accessor). Each `Conjunct` built by `NormalizeFilter` carries a lazily computed, shared `PrefixSpace`. `consist.Memo` bundles a bounded LRU of decoded aut-nums/inet-rtrs with a `FilterMemo`; `Checker.Memo` turns it on and `rpslcheck` sets it.

**Tech Stack:** Go 1.23 (module floor), `container/list`, `sync`; the repo's model tests, fuzz targets and real-data tests.

**Spec:** `docs/superpowers/specs/2026-10-13-sweep-memo-design.md` (read it first; this plan argues from it).

## Global Constraints

- Go floor is 1.23: no `testing.B.Loop`, no APIs newer than 1.23. `for range n` (1.22) is fine.
- The memo is result-neutral: every answer with it equals the answer without it. Never weaken a test to make a difference pass; a difference is a bug.
- Never store an answer whose normalization read `Expander.Peer` (including `Peer == 0`).
- Never store a context error or a `Source` failure; store successes and only `*SetTooLargeError`, `*NotEnumerableError`, `*AnySetError` (and, for objects, `resolve.ErrNotFound`).
- `FilterMemo` is ignored when `Expander.Exclude` is non-empty.
- Engine purity: `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki` must not list `net`.
- API conventions (CLAUDE.md, C1–C3) hold; the `api/` golden is rewritten with `RPSL_API_UPDATE=1 go run ./internal/apisurface -check` (run from the repo root) and the diff reviewed.
- Heavy runs (check.sh, real-data tests, full sweeps) run one at a time under `.superpowers/sdd/tools/memguard.sh` with `GOMAXPROCS=4`, `MEMGUARD_NORMAL_PRIORITY=1`, a cap of 6–7 GB; never two at once.
- Commit after each task with a message in the repo's style (`area: what changed`).

## Review Focus

1. A filter whose only `PeerAS` is two filter-sets deep, normalized first for one peer and then another, must give each peer its own answer — Task 1 (flag) and Task 3 (`TestFilterMemoNestedPeer`).
2. A check that runs out of its time budget mid-normalization must not leave its error for the next check — Task 3 (`TestFilterMemoContextNotStored`) and Task 4 (`TestMemoCheckAfterTimeout`).
3. The same filter text under two address families must not share an answer — Task 3 (`TestFilterMemoKeyedByAFI`).
4. An `Expander` with `Exclude` set must not read or fill the memo — Task 3 (`TestFilterMemoIgnoredWithExclude`).
5. `Lint`, which evaluates sentinel sessions toward AS4294967295/AS65535 to detect peer-dependent clauses, must report the same issues with the memo — Task 4 (`TestModelConsistMemo` lints both ASes).

---

### Task 1: Record every read of `Expander.Peer` during normalization

**Files:**
- Modify: `resolve/expand_more.go:192-219` (filterEval), `:391-403`, `:644-647`
- Modify: `resolve/normalize.go:104-124` (normalize), `:449-459` (path)
- Modify: `resolve/export_test.go:12-17` (NormalizePeak)
- Create: `resolve/peerread_test.go`

**Interfaces:**
- Produces: `func (ev *filterEval) peer() types.ASN` (records `ev.usedPeer = true`); `func (e *Expander) normalize(ctx context.Context, f policy.Filter) (nf NormalFilter, peak int, usedPeer bool, err error)`. Task 3 consumes both.

- [ ] **Step 1: Write the failing tests**

Create `resolve/peerread_test.go`:

```go
package resolve

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// normalize reports whether the answer read Expander.Peer, at any depth:
// PeerAS, a set template in a filter or an AS expression, a regexp naming
// the peer, inside filter-sets too, and with no peer bound as well.
func TestNormalizeReportsPeerRead(t *testing.T) {
	src := corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"filter-set: FLTR-INNER\nfilter: PeerAS OR AS-A\nsource: TEST\n",
		"filter-set: FLTR-OUTER\nfilter: FLTR-INNER AND {10.0.0.0/8^+}\nsource: TEST\n",
		"filter-set: FLTR-PLAIN\nfilter: AS-A\nsource: TEST\n",
		"as-set: AS65001:AS-T:AS65002\nmembers: AS65001\nsource: TEST\n",
	)
	for _, c := range []struct {
		filter string
		peer   bool
	}{
		{"ANY", false},
		{"AS-A", false},
		{"{10.0.0.0/8^+}", false},
		{"FLTR-PLAIN", false},
		{"<^AS65001>", false},
		{"PeerAS", true},
		{"AS65001:AS-T:PeerAS", true},
		{"<^PeerAS>", true},
		{"FLTR-INNER", true},
		{"FLTR-OUTER", true},
		{"AS-A OR NOT PeerAS", true},
	} {
		f, _ := policy.ParseFilter(c.filter)
		for _, peer := range []types.ASN{0, 65002} {
			e := &Expander{Src: src, Peer: peer}
			_, _, used, _ := e.normalize(context.Background(), f)
			if used != c.peer {
				t.Errorf("%s (peer %d): read the peer %v, want %v", c.filter, peer, used, c.peer)
			}
		}
	}
}

// Every read of Expander.Peer in the evaluator goes through filterEval.peer,
// which records it; a direct read would let FilterMemo share an answer that
// depends on the peer.
func TestPeerReadsGoThroughAccessor(t *testing.T) {
	direct := regexp.MustCompile(`\bev\.e\.Peer\b|\bn\.ev\.e\.Peer\b|\bn\.noEx\.e\.Peer\b`)
	for _, name := range []string{"expand_more.go", "normalize.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if direct.MatchString(line) && !strings.Contains(line, "ev.usedPeer = true") {
				t.Errorf("%s:%d reads Expander.Peer directly: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd resolve && go test -run 'TestNormalizeReportsPeerRead|TestPeerReadsGoThroughAccessor' .`
Expected: build failure — `e.normalize` returns 3 values, not 4.

- [ ] **Step 3: Implement**

In `resolve/expand_more.go`, add a field to `filterEval` (after `anyAll`):

```go
	usedPeer bool // Expander.Peer was read (peer): the answer depends on it
```

Add after `newFilterEval`:

```go
// peer returns Expander.Peer and records that the answer depends on it —
// bound or not (an unbound peer's error depends on it too). Every read of
// the peer during evaluation goes through here, so FilterMemo never shares
// an answer that read it (TestPeerReadsGoThroughAccessor).
func (ev *filterEval) peer() types.ASN { ev.usedPeer = true; return ev.e.Peer }
```

Replace the three read sites:

```go
	case policy.FilterPeerAS:
		peer := ev.peer()
		if peer == 0 {
			return nil, unboundPeer("PeerAS")
		}
		if ev.skipAS(peer) {
			return rangeSetOf{}, nil
		}
		return ev.routesOf(map[types.ASN]bool{peer: true}, x.Op)
	case policy.FilterSetTemplate:
		peer := ev.peer()
		if peer == 0 {
			return nil, unboundPeer(x.Template.String())
		}
		return ev.setRef(x.Template.Instantiate(peer), x.Op, depth)
```

```go
	case policy.ASSetTemplate:
		peer := ev.peer()
		if peer == 0 {
			return nil, unboundPeer(x.Template.String())
		}
		return ev.asExpr(policy.ASSetRef{Name: x.Template.Instantiate(peer)}, depth)
```

In `resolve/normalize.go` `path`:

```go
	re := x.Regexp
	if re.UsesPeer() {
		peer := n.ev.peer()
		if peer == 0 {
			return PathMatch{}, unboundPeer(filterText(x))
		}
		re = re.Bind(peer)
	}
```

Change `normalize` to return the flag (both evaluators can read it: `noEx` evaluates negated literals):

```go
// normalize is NormalizeFilter, also returning the largest disjunction built
// and whether the answer read Expander.Peer.
func (e *Expander) normalize(ctx context.Context, f policy.Filter) (NormalFilter, int, bool, error) {
	n := &normalizer{ev: newFilterEval(e, ctx), inline: map[string]bool{}, memo: map[string][]nconj{}, height: map[string]int{}}
	// … unchanged lines through n.noEx.anyAll = true …
	cs, err := n.norm(f, false, 0)
	used := func() bool { return n.ev.usedPeer || n.noEx.usedPeer }
	if err != nil {
		return NormalFilter{}, n.peak, used(), err
	}
	nf, err := n.finish(cs)
	return nf, n.peak, used(), err
}
```

Update `NormalizeFilter`:

```go
	nf, _, _, err := e.normalize(ctx, f)
	return nf, err
```

and `resolve/export_test.go`'s `NormalizePeak`:

```go
func NormalizePeak(e *Expander, ctx context.Context, f policy.Filter) (NormalFilter, int, error) {
	nf, peak, _, err := e.normalize(ctx, f)
	return nf, peak, err
}
```

Then make the guard test's exception match the accessor line exactly: the only remaining direct read is `func (ev *filterEval) peer() types.ASN { ev.usedPeer = true; return ev.e.Peer }`, which contains `ev.usedPeer = true`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd resolve && gofmt -l . ; go vet . && go test -run 'TestNormalizeReportsPeerRead|TestPeerReadsGoThroughAccessor' . && grep -n '\.e\.Peer' expand_more.go normalize.go`
Expected: PASS; the grep shows only the `peer()` line.

- [ ] **Step 5: Run the package's tests**

Run: `cd resolve && go test -count=1 .`
Expected: `ok` (normalization behaviour unchanged).

- [ ] **Step 6: Commit**

```bash
git add resolve/expand_more.go resolve/normalize.go resolve/export_test.go resolve/peerread_test.go
git commit -m "resolve: record every read of Expander.Peer during normalization"
```

---

### Task 2: A `Conjunct`'s space, computed once and shared by its copies

**Files:**
- Modify: `resolve/normalize.go:28-46` (Conjunct, Space), `finish` (where `conj := Conjunct{…}` is built)
- Create: `resolve/conjspace_test.go`

**Interfaces:**
- Produces: unexported `Conjunct.space *spaceOnce`; `Conjunct.Space()` unchanged in signature and meaning. Task 3's memoized conjuncts and consist's `sideOf` rely on it.

- [ ] **Step 1: Write the failing test**

Create `resolve/conjspace_test.go`:

```go
package resolve

import (
	"context"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// A conjunct NormalizeFilter built computes its space once, and its copies
// share it; one built by hand still answers.
func TestConjunctSpaceShared(t *testing.T) {
	src := corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS65001\nsource: TEST\n",
	)
	f, _ := policy.ParseFilter("AS-A AND NOT {10.2.0.0/16}")
	nf, err := (&Expander{Src: src}).NormalizeFilter(context.Background(), f)
	if err != nil || len(nf.Conjuncts) != 1 {
		t.Fatalf("%v, %v", nf, err)
	}
	c := nf.Conjuncts[0]
	if c.space == nil {
		t.Fatal("NormalizeFilter left the conjunct without its space cache")
	}
	want := types.SpaceOf(c.Prefixes.List()...).Minus(types.SpaceOf(c.NotPrefixes.List()...))
	copy1 := c
	if got := copy1.Space(); !got.Equal(want) {
		t.Fatalf("Space %v, want %v", got, want)
	}
	if copy1.space != c.space {
		t.Fatal("a copy does not share the cache")
	}
	if got := c.Space(); !got.Equal(want) {
		t.Fatalf("Space again %v, want %v", got, want)
	}
	byHand := Conjunct{Prefixes: c.Prefixes, NotPrefixes: c.NotPrefixes}
	if got := byHand.Space(); !got.Equal(want) {
		t.Fatalf("hand-built Space %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd resolve && go test -run TestConjunctSpaceShared .`
Expected: build failure — `c.space undefined`.

- [ ] **Step 3: Implement**

In `resolve/normalize.go`, add to `Conjunct` after `any bool`:

```go
	space *spaceOnce // set by NormalizeFilter: Space computed once, shared by copies
```

Add the type and replace `Space`:

```go
// spaceOnce is a conjunct's space, computed on first use.
type spaceOnce struct {
	once sync.Once
	s    types.PrefixSpace
}

// Space returns the prefixes the conjunct's prefix tests accept: Prefixes
// less NotPrefixes. For a conjunct NormalizeFilter built it is computed
// once and shared by every copy (a memoized NormalFilter is handed to many
// callers); for one built by hand, on each call.
func (c Conjunct) Space() types.PrefixSpace {
	if c.space == nil {
		return c.computeSpace()
	}
	c.space.once.Do(func() { c.space.s = c.computeSpace() })
	return c.space.s
}

// computeSpace is Space without the cache. SpaceOf does not depend on the
// order of its ranges, so List's sort would be wasted.
func (c Conjunct) computeSpace() types.PrefixSpace {
	return types.SpaceOf(c.Prefixes.unsorted()...).Minus(types.SpaceOf(c.NotPrefixes.unsorted()...))
}
```

Keep the existing doc comment's first sentence if it differs; add `"sync"` to the imports. In `finish`, add the field where the conjunct is built:

```go
		conj := Conjunct{
			Prefixes:    toRangeSet(pos),
			NotPrefixes: toRangeSet(neg),
			Paths:       c.paths,
			Communities: c.comms,
			any:         covers(pos, all),
			space:       &spaceOnce{},
		}
```

- [ ] **Step 4: Run tests**

Run: `cd resolve && gofmt -l . ; go vet . && go test -count=1 -race -run 'TestConjunctSpaceShared|TestModelNormalize|TestModelConsist' . ./consist`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add resolve/normalize.go resolve/conjspace_test.go
git commit -m "resolve: a normalized conjunct computes its space once, shared by its copies"
```

---

### Task 3: `resolve.FilterMemo` and `Expander.Memo`

**Files:**
- Create: `resolve/filtermemo.go`, `resolve/filtermemo_test.go`
- Modify: `resolve/expander.go:42-63` (Expander: add `Memo`), `resolve/normalize.go` (`NormalizeFilter`)
- Modify: `resolve/filter_model_test.go` (add `TestModelFilterMemo`), `resolve/normalize_fuzz_test.go` (memo property)
- Modify: `api/resolve.txt` (regenerated)

**Interfaces:**
- Consumes: `normalize(...) (NormalFilter, int, bool, error)` from Task 1.
- Produces (Task 4 uses):

```go
type FilterMemo struct{ /* unexported */ }
func NewFilterMemo(maxRanges int) *FilterMemo
func (m *FilterMemo) Stats() FilterMemoStats
type FilterMemoStats struct {
	Hits, Misses  int
	PeerDependent int
	Entries, Held int
}
// Expander gains: Memo *FilterMemo
```

- [ ] **Step 1: Write the failing unit tests**

Create `resolve/filtermemo_test.go`:

```go
package resolve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

func memoCorpus(t *testing.T) *MemSource {
	return corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS65002\nsource: TEST\n",
		"route: 10.3.0.0/16\norigin: AS65003\nsource: TEST\n",
		"filter-set: FLTR-INNER\nfilter: PeerAS OR AS-A\nsource: TEST\n",
		"filter-set: FLTR-OUTER\nfilter: FLTR-INNER AND {10.0.0.0/8^+}\nsource: TEST\n",
	)
}

func mustFilter(t *testing.T, s string) policy.Filter {
	t.Helper()
	f, ds := policy.ParseFilter(s)
	for _, d := range ds {
		t.Fatalf("%s: %v", s, d)
	}
	return f
}

// sameNormal fails unless two answers are the same normal form, missing
// sets and error.
func sameNormal(t *testing.T, label string, got NormalFilter, gerr error, want NormalFilter, werr error) {
	t.Helper()
	if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() || fmt.Sprint(got.Missing()) != fmt.Sprint(want.Missing()) {
		t.Fatalf("%s: memo %q %v %v, plain %q %v %v", label, got, got.Missing(), gerr, want, want.Missing(), werr)
	}
}

func TestFilterMemoHit(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	first, err1 := e.NormalizeFilter(context.Background(), f)
	again, err2 := e.NormalizeFilter(context.Background(), f)
	sameNormal(t, "AS-A", again, err2, first, err1)
	if st := memo.Stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 || st.Held != 2 {
		t.Fatalf("stats %+v, want 1 hit, 1 miss, 1 entry holding 2", st)
	}
}

// Review focus 1: a PeerAS two filter-sets deep is never shared between peers.
func TestFilterMemoNestedPeer(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "FLTR-OUTER")
	for _, peer := range []types.ASN{65002, 65003, 65002, 0} {
		plain := &Expander{Src: src, Peer: peer}
		withMemo := &Expander{Src: src, Peer: peer, Memo: memo}
		want, werr := plain.NormalizeFilter(context.Background(), f)
		got, gerr := withMemo.NormalizeFilter(context.Background(), f)
		sameNormal(t, fmt.Sprintf("FLTR-OUTER peer %d", peer), got, gerr, want, werr)
	}
	if st := memo.Stats(); st.Hits != 0 || st.Entries != 0 || st.PeerDependent != 4 {
		t.Fatalf("stats %+v, want nothing stored and 4 peer-dependent answers", st)
	}
}

// Review focus 3: one text under two families is two answers.
func TestFilterMemoKeyedByAFI(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "AS-A")
	for _, afi := range []types.AFI{types.AFIv4, types.AFIv6, types.AFIv4} {
		plain := &Expander{Src: src, AFI: afi}
		withMemo := &Expander{Src: src, AFI: afi, Memo: memo}
		want, werr := plain.NormalizeFilter(context.Background(), f)
		got, gerr := withMemo.NormalizeFilter(context.Background(), f)
		sameNormal(t, fmt.Sprintf("AS-A %v", afi), got, gerr, want, werr)
	}
	if st := memo.Stats(); st.Entries != 2 || st.Hits != 1 {
		t.Fatalf("stats %+v, want 2 entries and 1 hit", st)
	}
}

// Review focus 4: an Expander with Exclude neither reads nor fills the memo.
func TestFilterMemoIgnoredWithExclude(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "AS-A")
	full := &Expander{Src: src, Memo: memo}
	if _, err := full.NormalizeFilter(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	ex := &Expander{Src: src, Memo: memo, Exclude: Exclusion{ASNs: []types.ASN{65001}}}
	want, werr := (&Expander{Src: src, Exclude: ex.Exclude}).NormalizeFilter(context.Background(), f)
	got, gerr := ex.NormalizeFilter(context.Background(), f)
	sameNormal(t, "AS-A excluding AS65001", got, gerr, want, werr)
	if st := memo.Stats(); st.Hits != 0 || st.Misses != 1 {
		t.Fatalf("stats %+v: the Exclude call touched the memo", st)
	}
}

// Review focus 2: a context error is never stored.
func TestFilterMemoContextNotStored(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.NormalizeFilter(ctx, f); err == nil {
		t.Fatal("a cancelled context normalized AS-A")
	}
	got, err := e.NormalizeFilter(context.Background(), f)
	if err != nil || got.String() != "{10.1.0.0/16}" {
		t.Fatalf("after a cancelled call: %q %v", got, err)
	}
}

// failingSource fails every GetSet while down.
type failingSource struct {
	Source
	mu   sync.Mutex
	down bool
}

func (s *failingSource) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, errors.New("registry down")
	}
	return s.Source.GetSet(ctx, ref)
}

func TestFilterMemoSourceFailureNotStored(t *testing.T) {
	src := &failingSource{Source: memoCorpus(t), down: true}
	memo := NewFilterMemo(1 << 10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	if _, err := e.NormalizeFilter(context.Background(), f); err == nil {
		t.Fatal("a failing Source normalized AS-A")
	}
	src.mu.Lock()
	src.down = false
	src.mu.Unlock()
	if got, err := e.NormalizeFilter(context.Background(), f); err != nil || got.String() != "{10.1.0.0/16}" {
		t.Fatalf("after the Source recovered: %q %v", got, err)
	}
}

// A deterministic error is stored: two regexps OR'd need two conjuncts,
// over MaxConjuncts 1 every time.
func TestFilterMemoStoresDeterministicError(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo, MaxConjuncts: 1}
	f := mustFilter(t, "<^AS65001> OR <^AS65002>")
	_, err1 := e.NormalizeFilter(context.Background(), f)
	_, err2 := e.NormalizeFilter(context.Background(), f)
	var tl *SetTooLargeError
	if !errors.As(err1, &tl) || fmt.Sprint(err1) != fmt.Sprint(err2) {
		t.Fatalf("%v, then %v; want the same *SetTooLargeError twice", err1, err2)
	}
	if st := memo.Stats(); st.Hits != 1 {
		t.Fatalf("stats %+v, want the second call answered from the memo", st)
	}
}

// Eviction keeps Held within the bound; an answer over a quarter of it is
// computed and not stored; answers stay equal throughout.
func TestFilterMemoBounded(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(12)
	plain := &Expander{Src: src}
	withMemo := &Expander{Src: src, Memo: memo}
	texts := []string{"{10.0.0.0/8}", "{10.1.0.0/16}", "{10.2.0.0/16}", "{10.3.0.0/16}", "{10.4.0.0/16}",
		"{10.5.0.0/16}", "{10.6.0.0/16}", "{10.7.0.0/16, 10.8.0.0/16, 10.9.0.0/16}"}
	for round := 0; round < 2; round++ {
		for _, s := range texts {
			f := mustFilter(t, s)
			want, werr := plain.NormalizeFilter(context.Background(), f)
			got, gerr := withMemo.NormalizeFilter(context.Background(), f)
			sameNormal(t, s, got, gerr, want, werr)
			if st := memo.Stats(); st.Held > 12 {
				t.Fatalf("%s: held %d ranges, over 12", s, st.Held)
			}
		}
	}
	if st := memo.Stats(); st.Entries == 0 || st.Entries > 6 {
		t.Fatalf("stats %+v, want between 1 and 6 entries of weight 2", st)
	}
}

func TestFilterMemoConcurrent(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	var fs []policy.Filter
	for _, s := range []string{"AS-A", "FLTR-OUTER", "PeerAS", "{10.0.0.0/8^+}", "AS-A OR AS65002"} {
		fs = append(fs, mustFilter(t, s)) // here: t.Fatalf may not run in another goroutine
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				f := fs[(g+i)%len(fs)]
				peer := types.ASN(65002 + i%2)
				want, werr := (&Expander{Src: src, Peer: peer}).NormalizeFilter(context.Background(), f)
				got, gerr := (&Expander{Src: src, Peer: peer, Memo: memo}).NormalizeFilter(context.Background(), f)
				if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() {
					t.Errorf("%v peer %d: memo %q %v, plain %q %v", f, peer, got, gerr, want, werr)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd resolve && go test -run 'TestFilterMemo' .`
Expected: build failure — `undefined: NewFilterMemo`, `unknown field Memo`.

- [ ] **Step 3: Implement `FilterMemo`**

Create `resolve/filtermemo.go`:

```go
package resolve

import (
	"container/list"
	"errors"
	"sync"

	"github.com/rkolesnichenko/rpsl/types"
)

// FilterMemo shares NormalizeFilter's answers between Expanders that differ
// only in AFI and Peer: the same Src, limits and Concurrency, and no
// Exclude (an Expander with Exclude set ignores it). An answer is keyed by
// the filter's text and AFI; one whose normalization read Peer — PeerAS, a
// set template, a regexp naming the peer, at any depth, inside filter-sets
// too, bound or not — is never stored, so a hit is always the answer
// NormalizeFilter would compute. Successes are stored, and the errors that
// follow from the filter and the registry alone (*SetTooLargeError,
// *NotEnumerableError, *AnySetError); a context error or a Source failure
// never is. It holds at most maxRanges prefix ranges in all (each answer
// weighs one plus its conjuncts' Prefixes and NotPrefixes), evicting the
// least recently used; an answer heavier than a quarter of that is not
// stored. A NormalFilter it returns is shared: the caller must not modify
// it. It never notices a change in the Source: build a new one for a new
// snapshot. Safe for concurrent use.
type FilterMemo struct {
	mu      sync.Mutex
	max     int
	held    int
	entries map[filterKey]*list.Element // of *filterAnswer
	lru     list.List                   // front: most recently used
	stats   FilterMemoStats
}

// FilterMemoStats is a FilterMemo's counters, for measurement and tests.
type FilterMemoStats struct {
	Hits, Misses  int // lookups answered from the memo / computed
	PeerDependent int // computed answers not stored because they read Peer
	Entries, Held int // answers stored; their weight in prefix ranges
}

type filterKey struct {
	text string
	afi  types.AFI
}

type filterAnswer struct {
	key    filterKey
	nf     NormalFilter
	err    error
	weight int
}

// NewFilterMemo returns a FilterMemo holding at most maxRanges prefix
// ranges.
func NewFilterMemo(maxRanges int) *FilterMemo {
	return &FilterMemo{max: maxRanges, entries: map[filterKey]*list.Element{}}
}

// Stats returns the counters so far.
func (m *FilterMemo) Stats() FilterMemoStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats
	s.Entries, s.Held = len(m.entries), m.held
	return s
}

// get returns the stored answer for k, if any, and counts the lookup.
func (m *FilterMemo) get(k filterKey) (*filterAnswer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[k]
	if !ok {
		m.stats.Misses++
		return nil, false
	}
	m.stats.Hits++
	m.lru.MoveToFront(el)
	return el.Value.(*filterAnswer), true
}

// put stores an answer computed for k, unless it read the peer, is an error
// that does not follow from the inputs alone, or is too heavy.
func (m *FilterMemo) put(k filterKey, nf NormalFilter, err error, usedPeer bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if usedPeer {
		m.stats.PeerDependent++
		return
	}
	if err != nil && !memoizable(err) {
		return
	}
	if _, ok := m.entries[k]; ok {
		return // another goroutine computed it too
	}
	w := 1
	for _, c := range nf.Conjuncts {
		w += c.Prefixes.Len() + c.NotPrefixes.Len()
	}
	if w > m.max/4 {
		return
	}
	m.entries[k] = m.lru.PushFront(&filterAnswer{key: k, nf: nf, err: err, weight: w})
	m.held += w
	for m.held > m.max {
		back := m.lru.Back()
		old := back.Value.(*filterAnswer)
		m.lru.Remove(back)
		delete(m.entries, old.key)
		m.held -= old.weight
	}
}

// memoizable reports whether err follows from the filter and the registry
// alone, so recomputing would give it again.
func memoizable(err error) bool {
	var tl *SetTooLargeError
	var ne *NotEnumerableError
	var as *AnySetError
	return errors.As(err, &tl) || errors.As(err, &ne) || errors.As(err, &as)
}
```

- [ ] **Step 4: Wire it into `Expander` and `NormalizeFilter`**

In `resolve/expander.go`, add after `Peer types.ASN` in `Expander`:

```go
	// Memo, when set, answers NormalizeFilter from a FilterMemo shared with
	// other Expanders (see FilterMemo for which may share one). It is
	// ignored when Exclude is set. EvalFilter and set expansion do not read
	// it.
	Memo *FilterMemo
```

In `resolve/normalize.go`, replace `NormalizeFilter`'s body (keep its doc comment, adding one paragraph at its end: `With Expander.Memo set and no Exclude, an answer may come from the memo; it is the answer NormalizeFilter would compute (see FilterMemo).`):

```go
func (e *Expander) NormalizeFilter(ctx context.Context, f policy.Filter) (NormalFilter, error) {
	k, memo := e.memoKey(f)
	if memo {
		if a, ok := e.Memo.get(k); ok {
			return a.nf, a.err
		}
	}
	nf, _, usedPeer, err := e.normalize(ctx, f)
	if memo && (err == nil || ctx.Err() == nil) {
		e.Memo.put(k, nf, err, usedPeer)
	}
	return nf, err
}

// memoKey is f's key in e.Memo, and whether the memo applies: it is set,
// Exclude is empty, and f has a text (every policy filter does).
func (e *Expander) memoKey(f policy.Filter) (filterKey, bool) {
	if e.Memo == nil || len(e.Exclude.Sets) > 0 || len(e.Exclude.ASNs) > 0 {
		return filterKey{}, false
	}
	s, ok := f.(fmt.Stringer)
	if !ok {
		return filterKey{}, false
	}
	return filterKey{text: s.String(), afi: e.AFI}, true
}
```

Add `"fmt"` to `normalize.go`'s imports if absent.

- [ ] **Step 5: Run the unit tests**

Run: `cd resolve && gofmt -l . ; go vet . && go test -count=1 -race -run 'TestFilterMemo' .`
Expected: PASS.

- [ ] **Step 6: Write the model equivalence test**

Append to `resolve/filter_model_test.go` (package `resolve_test`; reuse its helpers):

```go
// The memo answers as NormalizeFilter does, over the model's random filters
// (sets, filter-sets, PeerAS, set templates, regexps naming the peer, NOT,
// AND, OR), for peers bound and not and both families, interleaved, with
// one memo per registry.
func TestModelFilterMemo(t *testing.T) {
	ctx := context.Background()
	hits, peerDep := 0, 0
	seeds, _ := resolve.ModelSeeds(200)
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 29))
		m := withTemplateSets(r, randomModel(r, false))
		o := newOracle(m)
		g := newFilterGen(r, o)
		texts := append(m.texts(r), g.filterSets(3)...)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		memo := resolve.NewFilterMemo(1 << 16)
		var fs []policy.Filter
		for i := 0; i < 8; i++ {
			fs = append(fs, mustParseFilter(t, fmt.Sprintf("seed %d", seed), g.filter(3).text()))
		}
		for round := 0; round < 3; round++ {
			for _, f := range fs {
				for _, peer := range []types.ASN{0, types.ASN(firstAS), types.ASN(firstAS + 1)} {
					for _, afi := range []types.AFI{types.AFIv4, types.AFIAny} {
						plain := resolve.Expander{Src: src, Peer: peer, AFI: afi}
						withMemo := plain
						withMemo.Memo = memo
						want, werr := plain.NormalizeFilter(ctx, f)
						got, gerr := withMemo.NormalizeFilter(ctx, f)
						label := fmt.Sprintf("seed %d %v peer %d %v", seed, f, peer, afi)
						if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() || fmt.Sprint(got.Missing()) != fmt.Sprint(want.Missing()) {
							t.Fatalf("%s: memo %q %v %v, plain %q %v %v", label, got, got.Missing(), gerr, want, want.Missing(), werr)
						}
						for i := range want.Conjuncts {
							if !got.Conjuncts[i].Space().Equal(want.Conjuncts[i].Space()) {
								t.Fatalf("%s: conjunct %d's space differs", label, i)
							}
						}
					}
				}
			}
		}
		st := memo.Stats()
		hits += st.Hits
		peerDep += st.PeerDependent
	}
	if hits == 0 || peerDep == 0 {
		t.Fatalf("hits %d, peer-dependent %d: the model exercised neither", hits, peerDep)
	}
}
```

Add `"github.com/rkolesnichenko/rpsl/policy"` to the file's imports if absent.

- [ ] **Step 7: Add the fuzz property**

In `resolve/normalize_fuzz_test.go`'s `FuzzNormalizeFilter`, create the memo next to `src` (shared across inputs, which is the point):

```go
	src := resolve.NewMemSource(objs)
	memo := resolve.NewFilterMemo(1 << 14)
```

and as the first statements inside `f.Fuzz(func(t *testing.T, s string) {`, after `pf, parsed := policy.ParseFilter(s)` and before the clean-parse early return:

```go
		// The memo answers as NormalizeFilter does, for any parse, clean or
		// not, with answers stored from earlier inputs.
		for _, peer := range []types.ASN{0, 65002} {
			plain := resolve.Expander{Src: src, Peer: peer, MaxConjuncts: 64, MaxPrefixes: 1 << 12, MaxVisited: 1 << 12}
			withMemo := plain
			withMemo.Memo = memo
			mctx, mcancel := context.WithTimeout(context.Background(), 2*time.Second)
			want, werr := plain.NormalizeFilter(mctx, pf)
			got, gerr := withMemo.NormalizeFilter(mctx, pf)
			late := mctx.Err() != nil
			mcancel()
			if !late && (fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String()) {
				t.Fatalf("%q peer %d: memo %q %v, plain %q %v", s, peer, got, gerr, want, werr)
			}
		}
```

Add `"fmt"` and `"github.com/rkolesnichenko/rpsl/types"` to its imports if absent.

- [ ] **Step 8: Run the model test and a short fuzz**

Run: `cd resolve && go test -count=1 -run 'TestModelFilterMemo|TestModelNormalize' . && GOMAXPROCS=4 go test -run '^$' -fuzz '^FuzzNormalizeFilter$' -fuzztime 30s .`
Expected: PASS; fuzz finds no failure.

- [ ] **Step 9: Regenerate the API golden**

Run (repo root): `RPSL_API_UPDATE=1 go run ./internal/apisurface -check; go run ./internal/apisurface -check && git diff api/`
Expected: the diff adds exactly `FilterMemo`, `FilterMemoStats` (and fields), `NewFilterMemo`, `(*FilterMemo).Stats`, and `Expander.Memo`; the second run passes.

- [ ] **Step 10: Commit**

```bash
git add resolve/filtermemo.go resolve/filtermemo_test.go resolve/expander.go resolve/normalize.go resolve/filter_model_test.go resolve/normalize_fuzz_test.go api/resolve.txt
git commit -m "resolve: FilterMemo shares NormalizeFilter's answers that did not read the peer"
```

---

### Task 4: `consist.Memo` and `Checker.Memo`

**Files:**
- Create: `resolve/consist/memo.go`, `resolve/consist/memo_test.go`
- Modify: `resolve/consist/consist.go` (`Checker`: add `Memo`; `eval()`)
- Modify: `resolve/consist_model_test.go` (add `TestModelConsistMemo`)
- Modify: `api/resolve_consist.txt` (regenerated)

**Interfaces:**
- Consumes: `resolve.NewFilterMemo`, `resolve.FilterMemoStats`, `Expander.Memo` (Task 3).
- Produces (Task 5 uses):

```go
type Memo struct{ /* unexported */ }
type MemoOptions struct{ AutNums, Ranges int }
type MemoStats struct {
	AutNumHits, AutNumMisses int
	Filters                  resolve.FilterMemoStats
}
func NewMemo() *Memo
func NewMemoWith(o MemoOptions) *Memo
func (m *Memo) Stats() MemoStats
// Checker gains: Memo *Memo
```

- [ ] **Step 1: Write the failing tests**

Create `resolve/consist/memo_test.go`:

```go
package consist

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

var v4 = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}

func keepPolicySource(t *testing.T, n int) resolve.PolicySource {
	t.Helper()
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(lintDump(n))); err != nil {
		t.Fatal(err)
	}
	return l.Source()
}

// A bounded LRU still reads AS1 once when its checks run consecutively, as
// rpslcheck orders them.
func TestMemoAutNumsBounded(t *testing.T) {
	src := countingSource{keepPolicySource(t, 5), map[types.ASN]int{}}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemoWith(MemoOptions{AutNums: 2})}
	for peer := types.ASN(2); peer <= 6; peer++ {
		if _, err := c.Check(context.Background(), Pair{A: 1, B: peer, AF: v4}); err != nil {
			t.Fatal(err)
		}
	}
	if src.n[1] != 1 {
		t.Fatalf("AS1 read %d times over five checks, want 1", src.n[1])
	}
	// Each check reads each side's aut-num twice (peval's Export, then
	// Import): 20 lookups, AS1 and each peer missed once.
	if st := c.Memo.Stats(); st.AutNumHits != 14 || st.AutNumMisses != 6 {
		t.Fatalf("stats %+v, want 14 hits and 6 misses", st)
	}
}

// flakySource fails AutNum while down.
type flakySource struct {
	resolve.PolicySource
	mu   sync.Mutex
	down bool
}

func (s *flakySource) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, errors.New("registry down")
	}
	return s.PolicySource.AutNum(ctx, as, source)
}

// A Source failure is not stored: the next call reads again.
func TestMemoSourceFailureNotStored(t *testing.T) {
	src := &flakySource{PolicySource: keepPolicySource(t, 2), down: true}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	if _, err := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4}); err == nil {
		t.Fatal("a failing Source gave a report")
	}
	src.mu.Lock()
	src.down = false
	src.mu.Unlock()
	want, _ := (&Checker{Eval: peval.Evaluator{Src: src}}).Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	got, err := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after recovery: %+v %v, want %+v", got, err, want)
	}
}

// Review focus 2: a check over its budget leaves nothing for the next.
func TestMemoCheckAfterTimeout(t *testing.T) {
	src := keepPolicySource(t, 3)
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Its answer does not matter (MemSource.AutNum ignores the context, so
	// it may even succeed); what it leaves in the memo does.
	c.Check(ctx, Pair{A: 1, B: 2, AF: v4})
	want, werr := (&Checker{Eval: peval.Evaluator{Src: src}}).Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	got, gerr := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	if werr != nil || gerr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after a cancelled check: %+v %v, want %+v %v", got, gerr, want, werr)
	}
}

// Many goroutines through one Memo, against the same checks without it.
func TestMemoConcurrent(t *testing.T) {
	src := keepPolicySource(t, 30)
	plain := &Checker{Eval: peval.Evaluator{Src: src}}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for peer := types.ASN(2); peer < 32; peer++ {
				p := Pair{A: 1, B: peer, AF: v4}
				want, werr := plain.Check(context.Background(), p)
				got, gerr := c.Check(context.Background(), p)
				if werr != nil || gerr != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("%v: %+v %v, want %+v %v", p, got, gerr, want, werr)
					return
				}
			}
			if _, err := c.Lint(context.Background(), types.ASN(2+g)); err != nil {
				t.Error(err)
			}
		}(g)
	}
	wg.Wait()
}
```

Append to `resolve/consist_model_test.go` (package `resolve_test`):

```go
// The memo changes no answer: every seed's checks and lints with one shared
// Memo equal those without (review focus 5: Lint's sentinel sessions too).
func TestModelConsistMemo(t *testing.T) {
	ctx := context.Background()
	hits := 0
	seeds, _ := resolve.ModelSeeds(200)
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 43))
		cm := randomConsist(t, r, seed)
		src := resolve.NewMemSource(decodeAll(t, cm.texts), "RIPE", "RADB")
		plain := &consist.Checker{Eval: peval.Evaluator{Src: src}, MaxRanges: 1 << 16}
		withMemo := &consist.Checker{Eval: peval.Evaluator{Src: src}, MaxRanges: 1 << 16, Memo: consist.NewMemo()}
		for k := 0; k < 6; k++ {
			p := cm.pair(r)
			want, werr := plain.Check(ctx, p)
			got, gerr := withMemo.Check(ctx, p)
			if fmt.Sprint(gerr) != fmt.Sprint(werr) || !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d %v: memo %+v %v, plain %+v %v", seed, p, got, gerr, want, werr)
			}
		}
		for _, as := range []types.ASN{localAS, peerAS} {
			want, werr := plain.Lint(ctx, as)
			got, gerr := withMemo.Lint(ctx, as)
			if fmt.Sprint(gerr) != fmt.Sprint(werr) || !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d lint %s: memo %v %v, plain %v %v", seed, as, got, gerr, want, werr)
			}
		}
		hits += withMemo.Memo.Stats().Filters.Hits
	}
	if hits == 0 {
		t.Fatal("the memo never answered a filter: the test compared nothing")
	}
}
```

Add `"reflect"` to the file's imports if absent.

- [ ] **Step 2: Run them to verify they fail**

Run: `cd resolve && go test -run 'TestMemo|TestModelConsistMemo' . ./consist`
Expected: build failure — `undefined: NewMemo`, `unknown field Memo in struct literal`.

- [ ] **Step 3: Implement `consist.Memo`**

Create `resolve/consist/memo.go`:

```go
package consist

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// The defaults NewMemo uses (spec §7: set from the full RIPE sweep's
// measurement in Task 6).
const (
	defaultMemoAutNums = 256
	defaultMemoRanges  = 1 << 22
)

// Memo shares work between a Checker's calls: decoded aut-nums and
// inet-rtrs (a bounded LRU) and normalized filters (a resolve.FilterMemo).
// It changes no answer. It holds data read from Checker.Eval.Src, so it
// serves one Checker, or Checkers with the same Eval; it never notices a
// change in the Source, so build a new one for a new snapshot. Safe for
// concurrent use.
type Memo struct {
	mu      sync.Mutex
	max     int
	objects map[memoKey]*list.Element // of *memoEntry
	lru     list.List                 // front: most recently used
	hits    int
	misses  int
	filters *resolve.FilterMemo
}

// MemoOptions bounds a Memo. A zero field takes its default.
type MemoOptions struct {
	AutNums int // decoded aut-nums and inet-rtrs held (default 256)
	Ranges  int // prefix ranges the filter memo holds (default 1<<22)
}

// MemoStats is a Memo's counters, for measurement and tests.
type MemoStats struct {
	AutNumHits, AutNumMisses int // aut-num and inet-rtr lookups answered from the memo / read
	Filters                  resolve.FilterMemoStats
}

type memoKey struct {
	kind         byte // 'a' aut-num, 'r' inet-rtr
	name, source string
}

type memoEntry struct {
	key memoKey
	obj object.Object // a *object.AutNum or *object.InetRtr, possibly a typed nil
	err error
}

// NewMemo returns a Memo with the default bounds.
func NewMemo() *Memo { return NewMemoWith(MemoOptions{}) }

// NewMemoWith returns a Memo with o's bounds.
func NewMemoWith(o MemoOptions) *Memo {
	if o.AutNums <= 0 {
		o.AutNums = defaultMemoAutNums
	}
	if o.Ranges <= 0 {
		o.Ranges = defaultMemoRanges
	}
	return &Memo{max: o.AutNums, objects: map[memoKey]*list.Element{}, filters: resolve.NewFilterMemo(o.Ranges)}
}

// Stats returns the counters so far.
func (m *Memo) Stats() MemoStats {
	m.mu.Lock()
	s := MemoStats{AutNumHits: m.hits, AutNumMisses: m.misses}
	m.mu.Unlock()
	s.Filters = m.filters.Stats()
	return s
}

func (m *Memo) get(k memoKey) (*memoEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.objects[k]
	if !ok {
		m.misses++
		return nil, false
	}
	m.hits++
	m.lru.MoveToFront(el)
	return el.Value.(*memoEntry), true
}

// put stores an answer: an object, or not found. Any other error (a Source
// failure, a context error) is not stored.
func (m *Memo) put(ctx context.Context, k memoKey, obj object.Object, err error) {
	if err != nil && (!errors.Is(err, resolve.ErrNotFound) || ctx.Err() != nil) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[k]; ok {
		return
	}
	m.objects[k] = m.lru.PushFront(&memoEntry{key: k, obj: obj, err: err})
	for len(m.objects) > m.max {
		back := m.lru.Back()
		m.lru.Remove(back)
		delete(m.objects, back.Value.(*memoEntry).key)
	}
}

// memoSource is a PolicySource answering aut-nums and inet-rtrs through a
// Memo shared by a Checker's calls.
type memoSource struct {
	resolve.PolicySource
	m *Memo
}

func (s memoSource) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	k := memoKey{'a', as.String(), source}
	if e, ok := s.m.get(k); ok {
		an, _ := e.obj.(*object.AutNum)
		return an, e.err
	}
	an, err := s.PolicySource.AutNum(ctx, as, source)
	s.m.put(ctx, k, an, err)
	return an, err
}

func (s memoSource) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	k := memoKey{'r', name, source}
	if e, ok := s.m.get(k); ok {
		ir, _ := e.obj.(*object.InetRtr)
		return ir, e.err
	}
	ir, err := s.PolicySource.InetRtr(ctx, name, source)
	s.m.put(ctx, k, ir, err)
	return ir, err
}
```

- [ ] **Step 4: Wire it into `Checker`**

In `resolve/consist/consist.go`, add to `Checker` after `SetPeers bool`:

```go
	// Memo, when set, shares decoded aut-nums and inet-rtrs and normalized
	// filters across this Checker's calls (Check, Lint, Peers); see Memo.
	// nil: each call stands alone. Results are the same either way.
	Memo *Memo
```

Replace `eval()`:

```go
// eval is c.Eval with Expander.Exclude cleared and Src memoizing its
// aut-nums and inet-rtrs: through c.Memo, shared by every call, when set
// (and Expander.Memo set to its filter memo); otherwise a per-call
// policyMemo. Every evaluation consist makes goes through it.
func (c *Checker) eval() *peval.Evaluator {
	e := c.Eval
	e.Expander.Exclude = resolve.Exclusion{}
	switch {
	case e.Src == nil:
	case c.Memo != nil:
		e.Src = memoSource{PolicySource: e.Src, m: c.Memo}
		e.Expander.Memo = c.Memo.filters
	default:
		e.Src = &policyMemo{PolicySource: e.Src, autNums: map[policyKey]autNumAnswer{}, rtrs: map[policyKey]inetRtrAnswer{}}
	}
	return &e
}
```

(`lint.go`'s peer existence check already reads `c.Eval.Src`, and `peers.go` asserts `PolicyIndex` on `c.Eval.Src`; both stay as they are.)

- [ ] **Step 5: Run the tests**

Run: `cd resolve && gofmt -l . ; go vet ./consist && go test -count=1 -race -run 'TestMemo|TestLint|TestPeers' ./consist && go test -count=1 -run 'TestModelConsist' .`
Expected: PASS.

- [ ] **Step 6: Regenerate the API golden**

Run (repo root): `RPSL_API_UPDATE=1 go run ./internal/apisurface -check; go run ./internal/apisurface -check && git diff api/`
Expected: adds `Memo`, `MemoOptions`, `MemoStats`, `NewMemo`, `NewMemoWith`, `(*Memo).Stats`, `Checker.Memo`; C1 holds (`NewMemo`/`NewMemoWith` pair); second run passes.

- [ ] **Step 7: Commit**

```bash
git add resolve/consist/memo.go resolve/consist/memo_test.go resolve/consist/consist.go resolve/consist_model_test.go api/resolve_consist.txt
git commit -m "consist: Memo shares decoded aut-nums and normalized filters across a Checker's calls"
```

---

### Task 5: `rpslcheck` uses the memo; a provider benchmark

**Files:**
- Modify: `resolve/internal/rpslcheck/rpslcheck.go:133`, `resolve/internal/rpslcheck/sweep.go:117`
- Modify: `resolve/consist/bench_test.go` (add `BenchmarkCheckProvider`)

**Interfaces:**
- Consumes: `consist.NewMemo()`, `Checker.Memo` (Task 4).

- [ ] **Step 1: Add the benchmark**

Append to `resolve/consist/bench_test.go`:

```go
// providerDump is AS1 exporting one customer as-set to each of n peers and
// importing each peer's routes; each peer imports the set from AS1. The
// set has 100 member ASes with a route each.
func providerDump(n int) string {
	var b strings.Builder
	b.WriteString("as-set: AS-CUST\nmembers: ")
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "AS%d", 10000+i)
	}
	b.WriteString("\nsource: RIPE\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "\nroute: 10.%d.%d.0/24\norigin: AS%d\nsource: RIPE\n", i/250, i%250, 10000+i)
	}
	b.WriteString("\naut-num: AS1\nas-name: PROVIDER\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "import: from AS%d accept AS%d\nexport: to AS%d announce AS-CUST\n", i, i, i)
	}
	b.WriteString("source: RIPE\n")
	for i := 2; i < n+2; i++ {
		fmt.Fprintf(&b, "\naut-num: AS%d\nas-name: PEER\nimport: from AS1 accept AS-CUST\nexport: to AS1 announce AS%d\nsource: RIPE\n", i, i)
	}
	return b.String()
}

// BenchmarkCheckProvider checks every pair of a provider with N peers, as
// rpslcheck's sweep does, with and without a Memo.
func BenchmarkCheckProvider(b *testing.B) {
	const n = 200
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(providerDump(n))); err != nil {
		b.Fatal(err)
	}
	af := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	for _, memo := range []bool{false, true} {
		b.Run(fmt.Sprintf("memo=%v", memo), func(b *testing.B) {
			for range b.N {
				c := &Checker{Eval: peval.Evaluator{Src: l.Source()}}
				if memo {
					c.Memo = NewMemo()
				}
				for peer := types.ASN(2); peer < n+2; peer++ {
					if _, err := c.Check(context.Background(), Pair{A: 1, B: peer, AF: af}); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
```

Add `"github.com/rkolesnichenko/rpsl/types"` to the file's imports.

- [ ] **Step 2: Run the benchmark**

Run: `cd resolve/consist && go test -run '^$' -bench BenchmarkCheckProvider -benchtime 5x -benchmem .`
Expected: both variants run; record ns/op for each (the memo variant should be lower; if not, stop and investigate before Step 3).

- [ ] **Step 3: Turn the memo on in rpslcheck**

In `resolve/internal/rpslcheck/rpslcheck.go:133` and `resolve/internal/rpslcheck/sweep.go:117`, add `Memo: consist.NewMemo()` to the `consist.Checker` literal:

```go
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: *setPeers, ASPAs: aspas, Memo: consist.NewMemo()}
```

```go
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: setPeers, ASPAs: aspas, Memo: consist.NewMemo()}
```

- [ ] **Step 4: The goldens must not change**

Run: `cd resolve && go test -count=1 ./internal/rpslcheck/ && git status --short resolve/testdata/rpslcheck/`
Expected: `ok`; no golden modified (do NOT run with `RPSL_RPSLCHECK_UPDATE=1`).

- [ ] **Step 5: Commit**

```bash
git add resolve/consist/bench_test.go resolve/internal/rpslcheck/rpslcheck.go resolve/internal/rpslcheck/sweep.go
git commit -m "rpslcheck: share a consist.Memo across each run's checks; BenchmarkCheckProvider"
```

---

### Task 6: Measure on RIPE, set the defaults, document

**Files:**
- Modify: `resolve/consist/memo.go` (defaults, if the measurement says so)
- Modify: `resolve/consist/consist_realdata_test.go` (`RPSL_CONSIST_MEMO=1` sets `Checker.Memo`, logs `Stats`)
- Modify: `CLAUDE.md`, `docs/rpsl-go-design.md` (§8.12), `docs/rpslcheck.md` (cost section), `CHANGELOG.md` (Unreleased)

- [ ] **Step 1: Let the real-data test use the memo**

In `TestRealDataConsist`, after `c := &Checker{…}` is built:

```go
	if os.Getenv("RPSL_CONSIST_MEMO") != "" {
		c.Memo = NewMemoWith(MemoOptions{AutNums: atoiEnv("RPSL_CONSIST_MEMO_AUTNUMS"), Ranges: atoiEnv("RPSL_CONSIST_MEMO_RANGES")})
		defer func() { t.Logf("memo: %+v", c.Memo.Stats()) }()
	}
```

and add to the file:

```go
func atoiEnv(k string) int { n, _ := strconv.Atoi(os.Getenv(k)); return n }
```

- [ ] **Step 2: Sample sweep, counts identical**

Run (from `resolve/`, alone):

```bash
env GOMAXPROCS=4 GOMEMLIMIT=4GiB MEMGUARD_NORMAL_PRIORITY=1 RPSL_REALDATA=$PWD/../.data RPSL_CONSIST_SAMPLE=2000 RPSL_CONSIST_MEMO=1 \
  ../.superpowers/sdd/tools/memguard.sh 6 3000 go test -count=1 -v -timeout 50m -run TestRealDataConsist ./consist > ../.superpowers/sdd/sweep-memo/sample-memo.log 2>&1; echo exit=$?
```

Expected: exit 0; the counts block (from `directions` to `via sets, not checked`) identical to `.superpowers/sdd/sweep-profile/run2.log.counts` (94,660 directions, 47,330 pairs, …). Compare with `diff`. Any difference is a bug: stop and find it.

- [ ] **Step 3: rpslcheck before and after**

Build both binaries (`git stash` is not needed: build `main`'s from a worktree):

```bash
git worktree add --detach .claude/worktrees/memo-base main
(cd .claude/worktrees/memo-base/resolve && go build -o ../../../../.superpowers/sdd/sweep-memo/rpslcheck-main ./cmd/rpslcheck)
(cd resolve && go build -o ../.superpowers/sdd/sweep-memo/rpslcheck-memo ./cmd/rpslcheck)
```

Run each alone, from the repo root, under memguard (`-dump` is repeatable; pass the RIPE files the real-data test reads):

```bash
D=.superpowers/sdd/sweep-memo
dumps=(); for f in .data/ripe/*.gz; do b=${f:t}; if [[ $(tr -cd . <<<$b | wc -c) -le 2 || $b == *.route* || $b == *-set* || $b == *.aut-num* || $b == *.inet-rtr* ]]; then dumps+=(-dump $f); fi; done
for v in main memo; do
  env GOMAXPROCS=4 MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 6 3600 \
    /usr/bin/time -l $D/rpslcheck-$v -sweep -sample 2000 -c 4 -json $dumps > $D/sweep-$v.json 2> $D/sweep-$v.err
  echo "$v exit=$?"
done
diff $D/sweep-main.json $D/sweep-memo.json && echo identical
grep -E 'real|maximum resident' $D/sweep-*.err
```

Expected: identical output (rpslcheck exits 0 or 1, by Warnings, the same for both); record both wall times and peak RSS.

- [ ] **Step 4: Full RIPE sweep, memo unbounded, to set the defaults**

Run `rpslcheck-memo` with `-sweep -c 4` over all of RIPE once with the memo effectively unbounded (temporarily build with `defaultMemoRanges = 1 << 30`, `defaultMemoAutNums = 1 << 20`; revert after), under memguard at 7 GB, logging `MemoStats` at exit (temporarily print `c.Memo.Stats()` to stderr in sweep.go; revert after). Record peak RSS, `Filters.Held`, `Filters.Entries`, hit rates. Then set `defaultMemoRanges` to the largest power of two such that the memo's share of the peak (peak RSS with memo minus peak RSS without, scaled by `Held`) stays under 1 GB; keep `defaultMemoAutNums = 256` unless `AutNumHits/(Hits+Misses)` rises by more than 5 points with 1024. Re-run the full sweep with the chosen defaults and the main build; record both times, both peaks, and diff their outputs (must be identical).

- [ ] **Step 5: Document**

- `CLAUDE.md`, under "Consistency (`resolve/consist`) is exact or undecided." add a bullet:
  `- **`Checker.Memo` is result-neutral.** `resolve.FilterMemo` never stores an answer whose normalization read `Expander.Peer` (every read goes through `filterEval.peer`; `TestPeerReadsGoThroughAccessor`), nor a context or Source error; a `Memo` serves one snapshot. `rpslcheck` always sets it.`
- `docs/rpsl-go-design.md` §8.12: one paragraph describing the memo (the three pieces of spec §1) and the measured full-sweep time before/after from Step 4.
- `docs/rpslcheck.md`, "Known limit" section: add the measured full RIPE sweep time with the memo, its peak RSS, and that the memo is on in every mode.
- `CHANGELOG.md`, under `## [Unreleased]`: `### Added` (`resolve.FilterMemo`, `Expander.Memo`, `consist.Memo`/`MemoOptions`/`MemoStats`/`NewMemo`/`NewMemoWith`, `Checker.Memo`) and `### Changed` (rpslcheck uses it: the sample and full-sweep times from Steps 3–4; `Conjunct.Space` computed once per normalized conjunct; the two removed sorts from `a3fff21`).

Every figure written comes from Steps 2–4's logs.

- [ ] **Step 6: Commit**

```bash
git add resolve/consist/memo.go resolve/consist/consist_realdata_test.go CLAUDE.md docs/rpsl-go-design.md docs/rpslcheck.md CHANGELOG.md
git commit -m "consist: memo defaults from a full RIPE sweep; docs"
git worktree remove .claude/worktrees/memo-base
```

---

### Task 7: Verification before merge

- [ ] **Step 1: Full check with fuzzing**

Run (repo root, alone): `GOMAXPROCS=4 FUZZTIME=15s MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 7 3000 scripts/check.sh > .superpowers/sdd/sweep-memo/check.log 2>&1; echo exit=$?`
Expected: exit 0, `check: ok`, 45 fuzz targets run.

- [ ] **Step 2: Engine purity and leaf isolation**

Run: `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki | grep -x net; cd ../types && go list -deps ./... | grep rkolesnichenko`
Expected: first prints nothing; second prints only `github.com/rkolesnichenko/rpsl/types`.

- [ ] **Step 3: Independent review**

Dispatch a reviewer agent on `git diff main...sweep-perf` with the spec and this plan; fix every Critical and Important finding, re-running the affected tests and Task 6 Step 2 if the memo code changed.

- [ ] **Step 4: Open the PR**

Push `sweep-perf` and open a PR whose body lists the measurements from Task 6 (each figure from its log) and the verification above.
