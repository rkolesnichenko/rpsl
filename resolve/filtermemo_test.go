package resolve

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
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

// Review focus 2: a context error is not stored. NormalizeFilter's ctx.Err()
// guard and memoizable each keep it out, and this test cannot tell which
// did; the guard is defensive, since a memoizable error never depends on the
// context.
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

// downSource fails every GetSet while down.
type downSource struct {
	Source
	mu   sync.Mutex
	down bool
}

func (s *downSource) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, errors.New("registry down")
	}
	return s.Source.GetSet(ctx, ref)
}

func TestFilterMemoSourceFailureNotStored(t *testing.T) {
	src := &downSource{Source: memoCorpus(t), down: true}
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

// An answer heavier than a quarter of the bound is computed and not stored:
// the memo is unchanged after it, and asking again misses again.
func TestFilterMemoOversizeNotStored(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(12)
	plain := &Expander{Src: src}
	e := &Expander{Src: src, Memo: memo}
	light := mustFilter(t, "{10.0.0.0/8, 10.1.0.0/16}")               // weight 3, a quarter of 12
	heavy := mustFilter(t, "{10.7.0.0/16, 10.8.0.0/16, 10.9.0.0/16}") // weight 4
	if _, err := e.NormalizeFilter(context.Background(), light); err != nil {
		t.Fatal(err)
	}
	before := memo.Stats()
	if before.Entries != 1 || before.Held != 3 {
		t.Fatalf("stats %+v after the light filter, want 1 entry holding 3", before)
	}
	for i := 0; i < 2; i++ {
		want, werr := plain.NormalizeFilter(context.Background(), heavy)
		got, gerr := e.NormalizeFilter(context.Background(), heavy)
		sameNormal(t, "heavy", got, gerr, want, werr)
	}
	after := memo.Stats()
	if after.Entries != before.Entries || after.Held != before.Held || after.Hits != before.Hits {
		t.Fatalf("stats %+v after the heavy filter, want %+v but for 2 more misses", after, before)
	}
}

// An AS-path test's sets count toward an answer's weight, one per ASN.
func TestFilterMemoWeighsPathSets(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	nf, err := (&Expander{Src: src, Memo: memo}).NormalizeFilter(context.Background(), mustFilter(t, "<AS-A>"))
	if err != nil || len(nf.Conjuncts) != 1 || nf.Conjuncts[0].Paths[0].Sets[mustSet(t, "AS-A")].Len() != 1 {
		t.Fatalf("<AS-A>: %+v %v", nf.Conjuncts, err)
	}
	c := nf.Conjuncts[0]
	if want, st := 1+c.Prefixes.Len()+c.NotPrefixes.Len()+1, memo.Stats(); st.Held != want {
		t.Fatalf("held %d, want %d: one, the conjunct's ranges and AS-A's one ASN", st.Held, want)
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

// Two groupings of one text are two filters: the normalizer charges depth
// per group, so under MaxDepth 1 the nested one fails where the flat one
// succeeds, and a memo must give each its own answer, in either order.
func TestFilterMemoKeyedByGrouping(t *testing.T) {
	src := memoCorpus(t)
	flat := mustFilter(t, "AS-A AND AS65001 AND {10.0.0.0/8^+}")
	nested := mustFilter(t, "(AS-A AND AS65001) AND {10.0.0.0/8^+}")
	if fmt.Sprint(flat) != fmt.Sprint(nested) {
		t.Fatalf("the two groupings print %q and %q; the test needs one text", flat, nested)
	}
	for _, lim := range []Expander{{MaxDepth: 1}, {MaxVisited: 6, MaxDepth: 1}} {
		plain := lim
		plain.Src = src
		_, ferr := plain.NormalizeFilter(context.Background(), flat)
		_, nerr := plain.NormalizeFilter(context.Background(), nested)
		if fmt.Sprint(ferr) == fmt.Sprint(nerr) {
			t.Fatalf("%+v: both groupings give %v; the test needs two answers", lim, ferr)
		}
		for _, order := range [][]policy.Filter{{flat, nested}, {nested, flat}} {
			withMemo := plain
			withMemo.Memo = NewFilterMemo(1 << 10)
			for _, f := range order {
				want, werr := plain.NormalizeFilter(context.Background(), f)
				got, gerr := withMemo.NormalizeFilter(context.Background(), f)
				sameNormal(t, fmt.Sprintf("%#v under %+v", f, lim), got, gerr, want, werr)
			}
			if st := withMemo.Memo.Stats(); st.Hits != 0 {
				t.Fatalf("%+v: stats %+v, want no hit between the groupings", lim, st)
			}
		}
	}
}

// Two spellings of one community test print alike, but a hit must return the
// test as the filter wrote it: each spelling gets its own Raw back.
func TestFilterMemoKeyedByCommunitySpelling(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	texts := []string{"community(65000:1)", "community.contains(65000:1)", "community(  65000:1 )"}
	for round := 0; round < 2; round++ {
		for _, s := range texts {
			f := mustFilter(t, s)
			want, werr := (&Expander{Src: src}).NormalizeFilter(context.Background(), f)
			got, gerr := (&Expander{Src: src, Memo: memo}).NormalizeFilter(context.Background(), f)
			if werr != nil || gerr != nil || !reflect.DeepEqual(got.Conjuncts[0].Communities, want.Conjuncts[0].Communities) {
				t.Fatalf("%s: memo %+v %v, plain %+v %v", s, got.Conjuncts, gerr, want.Conjuncts, werr)
			}
			if raw := got.Conjuncts[0].Communities[0].Test.Raw; raw != f.(policy.FilterCommunity).Raw {
				t.Fatalf("%s: the memo returned Raw %q", s, raw)
			}
		}
	}
	if st := memo.Stats(); st.Entries != len(texts) || st.Hits != len(texts) {
		t.Fatalf("stats %+v, want one entry per spelling, each hit once", st)
	}
}

// An AS-path regexp's tree is part of the answer (PathMatch.RE), so two
// regexps with one Raw and one String but different trees are two filters.
func TestFilterMemoKeyedByRegexpTree(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	re := func(min, max int) policy.Filter {
		return policy.FilterPathRE{Raw: "AS1*", Regexp: &policy.ASPathRE{Body: policy.ASPathRepeat{
			Inner: policy.ASPathASN{AS: 1}, Op: policy.RepeatStar, Min: min, Max: max}}}
	}
	a, b := re(0, -1), re(2, 7)
	if a.(policy.FilterPathRE).Regexp.String() != b.(policy.FilterPathRE).Regexp.String() {
		t.Fatal("the two trees print differently; the test needs one text")
	}
	for _, f := range []policy.Filter{a, b, a, b} {
		got, err := (&Expander{Src: src, Memo: memo}).NormalizeFilter(context.Background(), f)
		if err != nil || !reflect.DeepEqual(got.Conjuncts[0].Paths[0].RE, f.(policy.FilterPathRE).Regexp) {
			t.Fatalf("%#v: got %+v %v", f, got.Conjuncts, err)
		}
	}
	if st := memo.Stats(); st.Entries != 2 || st.Hits != 2 {
		t.Fatalf("stats %+v, want 2 entries, each hit once", st)
	}
}

// memoText tells apart what String does not, and refuses what it cannot
// render rather than guessing.
func TestMemoText(t *testing.T) {
	text := func(f policy.Filter) string {
		t.Helper()
		s, ok := memoText(f)
		if !ok {
			t.Fatalf("memoText(%#v) refused", f)
		}
		return s
	}
	rs := mustFilter(t, "RS-X").(policy.FilterSetRef)
	plusN := rs
	plusN.Op = types.RangeOperator{Op: types.RangePlus, N: 3}
	plus := rs
	plus.Op = types.RangeOperator{Op: types.RangePlus}
	pairs := [][2]policy.Filter{
		{mustFilter(t, "(AS1 OR AS2) OR AS3"), mustFilter(t, "AS1 OR AS2 OR AS3")},
		{mustFilter(t, "community(1:1)"), mustFilter(t, "community.contains(1:1)")},
		{plusN, plus},
		{policy.FilterPrefixList{Ranges: []types.PrefixRange{{}}}, policy.FilterPrefixList{}},
		{policy.FilterASExpr{AS: policy.ASSetRef{Name: mustSet(t, "AS-A")}}, policy.FilterSetRef{Name: mustSet(t, "AS-A")}},
		{policy.FilterCommunity{Raw: "community(1:1)", Values: []string{}}, policy.FilterCommunity{Raw: "community(1:1)"}},
	}
	for _, p := range pairs {
		if fmt.Sprint(p[0]) != fmt.Sprint(p[1]) {
			continue // String already tells these apart; memoText must too
		}
		if a, b := text(p[0]), text(p[1]); a == b {
			t.Errorf("%#v and %#v share the key %q", p[0], p[1], a)
		}
	}
	for _, f := range []policy.Filter{nil, &policy.FilterAny{}, policy.FilterNot{}, policy.FilterAnd{Terms: []policy.Filter{policy.FilterAny{}, nil}},
		policy.FilterASExpr{}, policy.FilterPathRE{Raw: "x", Regexp: &policy.ASPathRE{}}} {
		if s, ok := memoText(f); ok {
			t.Errorf("memoText(%#v) = %q, want it refused", f, s)
		}
	}
}

// The limits are part of the key: Expanders with different limits sharing a
// memo each get their own answer, and a zero limit shares with its default.
func TestFilterMemoKeyedByLimits(t *testing.T) {
	src := memoCorpus(t)
	for _, c := range []struct {
		filter string
		tight  Expander
	}{
		{"AS-A OR AS65002", Expander{MaxPrefixes: 1}},
		{"<^AS65001> OR <^AS65002>", Expander{MaxConjuncts: 1}},
		{"(AS-A AND AS65001) AND {10.0.0.0/8^+}", Expander{MaxDepth: 1}},
	} {
		f := mustFilter(t, c.filter)
		tight := c.tight
		tight.Src = src
		loose := Expander{Src: src}
		_, terr := tight.NormalizeFilter(context.Background(), f)
		_, lerr := loose.NormalizeFilter(context.Background(), f)
		if terr == nil || lerr != nil {
			t.Fatalf("%s: tight %v, loose %v; the test needs an error and a success", c.filter, terr, lerr)
		}
		for _, order := range [][]Expander{{tight, loose}, {loose, tight}} {
			memo := NewFilterMemo(1 << 10)
			for _, e := range order {
				want, werr := e.NormalizeFilter(context.Background(), f)
				withMemo := e
				withMemo.Memo = memo
				got, gerr := withMemo.NormalizeFilter(context.Background(), f)
				sameNormal(t, fmt.Sprintf("%s under %+v", c.filter, e), got, gerr, want, werr)
			}
		}
	}
	memo := NewFilterMemo(1 << 10)
	f := mustFilter(t, "AS-A")
	zero := &Expander{Src: src, Memo: memo}
	explicit := &Expander{Src: src, Memo: memo, MaxDepth: defaultMaxDepth, MaxPrefixes: defaultMaxPrefixes,
		MaxVisited: defaultMaxVisited, MaxConjuncts: defaultMaxConjuncts}
	for _, e := range []*Expander{zero, explicit} {
		if _, err := e.NormalizeFilter(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	if st := memo.Stats(); st.Hits != 1 || st.Entries != 1 {
		t.Fatalf("stats %+v: zero limits and explicit defaults should share one entry", st)
	}
}

// sameASNs fails unless two ExpandAS answers are the same ASNs, missing sets
// and error.
func sameASNs(t *testing.T, label string, got ASNSet, gerr error, want ASNSet, werr error) {
	t.Helper()
	if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() || fmt.Sprint(got.Missing()) != fmt.Sprint(want.Missing()) {
		t.Fatalf("%s: memo %v %v %v, plain %v %v %v", label, got, got.Missing(), gerr, want, want.Missing(), werr)
	}
}

// ExpandAS answers from the memo too: peval tests a peering's as-set once per
// call, and a lint makes six calls per peer.
func TestFilterMemoExpandASHit(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	ref := types.Ref(mustSet(t, "AS-A"))
	first, err1 := e.ExpandAS(context.Background(), ref)
	again, err2 := e.ExpandAS(context.Background(), ref)
	sameASNs(t, "AS-A", again, err2, first, err1)
	if st := memo.Stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 || st.Held != 2 {
		t.Fatalf("stats %+v, want 1 hit, 1 miss, 1 entry holding 2", st)
	}
}

// A filter naming a set and the set's expansion are two answers: neither is
// served for the other.
func TestFilterMemoExpandASKeyedApartFromFilters(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, "AS-A")); err != nil {
		t.Fatal(err)
	}
	got, gerr := e.ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-A")))
	want, werr := (&Expander{Src: src}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-A")))
	sameASNs(t, "AS-A", got, gerr, want, werr)
	if st := memo.Stats(); st.Hits != 0 || st.Entries != 2 {
		t.Fatalf("stats %+v, want 2 entries and no hit", st)
	}
}

// Over random as-set graphs (cycles, scoped members, missing sets), one memo
// shared by every call gives each call the answer a plain Expander gives,
// under the default limits and tight ones, whatever was asked before.
func TestFilterMemoExpandASMatchesPlain(t *testing.T) {
	limits := []Expander{{}, {MaxDepth: 1}, {MaxVisited: 2}, {MaxDepth: 2, MaxVisited: 3}}
	for seed := uint64(0); seed < 100; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x3e3))
		src := randomGraph(r, 6).corpus(t, r)
		memo := NewFilterMemo(1 << 10)
		for round := 0; round < 2; round++ {
			for _, i := range r.Perm(7) { // AS-S6 is missing
				ref := types.Ref(mustSet(t, fmt.Sprintf("AS-S%d", i)))
				for _, l := range limits {
					plain := l
					plain.Src = src
					withMemo := plain
					withMemo.Memo = memo
					want, werr := plain.ExpandAS(context.Background(), ref)
					got, gerr := withMemo.ExpandAS(context.Background(), ref)
					sameASNs(t, fmt.Sprintf("seed %d %s under %+v", seed, ref, l), got, gerr, want, werr)
				}
			}
		}
		if st := memo.Stats(); st.Hits == 0 {
			t.Fatalf("seed %d: stats %+v, want hits on the second round", seed, st)
		}
	}
}

func TestFilterMemoExpandASIgnoredWithExclude(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	ref := types.Ref(mustSet(t, "AS-A"))
	if _, err := (&Expander{Src: src, Memo: memo}).ExpandAS(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	ex := Exclusion{ASNs: []types.ASN{65001}}
	want, werr := (&Expander{Src: src, Exclude: ex}).ExpandAS(context.Background(), ref)
	got, gerr := (&Expander{Src: src, Memo: memo, Exclude: ex}).ExpandAS(context.Background(), ref)
	sameASNs(t, "AS-A excluding AS65001", got, gerr, want, werr)
	if st := memo.Stats(); st.Hits != 0 || st.Misses != 1 {
		t.Fatalf("stats %+v: the Exclude call touched the memo", st)
	}
}

// A set reaching AS-ANY is an *AnySetError every time: stored.
func TestFilterMemoExpandASStoresDeterministicError(t *testing.T) {
	src := corpus(t, asSet("AS-TOP", "AS65001", "AS-ANY"))
	memo := NewFilterMemo(1 << 10)
	e := &Expander{Src: src, Memo: memo}
	ref := types.Ref(mustSet(t, "AS-TOP"))
	_, err1 := e.ExpandAS(context.Background(), ref)
	_, err2 := e.ExpandAS(context.Background(), ref)
	var as *AnySetError
	if !errors.As(err1, &as) || fmt.Sprint(err1) != fmt.Sprint(err2) {
		t.Fatalf("%v, then %v; want the same *AnySetError twice", err1, err2)
	}
	if st := memo.Stats(); st.Hits != 1 {
		t.Fatalf("stats %+v, want the second call answered from the memo", st)
	}
}

// A Source failure, a context error and a missing top set are not stored.
// The context error is kept out by memoizable; ExpandAS's ctx.Err() guard,
// like NormalizeFilter's, is defensive, and this test cannot tell it apart.
func TestFilterMemoExpandASFailuresNotStored(t *testing.T) {
	src := &downSource{Source: memoCorpus(t), down: true}
	memo := NewFilterMemo(1 << 10)
	e := &Expander{Src: src, Memo: memo}
	ref := types.Ref(mustSet(t, "AS-A"))
	if _, err := e.ExpandAS(context.Background(), ref); err == nil {
		t.Fatal("a failing Source expanded AS-A")
	}
	src.mu.Lock()
	src.down = false
	src.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.ExpandAS(ctx, ref); err == nil {
		t.Fatal("a cancelled context expanded AS-A")
	}
	if _, err := e.ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-NONE"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AS-NONE: %v, want ErrNotFound", err)
	}
	if got, err := e.ExpandAS(context.Background(), ref); err != nil || got.String() != "[AS65001]" {
		t.Fatalf("after the Source recovered: %v %v", got, err)
	}
	if st := memo.Stats(); st.Entries != 1 || st.Hits != 0 {
		t.Fatalf("stats %+v, want only the last answer stored", st)
	}
}

// An expansion heavier than a quarter of the bound is computed, not stored.
func TestFilterMemoExpandASOversizeNotStored(t *testing.T) {
	src := corpus(t, asSet("AS-BIG", "AS1", "AS2", "AS3"), asSet("AS-SMALL", "AS1", "AS2"))
	memo := NewFilterMemo(12)
	e := &Expander{Src: src, Memo: memo}
	for _, name := range []string{"AS-SMALL", "AS-BIG", "AS-BIG"} { // weights 3 (a quarter of 12) and 4
		if _, err := e.ExpandAS(context.Background(), types.Ref(mustSet(t, name))); err != nil {
			t.Fatal(err)
		}
	}
	if st := memo.Stats(); st.Entries != 1 || st.Held != 3 || st.Misses != 3 {
		t.Fatalf("stats %+v, want AS-SMALL alone stored and AS-BIG missing twice", st)
	}
}

// An expansion weighs its missing sets too: a set of few ASNs can name up to
// MaxVisited sets that are not there, each held in its Missing list.
func TestFilterMemoExpandASWeighsMissing(t *testing.T) {
	src := corpus(t, asSet("AS-M", "AS1", "AS-X1", "AS-X2", "AS-X3"))
	memo := NewFilterMemo(1 << 10)
	e := &Expander{Src: src, Memo: memo}
	got, err := e.ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-M")))
	if err != nil || got.Len() != 1 || len(got.Missing()) != 3 {
		t.Fatalf("AS-M: %v missing %v, %v; the test needs 1 ASN and 3 missing sets", got, got.Missing(), err)
	}
	if st := memo.Stats(); st.Held != 5 {
		t.Fatalf("stats %+v, want AS-M held at weight 5 (1 + 1 ASN + 3 missing)", st)
	}
}

// Expansions never evict a filter, nor filters an expansion: the two are
// bounded apart. Sharing one bound, RIPE's AS202827 filled the memo with its
// filters, and the IXP sets its peerings expand pushed them out, so it
// normalized them again and again: alone, it took 24.7 s, where v0.27.1 had
// taken 16.0 s; bounded apart, 5.5 s.
func TestFilterMemoExpansionsDoNotEvictFilters(t *testing.T) {
	src := corpus(t, asSet("AS-A", "AS1", "AS2"), asSet("AS-B", "AS3", "AS4"), asSet("AS-C", "AS5", "AS6"), asSet("AS-D", "AS7", "AS8"))
	memo := NewFilterMemo(12)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "{10.1.0.0/16, 10.2.0.0/16}")
	if _, err := e.NormalizeFilter(context.Background(), f); err != nil { // weight 3
		t.Fatal(err)
	}
	for _, name := range []string{"AS-A", "AS-B", "AS-C", "AS-D"} { // weight 3 each: 12 in all
		if _, err := e.ExpandAS(context.Background(), types.Ref(mustSet(t, name))); err != nil {
			t.Fatal(err)
		}
	}
	before := memo.Stats().Hits
	if _, err := e.NormalizeFilter(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if st := memo.Stats(); st.Hits != before+1 {
		t.Fatalf("stats %+v: the expansions evicted the filter", st)
	}
}

func TestFilterMemoFiltersDoNotEvictExpansions(t *testing.T) {
	src := corpus(t, asSet("AS-SMALL", "AS1", "AS2"))
	memo := NewFilterMemo(12)
	e := &Expander{Src: src, Memo: memo}
	ref := types.Ref(mustSet(t, "AS-SMALL"))
	if _, err := e.ExpandAS(context.Background(), ref); err != nil { // weight 3
		t.Fatal(err)
	}
	for _, s := range []string{"{10.1.0.0/16, 10.2.0.0/16}", "{10.3.0.0/16, 10.4.0.0/16}", "{10.5.0.0/16, 10.6.0.0/16}", "{10.7.0.0/16, 10.8.0.0/16}"} {
		if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, s)); err != nil { // weight 3 each: 12 in all
			t.Fatal(err)
		}
	}
	before := memo.Stats().Hits
	if _, err := e.ExpandAS(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if st := memo.Stats(); st.Hits != before+1 {
		t.Fatalf("stats %+v: the filters evicted AS-SMALL's expansion", st)
	}
}
