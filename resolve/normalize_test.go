package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

func normCorpus(t *testing.T) *MemSource {
	return corpus(t,
		"route: 10.1.0.0/16\norigin: AS1\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS2\nsource: TEST\n",
		"route6: 2001:db8:1::/48\norigin: AS1\nsource: TEST\n",
		asSet("AS-A", "AS1", "AS2"),
		routeSet("RS-A", "10.9.0.0/16"),
		fltrSet("FLTR-PLAIN", "{10.8.0.0/16}"),
		fltrSet("FLTR-RE", "AS1 AND <^AS1$>"),
		fltrSet("FLTR-NEST", "FLTR-RE OR {10.7.0.0/16}"),
		fltrSet("FLTR-LOOP-A", "<AS1> OR FLTR-LOOP-B"),
		fltrSet("FLTR-LOOP-B", "FLTR-LOOP-A"),
		fltrSet("FLTR-X", "AS1 OR AS2"),
		fltrSet("FLTR-DENY", "AS-A"),
	)
}

// normalizes checks that each filter normalizes to the given text, and that
// the text normalizes to itself.
func normalizes(t *testing.T, e *Expander, cases map[string]string) {
	t.Helper()
	ctx := context.Background()
	for filter, want := range cases {
		nf, err := e.NormalizeFilter(ctx, mustFilter(t, filter))
		if err != nil || nf.String() != want {
			t.Errorf("NormalizeFilter(%s) = %q, %v; want %q", filter, nf.String(), err, want)
			continue
		}
		again, err := e.NormalizeFilter(ctx, mustFilter(t, nf.String()))
		if err != nil || again.String() != want {
			t.Errorf("NormalizeFilter(%s) = %q, %v; its own text normalizes to %q", filter, want, err, again.String())
		}
	}
}

func TestNormalizeFilter(t *testing.T) {
	src := normCorpus(t)
	normalizes(t, &Expander{Src: src, AFI: types.AFIv4}, map[string]string{
		"AS1":                           "{10.1.0.0/16}",
		"ANY":                           "ANY",
		"AS-A AND NOT AS2":              "{10.1.0.0/16}",
		"AS-A AND NOT {10.2.0.0/16^+}":  "{10.1.0.0/16}",
		"{10.0.0.0/8^+} AND NOT AS2":    "{10.0.0.0/8^+} AND NOT {10.2.0.0/16}",
		"NOT AS1":                       "NOT {10.1.0.0/16}",
		"community(1:2)":                "community(1:2)",
		"NOT community(1:2)":            "NOT community(1:2)",
		"AS1 AND community(1:2)":        "{10.1.0.0/16} AND community(1:2)",
		"NOT (AS1 OR community(1:2))":   "NOT {10.1.0.0/16} AND NOT community(1:2)",
		"community == {1:2, no_export}": "community == {1:2, no_export}",
		"(AS1 OR community(1:1)) AND (AS2 OR community(1:2))": "({10.1.0.0/16} AND community(1:2)) OR " +
			"({10.2.0.0/16} AND community(1:1)) OR (community(1:1) AND community(1:2))",
	})
	normalizes(t, &Expander{Src: src, AFI: types.AFIv6}, map[string]string{
		"AS1": "{2001:db8:1::/48}",
		"ANY": "ANY",
	})
}

// A filter that matches nothing is no conjuncts, written NOT ANY — never an
// empty prefix list a printer could take for no constraint.
func TestNormalizeMatchesNothing(t *testing.T) {
	e := &Expander{Src: normCorpus(t), AFI: types.AFIv4}
	for _, filter := range []string{"NOT ANY", "AS-GONE", "AS1 AND AS2", "AS-GONE AND community(1:1)", "{}"} {
		nf, err := e.NormalizeFilter(context.Background(), mustFilter(t, filter))
		if err != nil || len(nf.Conjuncts) != 0 || nf.String() != "NOT ANY" {
			t.Errorf("NormalizeFilter(%s) = %q (%d conjuncts), %v; want NOT ANY", filter, nf.String(), len(nf.Conjuncts), err)
		}
	}
	nf, _ := e.NormalizeFilter(context.Background(), mustFilter(t, "AS-GONE OR AS1"))
	if got := nf.Missing(); len(got) != 1 || got[0].String() != "AS-GONE" {
		t.Errorf("NormalizeFilter(AS-GONE OR AS1).Missing() = %v, want [AS-GONE]", got)
	}
}

func TestNormalizeRegexps(t *testing.T) {
	src := normCorpus(t)
	e := &Expander{Src: src, AFI: types.AFIv4}
	normalizes(t, e, map[string]string{
		"AS1 AND <^AS1$>":  "{10.1.0.0/16} AND <^ AS1 $>",
		"<AS-A> OR AS2":    "{10.2.0.0/16} OR <AS-A>",
		"NOT <AS1>":        "NOT <AS1>",
		"<AS-ANY>":         "<AS-ANY>",
		"AS-ANY AND <AS1>": "<AS1>",
	})
	nf, err := e.NormalizeFilter(context.Background(), mustFilter(t, "<AS-A> OR AS2"))
	if err != nil {
		t.Fatal(err)
	}
	set := nf.Conjuncts[1].Paths[0].Sets[mustSet(t, "AS-A")]
	if !set.Has(1) || !set.Has(2) || set.Len() != 2 {
		t.Errorf("<AS-A>: Sets[AS-A] = %v, want AS1 and AS2", set.List())
	}
	nf, _ = e.NormalizeFilter(context.Background(), mustFilter(t, "<AS-ANY>"))
	if len(nf.Conjuncts[0].Paths[0].Sets) != 0 {
		t.Errorf("<AS-ANY>: AS-ANY was expanded: %v", nf.Conjuncts[0].Paths[0].Sets)
	}

	bound := &Expander{Src: src, AFI: types.AFIv4, Peer: 2}
	nf, err = bound.NormalizeFilter(context.Background(), mustFilter(t, "<PeerAS AS1:AS-CUST:PeerAS>"))
	if err != nil || nf.String() != "<AS2 AS1:AS-CUST:AS2>" {
		t.Errorf("<PeerAS AS1:AS-CUST:PeerAS> for AS2 = %q, %v", nf.String(), err)
	}
	if m := nf.Missing(); len(m) != 1 || m[0].String() != "AS1:AS-CUST:AS2" {
		t.Errorf("Missing() = %v, want [AS1:AS-CUST:AS2]", m)
	}
	if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, "<PeerAS>")); !errors.Is(err, ErrUnboundPeer) {
		t.Errorf("<PeerAS> unbound: err %v, want ErrUnboundPeer", err)
	}
	var ne *NotEnumerableError
	if _, err := e.NormalizeFilter(context.Background(), policy.FilterPathRE{Raw: "AS1 ["}); !errors.As(err, &ne) {
		t.Errorf("an unparsed regexp: err %v, want *NotEnumerableError", err)
	}
}

// A filter-set with a regexp or community test inside is inlined; with a
// range operator, or on a cycle, it is refused by name, never dropped.
func TestNormalizeSymbolicFilterSets(t *testing.T) {
	src := normCorpus(t)
	e := &Expander{Src: src, AFI: types.AFIv4}
	normalizes(t, e, map[string]string{
		"FLTR-PLAIN":     "{10.8.0.0/16}",
		"FLTR-RE":        "{10.1.0.0/16} AND <^ AS1 $>",
		"FLTR-NEST":      "{10.7.0.0/16} OR ({10.1.0.0/16} AND <^ AS1 $>)",
		"NOT FLTR-RE":    "NOT {10.1.0.0/16} OR NOT <^ AS1 $>",
		"RS-A OR AS-ANY": "ANY",
	})
	// A filter-set on a cycle is refused by name.
	_, err := e.NormalizeFilter(context.Background(), mustFilter(t, "FLTR-LOOP-A"))
	var ne *NotEnumerableError
	if !errors.As(err, &ne) || !strings.Contains(ne.Term, "FLTR-LOOP") {
		t.Errorf("NormalizeFilter(FLTR-LOOP-A): err %v, want a *NotEnumerableError naming FLTR-LOOP", err)
	}
	// A filter-set referenced with a range operator is refused by name too.
	// ParseFilter itself refuses a range operator on a plain filter-set name
	// (policy/range-op: "a filter-set takes no range operator"), so this half
	// of the rule is exercised by constructing the AST directly — as
	// TestEvalFilterASExpressions does for RFC 2622's binary AS expressions,
	// which the filter grammar likewise cannot spell directly.
	op, err := types.ParseRangeOperator("+")
	if err != nil {
		t.Fatal(err)
	}
	withOp := policy.FilterSetRef{Name: mustSet(t, "FLTR-RE"), Op: op}
	if _, err := e.NormalizeFilter(context.Background(), withOp); !errors.As(err, &ne) || !strings.Contains(ne.Term, "FLTR-RE") {
		t.Errorf("NormalizeFilter(FLTR-RE^+): err %v, want a *NotEnumerableError naming FLTR-RE", err)
	}
	ex := &Expander{Src: src, AFI: types.AFIv4, Exclude: Exclusion{ASNs: []types.ASN{1}}}
	if nf, err := ex.NormalizeFilter(context.Background(), mustFilter(t, "FLTR-RE")); err != nil || nf.String() != "NOT ANY" {
		t.Errorf("FLTR-RE with AS1 excluded = %q, %v; want NOT ANY", nf.String(), err)
	}
}

func TestNormalizeMaxConjuncts(t *testing.T) {
	src := normCorpus(t)
	f := mustFilter(t, "(community(1:1) OR community(1:2)) AND (community(1:3) OR community(1:4))")
	ctx := context.Background()
	nf, peak, err := NormalizePeak(&Expander{Src: src}, ctx, f)
	if err != nil || len(nf.Conjuncts) != 4 || peak != 4 {
		t.Fatalf("NormalizeFilter = %d conjuncts, peak %d, %v; want 4, 4", len(nf.Conjuncts), peak, err)
	}
	if _, err := (&Expander{Src: src, MaxConjuncts: 4}).NormalizeFilter(ctx, f); err != nil {
		t.Errorf("MaxConjuncts 4: %v", err)
	}
	_, err = (&Expander{Src: src, MaxConjuncts: 3}).NormalizeFilter(ctx, f)
	var tl *SetTooLargeError
	if !errors.As(err, &tl) || tl.Limit != LimitConjuncts || tl.Limit.String() != "MaxConjuncts" {
		t.Errorf("MaxConjuncts 3: err %v, want *SetTooLargeError{Limit: LimitConjuncts}", err)
	}
}

// TestNormalizeExcludeUnderNot is fix round 1: Exclude only ever narrows what
// a filter accepts. Before the fix, excluding AS1 turned NOT of a filter
// naming it into an admission of AS1's routes — a positive literal correctly
// drops an excluded AS's routes, but the same exclusion, carried unchanged
// into a negated literal's complement, dropped the excluded AS from the deny
// side too, admitting it instead of rejecting it. FLTR-X = "AS1 OR AS2" and
// FLTR-DENY = "AS-A" (AS-A = AS1, AS2) are the reviewer's two probes.
func TestNormalizeExcludeUnderNot(t *testing.T) {
	src := normCorpus(t)
	e := &Expander{Src: src, AFI: types.AFIv4, Exclude: Exclusion{ASNs: []types.ASN{1}}}
	normalizes(t, e, map[string]string{
		// Both probes must reject AS1's route, not admit it: the deny side is
		// complete regardless of Exclude.
		"NOT FLTR-X":            "NOT {10.1.0.0/16, 10.2.0.0/16}",
		"ANY AND NOT FLTR-DENY": "NOT {10.1.0.0/16, 10.2.0.0/16}",
		"NOT (AS1 OR AS2)":      "NOT {10.1.0.0/16, 10.2.0.0/16}",
		// The positive counterpart is unaffected: it must still drop AS1.
		"FLTR-X": "{10.2.0.0/16}",
	})

	ctx := context.Background()
	// A negated AS-path regexp's Sets must hold the excluded AS too, so a
	// printer that writes NOT <AS-A> out as a router config still rejects
	// paths through AS1.
	nf, err := e.NormalizeFilter(ctx, mustFilter(t, "NOT <AS-A>"))
	if err != nil {
		t.Fatal(err)
	}
	set := nf.Conjuncts[0].Paths[0].Sets[mustSet(t, "AS-A")]
	if !set.Has(1) || !set.Has(2) || set.Len() != 2 {
		t.Errorf("NOT <AS-A>: Sets[AS-A] = %v, want AS1 and AS2", set.List())
	}

	// The positive form keeps it too (F2 of the final review): Exclude never
	// reaches inside an AS-path regexp, in either polarity. A set inside
	// "[^…]" is on the rejecting side even in a positive regexp, so leaving
	// AS1 out of AS-A there would make <[^AS-A]> and <^[^AS-A]*$> accept a
	// path through AS1 that they reject without Exclude. This used to assert
	// Sets[AS-A] = {AS2}.
	for _, f := range []string{"<AS-A>", "<[^AS-A]>", "<^[^AS-A]*$>"} {
		nf, err = e.NormalizeFilter(ctx, mustFilter(t, f))
		if err != nil {
			t.Fatal(err)
		}
		set = nf.Conjuncts[0].Paths[0].Sets[mustSet(t, "AS-A")]
		if !set.Has(1) || !set.Has(2) || set.Len() != 2 {
			t.Errorf("%s: Sets[AS-A] = %v, want AS1 and AS2", f, set.List())
		}
	}
}

// andChain is the final review's probe: FLTR-L0 … FLTR-L<levels>, each level
// the 4-way AND of the next, the last <AS1>. Inlined naively it is 4^levels
// copies of one test in one conjunct (10 levels: 1,048,576 paths, 1.6 GB).
func andChain(levels int) []string {
	var texts []string
	for k := 0; k < levels; k++ {
		next := fmt.Sprintf("FLTR-L%d", k+1)
		texts = append(texts, fltrSet(fmt.Sprintf("FLTR-L%d", k), next+" AND "+next+" AND "+next+" AND "+next))
	}
	return append(texts, fltrSet(fmt.Sprintf("FLTR-L%d", levels), "<AS1>"))
}

// TestNormalizeRepeatedFilterSets is F1 of the final review: a filter-set
// referenced many times is inlined once per polarity, and a test repeated in
// a conjunct is kept once, so the probe is one conjunct of one path.
func TestNormalizeRepeatedFilterSets(t *testing.T) {
	for _, levels := range []int{10, 20} {
		t.Run(fmt.Sprint(levels), func(t *testing.T) {
			// Each level nests two deep (the set, then its AND), so 20 levels
			// need more than the default MaxDepth.
			e := &Expander{Src: corpus(t, andChain(levels)...), AFI: types.AFIv4, MaxDepth: 4 * levels}
			nf, err := e.NormalizeFilter(context.Background(), mustFilter(t, "FLTR-L0"))
			if err != nil || len(nf.Conjuncts) != 1 || len(nf.Conjuncts[0].Paths) != 1 || nf.String() != "<AS1>" {
				t.Fatalf("NormalizeFilter(FLTR-L0) = %q (%d conjuncts), %v; want one conjunct of one path, <AS1>", nf.String(), len(nf.Conjuncts), err)
			}
			// Negated, each AND is a union of four equal disjunctions, which
			// only finish deduplicates: MaxConjuncts refuses it, quickly.
			var tl *SetTooLargeError
			if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, "NOT FLTR-L0")); !errors.As(err, &tl) || tl.Limit != LimitConjuncts {
				t.Errorf("NormalizeFilter(NOT FLTR-L0): err %v, want *SetTooLargeError{Limit: LimitConjuncts}", err)
			}
			allocs := testing.AllocsPerRun(1, func() {
				if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, "FLTR-L0")); err != nil {
					t.Fatal(err)
				}
			})
			if allocs > float64(2000*levels) {
				t.Errorf("NormalizeFilter(FLTR-L0) over %d levels: %.0f allocations", levels, allocs)
			}
		})
	}
	e := &Expander{Src: normCorpus(t), AFI: types.AFIv4}
	normalizes(t, e, map[string]string{
		"<AS1> AND <AS1>":                             "<AS1>",
		"<AS1> AND NOT <AS1>":                         "<AS1> AND NOT <AS1>",
		"community(1:2) AND community(1:2) AND <AS1>": "<AS1> AND community(1:2)",
		"(FLTR-RE AND FLTR-RE) OR FLTR-RE":            "{10.1.0.0/16} AND <^ AS1 $>",
	})
}

// binaryTree is filter-sets FLTR-T (the root) down to 2^levels leaves, each a
// distinct regexp <AS1>, <AS2>, …, joined by AND: its one conjunct genuinely
// holds 2^levels tests.
func binaryTree(levels int) []string {
	var texts []string
	var walk func(name string, k int)
	leaf := 0
	walk = func(name string, k int) {
		if k == levels {
			leaf++
			texts = append(texts, fltrSet(name, fmt.Sprintf("<AS%d>", leaf)))
			return
		}
		texts = append(texts, fltrSet(name, name+"-0 AND "+name+"-1"))
		walk(name+"-0", k+1)
		walk(name+"-1", k+1)
	}
	walk("FLTR-T", 0)
	return texts
}

// A conjunct over MaxConjuncts tests is refused, and every step of the
// normalization is charged against MaxVisited: a filter whose tests multiply
// is a *SetTooLargeError, never a runaway.
func TestNormalizeBoundsTests(t *testing.T) {
	src := corpus(t, binaryTree(5)...) // 63 filter-sets, 32 leaves
	ctx := context.Background()
	f := mustFilter(t, "FLTR-T")
	nf, peak, err := NormalizePeak(&Expander{Src: src}, ctx, f)
	if err != nil || len(nf.Conjuncts) != 1 || len(nf.Conjuncts[0].Paths) != 32 || peak != 32 {
		t.Fatalf("NormalizeFilter(FLTR-T) = %d conjuncts, peak %d, %v; want one of 32 paths, peak 32", len(nf.Conjuncts), peak, err)
	}
	if _, err := (&Expander{Src: src, MaxConjuncts: 32}).NormalizeFilter(ctx, f); err != nil {
		t.Errorf("MaxConjuncts 32: %v", err)
	}
	var tl *SetTooLargeError
	_, err = (&Expander{Src: src, MaxConjuncts: 31}).NormalizeFilter(ctx, f)
	if !errors.As(err, &tl) || tl.Limit != LimitConjuncts {
		t.Errorf("MaxConjuncts 31: err %v, want *SetTooLargeError{Limit: LimitConjuncts}", err)
	}
	// Fetching the 63 sets alone is 63 visits; normalizing them is more.
	_, err = (&Expander{Src: src, MaxVisited: 100}).NormalizeFilter(ctx, f)
	if !errors.As(err, &tl) || tl.Limit != LimitVisited {
		t.Errorf("MaxVisited 100: err %v, want *SetTooLargeError{Limit: LimitVisited}", err)
	}
	// Thirteen levels of distinct leaves under the default limits.
	deep := &Expander{Src: corpus(t, binaryTree(13)...)}
	if _, err := deep.NormalizeFilter(ctx, f); !errors.As(err, &tl) || tl.Limit != LimitConjuncts && tl.Limit != LimitVisited {
		t.Errorf("a tree of 8,192 distinct leaves: err %v, want *SetTooLargeError", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (&Expander{Src: src}).NormalizeFilter(cancelled, f); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: err %v", err)
	}
}

// The memo of inlined filter-sets keeps each set's height, so MaxDepth holds
// the same whichever order the terms come in.
func TestNormalizeMaxDepthIsOrderIndependent(t *testing.T) {
	src := corpus(t,
		fltrSet("FLTR-A", "<AS1>"),
		fltrSet("FLTR-N3", "FLTR-A"),
		fltrSet("FLTR-N2", "FLTR-N3"),
		fltrSet("FLTR-N1", "FLTR-N2"),
		fltrSet("FLTR-N0", "FLTR-N1"),
	)
	e := &Expander{Src: src, AFI: types.AFIv4, MaxDepth: 5}
	for _, filter := range []string{"FLTR-N0 OR FLTR-A", "FLTR-A OR FLTR-N0"} {
		_, err := e.NormalizeFilter(context.Background(), mustFilter(t, filter))
		var tl *SetTooLargeError
		if !errors.As(err, &tl) || tl.Limit != LimitDepth {
			t.Errorf("NormalizeFilter(%s) at MaxDepth 5: err %v, want LimitDepth", filter, err)
		}
	}
	deep := &Expander{Src: src, AFI: types.AFIv4, MaxDepth: 32}
	for _, filter := range []string{"FLTR-N0 OR FLTR-A", "FLTR-A OR FLTR-N0"} {
		if nf, err := deep.NormalizeFilter(context.Background(), mustFilter(t, filter)); err != nil || nf.String() != "<AS1>" {
			t.Errorf("NormalizeFilter(%s) at MaxDepth 32 = %q, %v; want <AS1>", filter, nf, err)
		}
	}
}

// The test cap counts only conjuncts that survive the prefix intersection.
func TestNormalizeTestCapAfterIntersection(t *testing.T) {
	src := corpus(t,
		fltrSet("FLTR-P", "{10.1.0.0/16} AND <AS1> AND <AS2>"),
		fltrSet("FLTR-Q", "{10.2.0.0/16} AND <AS3>"),
	)
	ctx := context.Background()
	f := mustFilter(t, "FLTR-P AND FLTR-Q")
	nf, peak, err := NormalizePeak(&Expander{Src: src, AFI: types.AFIv4, MaxConjuncts: 2}, ctx, f)
	if err != nil || nf.String() != "NOT ANY" {
		t.Fatalf("FLTR-P AND FLTR-Q at MaxConjuncts 2 = %q, %v; want NOT ANY", nf, err)
	}
	if peak > 2 {
		t.Errorf("peak %d counts a conjunct that was dropped", peak)
	}
}
