package resolve

import (
	"context"
	"errors"
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
