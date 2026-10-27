package consist

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestRejectsEveryPath(t *testing.T) {
	asR, err := types.ParseSetName("AS-R")
	if err != nil {
		t.Fatal(err)
	}
	asS, err := types.ParseSetName("AS-S")
	if err != nil {
		t.Fatal(err)
	}
	sets := map[types.SetName]resolve.ASNSet{asR: resolve.NewAnyASNSet(), asS: resolve.NewASNSet(1)}
	for _, c := range []struct {
		re   string
		want bool
	}{
		{".", true}, {"AS-ANY", true}, {"AS-R", true}, {".* AS-R .*", true},
		{"[AS1 AS-ANY]", true}, {"[AS-R]", true},
		{"AS1*", true}, {"AS1? AS2?", true},
		{".+", true}, {"(AS1|.)", true}, {"AS1? .", true},
		{"AS1 AS-R", false}, {".* AS64512 .*", false}, {"^.$", false},
		{".{2}", false}, {"[^AS1]", false}, {"AS-S", false}, {"PeerAS", false}, {"AS1", false},
		// Anchored at one end: the unanchored form's answer.
		{"^AS-R", true}, {"AS-R$", true}, {"^.", true}, {".$", true}, {"^", true}, {"$", true},
		{"^AS1*", true}, {"^.* AS-R", true},
		{"^AS1", false}, {"^[AS1 AS2]", false}, {"^AS-R AS1", false}, {"^AS-X", false}, // AS-X: not in sets
		// A top-level alternation, branch by branch.
		{"AS-R$ | AS1$", true}, {"^AS1 | AS-R", true}, {"(AS1|AS2)", false},
		// Anchored at both ends, or anywhere but the top-level edges: not counted.
		{"^$", false}, {"^AS-R+$", false}, {"AS1 ^ AS-R", false}, {"^(^AS-R)", false},
		{"(^AS-R) AS1", false}, {"^(AS-R$)", false},
	} {
		re, err := policy.ParseASPathRegexp(c.re)
		if err != nil {
			t.Fatalf("%q: %v", c.re, err)
		}
		if got := rejectsEveryPath(resolve.PathMatch{Negated: true, RE: re, Sets: sets}); got != c.want {
			t.Errorf("rejectsEveryPath(<%s>) = %v, want %v", c.re, got, c.want)
		}
	}
}

// TestRejectsEveryPathSound holds rejectsEveryPath to the brute-force matcher:
// whenever it says a random regexp rejects every path, routemodel.MatchPath
// accepts every path of one to three ASes over AS1-AS3. An anchor-free regexp
// it counts must also count under one anchor (^(R), (R)$). Each kind of answer
// must come out true at least once, so the test cannot pass by never saying so.
func TestRejectsEveryPathSound(t *testing.T) {
	asR, _ := types.ParseSetName("AS-R")
	asS, _ := types.ParseSetName("AS-S")
	sets := map[types.SetName]resolve.ASNSet{asR: resolve.NewAnyASNSet(), asS: resolve.NewASNSet(1)}
	var paths [][]types.ASN
	var grow func(p []types.ASN)
	grow = func(p []types.ASN) {
		if len(p) > 0 {
			paths = append(paths, p)
		}
		if len(p) < 3 {
			for a := types.ASN(1); a <= 3; a++ {
				grow(append(append([]types.ASN(nil), p...), a))
			}
		}
	}
	grow(nil)

	r := rand.New(rand.NewPCG(1, 0))
	atoms := []string{"AS1", "AS2", ".", "AS-R", "AS-S", "[AS1 AS2]", "[^AS1]"}
	ops := []string{"", "", "*", "+", "?", "{2}"}
	var gen func(depth int) string
	gen = func(depth int) string {
		if depth >= 2 || r.IntN(3) == 0 {
			return atoms[r.IntN(len(atoms))] + ops[r.IntN(len(ops))]
		}
		switch r.IntN(4) {
		case 0:
			return "(" + gen(depth+1) + "|" + gen(depth+1) + ")" + ops[r.IntN(len(ops))]
		case 1: // a group with an anchor inside, at its edge or between terms
			return "(" + []string{"^", ""}[r.IntN(2)] + gen(depth+1) + []string{"$", ""}[r.IntN(2)] + ")"
		default:
			terms := make([]string, 1+r.IntN(3))
			for i := range terms {
				terms[i] = gen(depth + 1)
			}
			if r.IntN(6) == 0 {
				terms[r.IntN(len(terms))] += []string{" ^", " $"}[r.IntN(2)]
			}
			return strings.Join(terms, " ")
		}
	}
	anchor := func(body string) string {
		switch r.IntN(5) {
		case 0:
			return "^" + body
		case 1:
			return body + "$"
		case 2:
			return "^" + body + "$"
		case 3:
			return anchorOne(r) + body + " | " + gen(1) + anchorEnd(r)
		}
		return body
	}
	parse := func(text string) *policy.ASPathRE {
		re, err := policy.ParseASPathRegexp(text)
		if err != nil {
			return nil
		}
		return re
	}
	all := func(re *policy.ASPathRE) bool {
		return rejectsEveryPath(resolve.PathMatch{Negated: true, RE: re, Sets: sets})
	}
	counts := map[string]int{"none": 0, "^": 0, "$": 0, "alt": 0}
	for drawn := 0; drawn < 3000; drawn++ {
		text := anchor(gen(0))
		re := parse(text)
		if re == nil {
			continue
		}
		if !all(re) {
			continue
		}
		for _, p := range paths {
			ok, err := routemodel.MatchPath(resolve.PathMatch{RE: re, Sets: sets}, p)
			if err != nil {
				t.Fatalf("MatchPath(<%s>, %v): %v", text, p, err)
			}
			if !ok {
				t.Fatalf("rejectsEveryPath(<%s>) = true, but the regexp does not match %v", text, p)
			}
		}
		counts[pathKind(re.Body)]++
		if !hasAnchor(re.Body) {
			for _, a := range []string{"^(" + text + ")", "(" + text + ")$"} {
				if are := parse(a); are == nil || !all(are) {
					t.Errorf("rejectsEveryPath(<%s>) = true, but not for <%s>", text, a)
				}
			}
		}
	}
	for kind, n := range counts {
		if n == 0 {
			t.Errorf("no regexp of kind %q was found to reject every path", kind)
		}
	}
	t.Logf("true answers by kind: %v", counts)
}

// anchorOne and anchorEnd give a top-level branch an optional '^' or '$'.
func anchorOne(r *rand.Rand) string { return []string{"^", ""}[r.IntN(2)] }
func anchorEnd(r *rand.Rand) string { return []string{"$", ""}[r.IntN(2)] }

// pathKind names a regexp's anchoring at the top level, for the soundness
// test's counts: "alt" (an alternation holding an anchor), "^", "$", or "none".
func pathKind(e policy.ASPathExpr) string {
	if alt, ok := e.(policy.ASPathAlt); ok && hasAnchor(alt) {
		return "alt"
	}
	ts := []policy.ASPathExpr{e}
	if seq, ok := e.(policy.ASPathSeq); ok {
		ts = seq.Terms
	}
	switch {
	case len(ts) > 0 && ts[0] == policy.ASPathExpr(policy.ASPathStart{}):
		return "^"
	case len(ts) > 0 && ts[len(ts)-1] == policy.ASPathExpr(policy.ASPathEnd{}):
		return "$"
	case hasAnchor(e):
		return "other"
	}
	return "none"
}
