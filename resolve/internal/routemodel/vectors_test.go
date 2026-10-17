package routemodel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// vector is one line of the vectors file routecheck's pathre package reads as
// an oracle: a regexp body (without < >), the sets it names with their
// members, the names of those that reach AS-ANY and so hold every AS
// (resolve.ASNSet.Any; absent when none), an AS path, and the answer. A set
// in "any_sets" is never in "sets": a reader that does not know "any_sets"
// then fails on a set it was not given rather than reading it as empty. The
// literal AS-ANY is in neither; routemodel treats it as any AS. An error
// answer carries "err" and no "match".
type vector struct {
	RE      string              `json:"re"`
	Sets    map[string][]uint32 `json:"sets"`
	AnySets []string            `json:"any_sets,omitempty"`
	Path    []uint32            `json:"path"`
	Match   *bool               `json:"match,omitempty"`
	Err     string              `json:"err,omitempty"`
}

// vectorsVersion is the vectors file's format: 2 added "any_sets".
const vectorsVersion = 2

type vectorHeader struct {
	Version   int    `json:"version"`
	Generator string `json:"generator"`
	Commit    string `json:"rpsl_commit"`
	Seed      int    `json:"seed"`
}

var vectorSets = map[string][]types.ASN{
	"AS-A":     {64501, 64502},
	"AS-EMPTY": {},
}

// vectorAnySets are the sets that reach AS-ANY: in a regexp, any AS.
var vectorAnySets = []string{"AS-ALL"}

func asnsToUint(p []types.ASN) []uint32 {
	out := make([]uint32, len(p))
	for i, a := range p {
		out[i] = uint32(a)
	}
	return out
}

// makeVector evaluates one (regexp, sets, path) with MatchPath. It fails the
// test if the regexp does not parse or the error is not one of the two the
// file can carry.
func makeVector(t *testing.T, body string, withSets bool, path []types.ASN) vector {
	t.Helper()
	r, err := policy.ParseASPathRegexp(body)
	if err != nil {
		t.Fatalf("generated regexp <%s> does not parse: %v", body, err)
	}
	pm := resolve.PathMatch{RE: r}
	v := vector{RE: body, Sets: map[string][]uint32{}, Path: asnsToUint(path)}
	if withSets {
		pm.Sets = map[types.SetName]resolve.ASNSet{}
		for name, members := range vectorSets {
			sn, err := types.ParseSetName(name)
			if err != nil {
				t.Fatal(err)
			}
			pm.Sets[sn] = resolve.NewASNSet(members...)
			v.Sets[name] = asnsToUint(members)
		}
		for _, name := range vectorAnySets {
			sn, err := types.ParseSetName(name)
			if err != nil {
				t.Fatal(err)
			}
			pm.Sets[sn] = resolve.NewAnyASNSet()
			v.AnySets = append(v.AnySets, name)
		}
	}
	got, err := MatchPath(pm, path)
	switch {
	case errors.Is(err, ErrTooComplex):
		v.Err = "too-complex"
	case errors.Is(err, ErrNotSingleAS):
		v.Err = "not-single-as"
	case err != nil:
		t.Fatalf("<%s> on %v: unexpected error %v", body, path, err)
	default:
		v.Match = &got
	}
	return v
}

type vecGen struct{ r *rand.Rand }

func (g vecGen) n(k int) int { return g.r.IntN(k) }

func (g vecGen) as() string { return fmt.Sprintf("AS%d", 64500+g.n(6)) }

func (g vecGen) set() string { return []string{"AS-A", "AS-EMPTY", "AS-ANY", "AS-ALL"}[g.n(4)] }

func (g vecGen) classItem() string {
	switch g.n(4) {
	case 0:
		return g.set()
	case 1:
		lo := 64500 + g.n(6)
		hi := lo + g.n(6-(lo-64500))
		return fmt.Sprintf("AS%d - AS%d", lo, hi)
	}
	return g.as()
}

func (g vecGen) class() string {
	var items []string
	for i, k := 0, 1+g.n(3); i < k; i++ {
		items = append(items, g.classItem())
	}
	neg := ""
	if g.n(3) == 0 {
		neg = "^"
	}
	return "[" + neg + strings.Join(items, " ") + "]"
}

func (g vecGen) quant() string {
	m := g.n(4)
	n := m + g.n(3)
	switch g.n(9) {
	case 0:
		return "*"
	case 1:
		return "+"
	case 2:
		return "?"
	case 3:
		return fmt.Sprintf("{%d}", m)
	case 4:
		return fmt.Sprintf("{%d,%d}", m, n)
	case 5:
		return fmt.Sprintf("{%d,}", m)
	case 6:
		return "~*"
	case 7:
		return "~+"
	}
	return fmt.Sprintf("~{%d,%d}", m, n)
}

func (g vecGen) atom(depth int) string {
	k := 5
	if depth > 0 {
		k = 7
	}
	switch g.n(k) {
	case 0, 1:
		return g.as()
	case 2:
		return "."
	case 3:
		return g.set()
	case 4:
		return g.class()
	}
	return "(" + g.alt(depth-1) + ")"
}

func (g vecGen) seq(depth int) string {
	var items []string
	for i, k := 0, 1+g.n(3); i < k; i++ {
		a := g.atom(depth)
		if g.n(3) == 0 {
			a += g.quant()
		}
		items = append(items, a)
	}
	return strings.Join(items, " ")
}

func (g vecGen) alt(depth int) string {
	parts := []string{g.seq(depth)}
	for g.n(4) == 0 && len(parts) < 3 {
		parts = append(parts, g.seq(depth))
	}
	return strings.Join(parts, " | ")
}

func (g vecGen) regexp() string {
	s := g.alt(4)
	if g.n(3) == 0 {
		s = "^" + s
	}
	if g.n(3) == 0 {
		s += "$"
	}
	return s
}

func (g vecGen) path() []types.ASN {
	p := make([]types.ASN, g.n(9))
	for i := range p {
		p[i] = types.ASN(64500 + g.n(6))
	}
	return p
}

// tooComplex is a regexp with a repetition count in 1001-5000.
func (g vecGen) tooComplex() string {
	c := 1001 + g.n(4000)
	switch g.n(4) {
	case 0:
		return fmt.Sprintf("%s{%d}", g.as(), c)
	case 1:
		return fmt.Sprintf("^%s{%d,}$", g.as(), c)
	case 2:
		return fmt.Sprintf("(%s %s){1,%d}", g.as(), g.as(), c)
	}
	return fmt.Sprintf(".{%d}", c)
}

// TestWriteVectors writes the oracle file routecheck's pathre package checks
// its matcher against. It is skipped unless RPSL_ROUTEMODEL_VECTORS names the
// output path; RPSL_ROUTEMODEL_COMMIT must then hold `git rev-parse HEAD`.
func TestWriteVectors(t *testing.T) {
	out := os.Getenv("RPSL_ROUTEMODEL_VECTORS")
	if out == "" {
		t.Skip("RPSL_ROUTEMODEL_VECTORS names the output file")
	}
	commit := os.Getenv("RPSL_ROUTEMODEL_COMMIT")
	if commit == "" {
		t.Fatal("RPSL_ROUTEMODEL_COMMIT must hold git rev-parse HEAD")
	}
	var vs []vector

	// RFC 2622 section 5.4's examples, each over five paths.
	rfc := []string{"AS3", "^AS1", "AS2$", "^AS1 AS2 AS3$", "^AS1 .* AS2$"}
	rfcPaths := [][]types.ASN{{1, 2, 3}, {3}, {1, 9, 2}, {2, 1}, {}}
	for _, b := range rfc {
		for _, p := range rfcPaths {
			vs = append(vs, makeVector(t, b, false, p))
		}
	}
	for _, c := range matchPathCases {
		v := makeVector(t, c.re, false, c.path)
		if v.Match == nil || *v.Match != c.want {
			t.Fatalf("<%s> on %v: vector %+v disagrees with TestMatchPath's %v", c.re, c.path, v, c.want)
		}
		vs = append(vs, v)
	}

	g := vecGen{rand.New(rand.NewPCG(1, 2))}
	for i := 0; i < 5000; i++ {
		body := g.regexp()
		for j := 0; j < 4; j++ {
			vs = append(vs, makeVector(t, body, true, g.path()))
		}
	}
	nTooComplex := 0
	for i := 0; i < 20; i++ {
		v := makeVector(t, g.tooComplex(), true, g.path())
		if v.Err != "too-complex" {
			t.Fatalf("<%s> was meant to be too complex, got %+v", v.RE, v)
		}
		nTooComplex++
		vs = append(vs, v)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	if err := enc.Encode(vectorHeader{vectorsVersion, "rpsl resolve/internal/routemodel TestWriteVectors", commit, 1}); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors (%d too-complex by construction)", len(vs), nTooComplex)
}
