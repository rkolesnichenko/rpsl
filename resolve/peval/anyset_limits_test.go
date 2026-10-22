package peval

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// textSource is a MemSource holding the objects of texts.
func textSource(t *testing.T, texts ...string) *resolve.MemSource {
	t.Helper()
	var objs []object.Object
	for _, s := range texts {
		raw, _ := rpsl.ParseObject(s)
		o, ds := rpsl.Decode(raw)
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("%q: %v", s, d)
			}
		}
		objs = append(objs, o)
	}
	return resolve.NewMemSource(objs)
}

// A set reaching AS-ANY is decided the same way in a peering (AS1's
// "from AS-X") and in an AS-path regexp (AS2's "<AS-X>"): discovery stops after
// the level reaching AS-ANY in both, so at each MaxDepth both decide or both
// are over the limit. MaxVisited stays at its default: a regexp is charged
// on the normalizer's budget, a peering is not, so the two cannot agree on it
// at the margin.
func TestAnySetPeeringAndRegexpAgree(t *testing.T) {
	asSet := func(name, members string) string {
		return "as-set: " + name + "\nmembers: " + members + "\nsource: TEST\n"
	}
	chain := func() []string {
		var out []string
		for i := 1; i <= 6; i++ {
			next := fmt.Sprintf("AS-C%d", i+1)
			if i == 6 {
				next = "AS5"
			}
			out = append(out, asSet(fmt.Sprintf("AS-C%d", i), next))
		}
		return out
	}
	autNums := []string{
		"aut-num: AS1\nas-name: ONE\nimport: from AS-X accept ANY\nsource: TEST\n",
		"aut-num: AS2\nas-name: TWO\nimport: from AS5 accept <AS-X>\nsource: TEST\n",
	}
	// deepest is the MaxDepth from which both decide: the depth of the
	// reference to AS-ANY.
	graphs := []struct {
		name    string
		sets    []string
		deepest int
	}{
		{"a: AS-ANY shallow, deep sibling", append([]string{asSet("AS-X", "AS-ANY, AS-C1")}, chain()...), 1},
		{"b: AS-ANY deep", []string{
			asSet("AS-X", "AS-D1"),
			asSet("AS-D1", "AS-D2"),
			asSet("AS-D2", "AS-ANY"),
		}, 3},
		{"c: a reversed", append([]string{asSet("AS-X", "AS-C1, AS-ANY")}, chain()...), 1},
	}
	ctx := context.Background()
	for _, g := range graphs {
		src := textSource(t, append(append([]string{}, autNums...), g.sets...)...)
		for depth := 1; depth <= 7; depth++ {
			v := &Evaluator{Src: src, Expander: resolve.Expander{MaxDepth: depth}}
			var outcome [2]string
			for i, local := range []uint32{1, 2} {
				p, err := v.Import(ctx, Session{Local: types.ASN(local), Peer: 5, AF: v4})
				var tl *resolve.SetTooLargeError
				switch {
				case errors.As(err, &tl):
					outcome[i] = "over " + tl.Limit.String()
				case err != nil:
					t.Fatalf("%s, MaxDepth %d, AS%d: %v", g.name, depth, local, err)
				case len(p.Clauses) == 1:
					outcome[i] = "decided"
				default:
					t.Fatalf("%s, MaxDepth %d, AS%d: %s; want one clause", g.name, depth, local, summary(p))
				}
			}
			want := "decided"
			if depth < g.deepest {
				want = "over " + resolve.LimitDepth.String()
			}
			if outcome[0] != want || outcome[1] != want {
				t.Errorf("%s, MaxDepth %d: peering %s, regexp %s; want both %s",
					g.name, depth, outcome[0], outcome[1], want)
			}
		}
	}
}
