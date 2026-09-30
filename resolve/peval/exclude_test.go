package peval

import (
	"context"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// excludeFixture is the final review's F2 probe: AS-BAD holds AS2 only
// through AS-X, RTRS-BAD holds 10.0.0.2 only through RTRS-XR, and AS-OUTER
// holds AS2 only through AS-X.
var excludeFixture = []string{
	`aut-num: AS20
as-name: TWENTY
import: from AS-PEERS EXCEPT AS-BAD accept ANY
import: from AS2 RTRS-ALL EXCEPT RTRS-BAD accept {10.2.0.0/16}
import: from AS-OUTER accept {10.9.0.0/16}
source: TEST
`,
	"as-set: AS-PEERS\nmembers: AS2, AS3\nsource: TEST\n",
	"as-set: AS-BAD\nmembers: AS-X\nsource: TEST\n",
	"as-set: AS-X\nmembers: AS2\nsource: TEST\n",
	"as-set: AS-OUTER\nmembers: AS-X\nsource: TEST\n",
	"rtr-set: RTRS-ALL\nmembers: 10.0.0.1, 10.0.0.2\nsource: TEST\n",
	"rtr-set: RTRS-BAD\nmembers: RTRS-XR\nsource: TEST\n",
	"rtr-set: RTRS-XR\nmembers: 10.0.0.2\nsource: TEST\n",
}

// Expander.Exclude never changes which terms cover a session (F2 of the final
// review): it narrows a clause's filter, but an excluded set is still in full
// on both sides of a peering's or router expression's EXCEPT, so excluding
// AS-X must not turn "AS-PEERS EXCEPT AS-BAD" into a match for AS2.
func TestExcludeLeavesPeeringsAlone(t *testing.T) {
	var objs []object.Object
	for _, s := range excludeFixture {
		raw, _ := rpsl.ParseObject(s)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	src := resolve.NewMemSource(objs)
	ex := resolve.Exclusion{Sets: []types.SetName{mustName(t, "AS-X"), mustName(t, "RTRS-XR")}}
	s := Session{Local: 20, Peer: 2, PeerRtr: addr("10.0.0.2"), AF: v4}
	clauses := func(e resolve.Expander) []string {
		p, err := (&Evaluator{Src: src, Expander: e}).Import(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range p.Clauses {
			out = append(out, c.Term.String()+" => "+c.Filter.String())
		}
		return out
	}
	without, with := clauses(resolve.Expander{}), clauses(resolve.Expander{Exclude: ex})
	if len(without) != 1 || len(with) != len(without) || with[0] != without[0] {
		t.Errorf("clauses without Exclude %q, with it %q; want the same one clause", without, with)
	}
	for _, p := range []string{"AS-PEERS EXCEPT AS-BAD", "AS2 RTRS-ALL EXCEPT RTRS-BAD", "AS-OUTER"} {
		want := noMatch
		if p == "AS-OUTER" {
			want = match
		}
		c := (&Evaluator{Src: src, Expander: resolve.Expander{Exclude: ex}}).newCall(context.Background(), s)
		if got, _, err := c.peering(peering(t, p)); err != nil || got != want {
			t.Errorf("%s with AS-X and RTRS-XR excluded = %v, %v; want %v", p, got, err, want)
		}
	}
}

func mustName(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
