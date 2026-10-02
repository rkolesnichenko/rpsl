package consist_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// A customer announces ANY to its provider, which accepts only the
// customer's own routes: the provider refuses the rest.
func Example() {
	var objs []object.Object
	for _, text := range []string{
		"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n",
		"as-set: AS-ONE\nmembers: AS1\nsource: RIPE\n",
		"aut-num: AS1\nexport: to AS2 announce ANY\nsource: RIPE\n",
		"aut-num: AS2\nimport: from AS1 accept AS-ONE\nsource: RIPE\n",
	} {
		raw, _ := rpsl.ParseObject(text)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	c := &consist.Checker{Eval: peval.Evaluator{Src: resolve.NewMemSource(objs)}}
	rep, err := c.Check(context.Background(), consist.Pair{A: 1, B: 2, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}})
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, f := range rep.AtoB.Findings {
		var ranges []string
		for _, r := range f.Ranges[:3] {
			ranges = append(ranges, r.String())
		}
		fmt.Printf("%s→%s: %v (%v), e.g. %v; %s, …\n", rep.AtoB.From, rep.AtoB.To, f.Kind, f.Severity, f.Example, strings.Join(ranges, ", "))
	}
	// Output:
	// AS1→AS2: not-imported (warning), e.g. 0.0.0.0/0; 0.0.0.0/0^0-15, 0.0.0.0/0^17-32, 0.0.0.0/5^16, …
}
