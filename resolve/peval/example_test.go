package peval_test

import (
	"context"
	"fmt"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

func ExampleEvaluator_Import() {
	var objs []object.Object
	for _, s := range []string{
		"aut-num: AS1\nas-name: ONE\nimport: from AS2 action pref = 10; accept AS2 AND NOT {10.2.99.0/24}\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS2\nsource: TEST\n",
	} {
		raw, _ := rpsl.ParseObject(s)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	v := &peval.Evaluator{Src: resolve.NewMemSource(objs)}
	p, err := v.Import(context.Background(), peval.Session{
		Local: 1, Peer: 2, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast},
	})
	if err != nil {
		panic(err)
	}
	for _, c := range p.Clauses {
		fmt.Println(c.Actions[0], "|", c.Filter)
	}
	// Output: pref = 10 | {10.2.0.0/16}
}
