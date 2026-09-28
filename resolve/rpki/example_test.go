package rpki_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// ExampleFilter expands an as-set as an RPKI-aware IRRd would: AS64501's route
// inside AS64500's ROA is invalid and suppressed, and the ROA itself is served
// as a pseudo route from the registry RPKI.
func ExampleFilter() {
	const dump = `as-set:  AS-CONE
members: AS64500, AS64501
source:  TEST

route:   192.0.2.0/24
origin:  AS64500
source:  TEST

route:   192.0.2.128/25
origin:  AS64501
source:  TEST
`
	vrps, err := rpki.ReadJSON(strings.NewReader(`{"roas": [
		{"asn": "AS64500", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "example"},
		{"asn": "AS64500", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "example"}]}`))
	if err != nil {
		panic(err)
	}
	var pseudo strings.Builder
	if err := vrps.WriteRPSL(&pseudo); err != nil {
		panic(err)
	}

	l := &resolve.DumpLoader{}
	for _, text := range []string{dump, pseudo.String()} {
		if err := l.Read(strings.NewReader(text)); err != nil {
			panic(err)
		}
	}
	e := &resolve.Expander{Src: &rpki.Filter{Src: l.Source(), VRPs: vrps}}
	name, _ := types.ParseSetName("AS-CONE")
	ps, err := e.ExpandPrefixes(context.Background(), types.Ref(name))
	if err != nil {
		panic(err)
	}
	fmt.Println(ps.List())
	// Output: [192.0.2.0/24 198.51.100.0/24]
}
