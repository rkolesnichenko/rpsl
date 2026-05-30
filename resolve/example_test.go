package resolve_test

import (
	"context"
	"fmt"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// decodeObject parses and typed-decodes one RPSL object for use in a corpus.
func decodeObject(text string) object.Object {
	o, _ := rpsl.ParseObject(text)
	obj, _ := object.Decode(o)
	return obj
}

// ExampleExpander expands an as-set into its member ASNs and into the prefixes
// those ASNs originate — entirely in memory, no network. The same Expander code
// runs against a live IRRd/WHOIS Source; only the injected Source differs.
func ExampleExpander() {
	src := resolve.NewMemSource([]object.Object{
		decodeObject("as-set: AS-CONE\nmembers: AS1\nmembers: AS2\nsource: TEST\n"),
		decodeObject("route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"),
		decodeObject("route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n"),
	})

	// AFIv4 drops any IPv6 members; Unspecified/AFIAny would keep both families.
	e := &resolve.Expander{Src: src, AFI: types.AFIv4}

	name, _ := types.ParseSetName("AS-CONE")
	ctx := context.Background()

	asns, _ := e.ExpandAS(ctx, name)
	fmt.Println("ASNs:", asns.List())

	prefixes, _ := e.ExpandPrefixes(ctx, name)
	for _, p := range prefixes.List() {
		fmt.Println("prefix:", p)
	}
	// Output:
	// ASNs: [AS1 AS2]
	// prefix: 10.0.0.0/8
	// prefix: 192.0.2.0/24
}
