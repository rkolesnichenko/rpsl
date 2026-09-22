package irrd_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/types"
)

// ExampleSource expands an as-set against RADB's IRRd query port, preferring
// RIPE's objects where both registries hold a set. It needs the network, so it
// is compiled but not run by go test.
func ExampleSource() {
	src := &irrd.Source{
		Addr:      "whois.radb.net:43",
		Sources:   []string{"RIPE", "RADB"},
		Timeout:   30 * time.Second,
		KeepAlive: true, // reuse connections across the many queries of an expansion
	}
	defer src.Close()

	set, err := types.ParseSetName("AS-RIPENCC")
	if err != nil {
		log.Fatal(err)
	}
	e := &resolve.Expander{Src: src, AFI: types.AFIv4}
	prefixes, err := e.ExpandPrefixes(context.Background(), set)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(prefixes.Len(), "prefixes; nested sets not found:", prefixes.Missing())
}
