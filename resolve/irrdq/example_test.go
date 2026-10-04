package irrdq_test

import (
	"context"
	"os"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
)

// A registry built from RPSL text answers IRRd's commands as IRRd does.
func Example() {
	c := &resolve.Corpus{KeepPolicy: true}
	for _, text := range []string{
		"as-set: AS-X\nmembers: AS1, AS-Y\nsource: RIPE\n",
		"as-set: AS-Y\nmembers: AS2\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS2\nsource: RIPE\n",
	} {
		o, _ := rpsl.ParseObject(text)
		obj, _ := rpsl.Decode(o)
		c.Put(obj)
	}
	reg, _ := irrdq.NewRegistry("RIPE", 1, c)
	snap, _ := irrdq.NewSnapshot([]*irrdq.Registry{reg}, irrdq.SnapshotOptions{})
	s := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
	for _, cmd := range []string{"!!", "!iAS-X,1", "!aAS-X", "!j-*"} {
		r, _ := s.Do(context.Background(), cmd)
		r.WriteTo(os.Stdout)
	}
	// Output:
	// A8
	// AS1 AS2
	// C
	// A13
	// 192.0.2.0/24
	// C
	// A11
	// RIPE:N:0-1
	// C
}
