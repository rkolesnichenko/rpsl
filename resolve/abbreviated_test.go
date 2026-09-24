package resolve_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/types"
)

// A route-set member and a route written with an abbreviated IPv4 prefix
// ("191.243.44/22") expand to the zero-filled prefix, from memory and over
// the IRRd protocol alike, as IRRd itself reads them.
func TestAbbreviatedPrefixMembers(t *testing.T) {
	texts := []string{
		"route-set: RS-S\nmembers: 191.243.44/22, AS2\nsource: RADB\n",
		"route: 143.208.148/22\norigin: AS2\nsource: RADB\n",
	}
	var objs []object.Object
	for _, s := range texts {
		o, _ := rpsl.ParseObject(s)
		obj, _ := rpsl.Decode(o)
		objs = append(objs, obj)
	}
	ir := &irrd.Source{Addr: irrtest.New(texts...).WithSources("RADB").IRRd(t), Sources: []string{"RADB"}, Timeout: 5 * time.Second}
	defer ir.Close()
	name, _ := types.ParseSetName("RS-S")
	for label, src := range map[string]resolve.Source{"memory": resolve.NewMemSource(objs), "irrd": ir} {
		got, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), name)
		if err != nil || fmt.Sprint(got.List()) != "[143.208.148.0/22 191.243.44.0/22]" {
			t.Errorf("%s: ExpandPrefixes(RS-S) = %v, %v; want [143.208.148.0/22 191.243.44.0/22]", label, got.List(), err)
		}
	}
}
