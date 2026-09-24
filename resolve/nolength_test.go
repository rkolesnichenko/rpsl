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

// A route-set member written as an address without a length ("206.197.238.0",
// in ARIN's rs-HCHBNET) expands to the host prefix, from memory and over the
// IRRd protocol alike. IRRd stores such a member with its length, so irrtest
// answers "!i" and "!i…,1" with "/32" and "/128" as rr.arin.net does.
func TestNoLengthMembers(t *testing.T) {
	texts := []string{
		"route-set: RS-S\nmembers: 206.197.238.0, 192.0.2.0/24\nmp-members: 2001:db8::32^+\nsource: ARIN\n",
	}
	var objs []object.Object
	for _, s := range texts {
		o, _ := rpsl.ParseObject(s)
		obj, _ := rpsl.Decode(o)
		objs = append(objs, obj)
	}
	db := irrtest.New(texts...).WithSources("ARIN")
	if got, _ := db.Members(nil, "RS-S"); fmt.Sprint(got) != "[206.197.238.0/32 192.0.2.0/24 2001:db8::32/128^+]" {
		t.Errorf(`irrtest "!iRS-S" = %v; want the lengths IRRd adds`, got)
	}
	ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"ARIN"}, Timeout: 5 * time.Second}
	defer ir.Close()
	name, _ := types.ParseSetName("RS-S")
	const want = "[192.0.2.0/24 206.197.238.0/32 2001:db8::32/128]"
	for label, src := range map[string]resolve.Source{"memory": resolve.NewMemSource(objs), "irrd": ir} {
		got, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), name)
		if err != nil || fmt.Sprint(got.List()) != want {
			t.Errorf("%s: ExpandPrefixes(RS-S) = %v, %v; want %s", label, got.List(), err, want)
		}
	}
}
