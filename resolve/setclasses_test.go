package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// Every set class expands over the live backends as it does from memory. The
// IRRd backend knew only as-sets and route-sets: an rtr-set or peering-set
// came back empty with no error, and a filter-set as a route-set; the whois
// backend asked only for those two classes and found nothing.
func TestBackendsExpandEverySetClass(t *testing.T) {
	texts := []string{
		"rtr-set: RTRS-A\nmembers: rtr1.example.net, 192.0.2.1, RTRS-B\nsource: TEST\n",
		"rtr-set: RTRS-B\nmembers: rtr2.example.net\nsource: TEST\n",
		"rtr-set: RTRS-REF\nmembers: direct.example.net\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"inet-rtr: claimed.example.net\nlocal-as: AS1\nmember-of: RTRS-REF\nmnt-by: MNT-A\nsource: TEST\n",
		"peering-set: PRNG-A\npeering: AS1\npeering: AS2 at 192.0.2.1\npeering: PRNG-B\nsource: TEST\n",
		"peering-set: PRNG-B\npeering: AS3\nsource: TEST\n",
		"filter-set: FLTR-A\nfilter: {192.0.2.0/24} OR FLTR-B\nsource: TEST\n",
		"filter-set: FLTR-B\nfilter: {198.51.100.0/24}\nsource: TEST\n",
	}
	var objs []object.Object
	for _, s := range texts {
		o, _ := rpsl.ParseObject(s)
		obj, _ := rpsl.Decode(o)
		objs = append(objs, obj)
	}
	db := irrtest.New(texts...).WithSources("TEST")
	ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"TEST"}, Timeout: 5 * time.Second}
	defer ir.Close()
	wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"TEST"}, Timeout: 5 * time.Second}
	mem := resolve.NewMemSource(objs)
	ctx := context.Background()
	name := func(s string) types.SetName {
		n, err := types.ParseSetName(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	expand := func(src resolve.Source, set string) (string, error) {
		e := &resolve.Expander{Src: src}
		switch n := name(set); n.Class() {
		case types.ClassRtrSet:
			got, err := e.ExpandRouters(ctx, n)
			var rs []string
			for _, r := range got.List() {
				rs = append(rs, r.String())
			}
			return strings.Join(rs, " "), err
		case types.ClassPeeringSet:
			got, err := e.ExpandPeerings(ctx, n)
			return strings.Join(got.Strings(), " | "), err
		default:
			got, err := e.ExpandFilterSet(ctx, n)
			return fmt.Sprint(got.List()), err
		}
	}
	for _, set := range []string{"RTRS-A", "RTRS-REF", "PRNG-A", "FLTR-A"} {
		want, err := expand(mem, set)
		if err != nil || want == "" || want == "[]" {
			t.Fatalf("memory: %s = %q, %v", set, want, err)
		}
		for label, src := range map[string]resolve.Source{"irrd": ir, "whois": wh} {
			got, err := expand(src, set)
			if label == "irrd" && set == "RTRS-REF" {
				// IRRd's query protocol cannot list inet-rtr member-of
				// claims; saying so beats an answer without them.
				if !errors.Is(err, irrd.ErrIndirectUnsupported) {
					t.Errorf("irrd: %s = %q, %v; want ErrIndirectUnsupported", set, got, err)
				}
				continue
			}
			if err != nil || got != want {
				t.Errorf("%s: %s = %q, %v; want %q, as from memory", label, set, got, err, want)
			}
		}
	}
	// Missing sets of these classes are not found, over both.
	for label, src := range map[string]resolve.Source{"irrd": ir, "whois": wh} {
		if _, err := src.GetSet(ctx, name("FLTR-GONE")); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: GetSet(FLTR-GONE) = %v, want ErrNotFound", label, err)
		}
	}
}
