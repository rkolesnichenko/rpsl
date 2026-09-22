package resolve

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// RFC 2622 §5.1: an as-set lists ASNs and as-sets. A route-set listed in one is
// invalid, and following it would let any nested as-set inject prefixes that
// have no route objects (here 0.0.0.0/0^+).
func TestAsSetDoesNotFollowRouteSets(t *testing.T) {
	src := corpus(t,
		asSet("AS-CUST", "AS1, RS-EVIL"),
		routeSet("RS-EVIL", "0.0.0.0/0^+"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
	)
	got, err := (&Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustSet(t, "AS-CUST"))
	if want := []string{"192.0.2.0/24"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("ExpandPrefixRanges(AS-CUST) = %v, %v; want %v", rangeList(got), err, want)
	}
}

// A route-set that is legitimately reachable (from a route-set) is still not
// entered from an as-set that also lists it, so the as-set's operator does not
// widen it.
func TestRouteSetIsNotEnteredFromAnAsSet(t *testing.T) {
	src := corpus(t,
		routeSet("RS-TOP", "RS-EVIL, AS-CUST^+"),
		asSet("AS-CUST", "RS-EVIL"),
		routeSet("RS-EVIL", "10.0.0.0/8"),
	)
	got, err := (&Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustSet(t, "RS-TOP"))
	if want := []string{"10.0.0.0/8"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("ExpandPrefixRanges(RS-TOP) = %v, %v; want %v", rangeList(got), err, want)
	}
}

// ExpandAS denotes the ASNs of an as-set; asked of any other class it used to
// return a partial answer (the as-sets a route-set lists, not its route-sets).
// Prefix expansions take an as-set or a route-set.
func TestExpansionsCheckTheSetClass(t *testing.T) {
	ctx := context.Background()
	src := corpus(t, routeSet("RS-X", "AS1, AS-Y"), asSet("AS-Y", "AS2"))
	e := &Expander{Src: src}
	if got, err := e.ExpandAS(ctx, mustSet(t, "RS-X")); !errors.Is(err, ErrSetClass) {
		t.Errorf("ExpandAS(RS-X) = %v, %v; want ErrSetClass", got, err)
	}
	for _, name := range []string{"FLTR-X", "RTRS-X", "PRNG-X"} {
		if got, err := e.ExpandPrefixRanges(ctx, mustSet(t, name)); !errors.Is(err, ErrSetClass) {
			t.Errorf("ExpandPrefixRanges(%s) = %v, %v; want ErrSetClass", name, got, err)
		}
		if got, err := e.ExpandPrefixes(ctx, mustSet(t, name)); !errors.Is(err, ErrSetClass) {
			t.Errorf("ExpandPrefixes(%s) = %v, %v; want ErrSetClass", name, got, err)
		}
	}
}
