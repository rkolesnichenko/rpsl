package resolve

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
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

// A set whose class is not the one its name denotes ("route-set: AS-EVIL") is
// invalid data. Expanded under its name's rules it would let an as-set pull in
// prefixes no route object backs, and take route claims into an "as-set"; it
// is not followed, and is listed as missing.
func TestClassConfusedSetNotFollowed(t *testing.T) {
	src := corpus(t,
		asSet("AS-TOP", "AS1, AS-EVIL"),
		"route-set: AS-EVIL\nmembers: 1.2.3.0/24, 9.9.0.0/16^+\nmbrs-by-ref: ANY\nsource: TEST\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n",
		"route: 203.0.113.0/24\norigin: AS2\nmember-of: AS-EVIL\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	got, err := e.ExpandPrefixRanges(context.Background(), mustSet(t, "AS-TOP"))
	if want := []string{"10.0.0.0/8"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("ExpandPrefixRanges(AS-TOP) = %v, %v; want %v", rangeList(got), err, want)
	}
	if want := []string{"AS-EVIL"}; !reflect.DeepEqual(canonList(got.Missing()), want) {
		t.Errorf("Missing = %v, want %v", canonList(got.Missing()), want)
	}
	// At the top it is not found at all.
	if _, err := e.ExpandAS(context.Background(), mustSet(t, "AS-EVIL")); !errors.Is(err, ErrNotFound) {
		t.Errorf("ExpandAS(AS-EVIL) error = %v, want ErrNotFound", err)
	}
}

// renamingSource answers every GetSet with the set it holds under another name.
type renamingSource struct {
	*MemSource
	to types.SetName
}

func (r renamingSource) GetSet(ctx context.Context, _ types.SetName) (object.NamedSet, error) {
	return r.MemSource.GetSet(ctx, r.to)
}

// A Source that answers with a set of another name has confused its
// responses: that is an error, not a missing set or, worse, a substitute.
func TestSourceReturningWrongNameIsError(t *testing.T) {
	src := renamingSource{corpus(t, asSet("AS-OTHER", "AS666")), mustSet(t, "AS-OTHER")}
	_, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-WANTED"))
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("ExpandAS(AS-WANTED) error = %v, want a Source fault", err)
	}
}
