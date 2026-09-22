package resolve

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// Ranges are identified by the prefixes they denote, not by their spelling:
// equivalent members collapse to one canonical range, a range that denotes
// nothing is dropped, and neither is charged against MaxPrefixes.
func TestRangeSetIsCanonical(t *testing.T) {
	src := corpus(t, routeSet("RS-A",
		"192.0.2.0/24, 192.0.2.0/24^24, 192.0.2.0/24^24-24, 192.0.2.1/24",
		"10.0.0.0/8^8-32, 10.0.0.0/8^+, 198.51.100.1/32^-"))
	got, err := (&Expander{Src: src, MaxPrefixes: 2}).ExpandPrefixRanges(context.Background(), mustSet(t, "RS-A"))
	if want := []string{"10.0.0.0/8^+", "192.0.2.0/24"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("ExpandPrefixRanges = %v, %v; want %v", rangeList(got), err, want)
	}
}

// A custom Source builds its ranges with types.NewPrefixRange, which cannot make
// a non-canonical one: host bits and equivalent windows collapse there, and the
// engine's output stays canonical.
func TestRangeSetCanonicalizesSourceRanges(t *testing.T) {
	name := mustSet(t, "RS-LIT")
	withHostBits, _ := types.NewPrefixRange(netip.MustParsePrefix("10.0.0.1/8"), 8, 32)
	plain, _ := types.NewPrefixRange(netip.MustParsePrefix("10.0.0.0/8"), 8, 32)
	src := staticSource{name.String(): object.RouteSet{Name: name, Members: []object.SetMember{
		{Kind: object.MemberPrefixRange, Range: withHostBits, Raw: "10.0.0.1/8^8-32"},
		{Kind: object.MemberPrefixRange, Range: plain, Raw: "10.0.0.0/8^+"},
	}}}
	got, err := (&Expander{Src: src}).ExpandPrefixRanges(context.Background(), name)
	if want := []string{"10.0.0.0/8^+"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("ExpandPrefixRanges = %v, %v; want %v", rangeList(got), err, want)
	}
	if !got.Has(plain) {
		t.Error("Has(10.0.0.0/8^+) = false")
	}
}

// staticSource serves literal typed sets, as a custom backend might build them.
type staticSource map[string]object.Set

func (s staticSource) GetSet(_ context.Context, n types.SetName) (object.NamedSet, error) {
	if set, ok := s[n.String()]; ok {
		return set, nil
	}
	return nil, ErrNotFound
}

func (staticSource) OriginatedRoutes(context.Context, types.ASN, types.AFI) ([]netip.Prefix, error) {
	return nil, nil
}

func (staticSource) MembersByRef(context.Context, object.NamedSet) ([]object.Object, error) {
	return nil, nil
}
