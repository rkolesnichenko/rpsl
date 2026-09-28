package rpki

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func decode(t testing.TB, texts ...string) []object.Object {
	t.Helper()
	var out []object.Object
	for _, text := range texts {
		o, ds := rpsl.ParseObject(text)
		obj, dds := object.Decode(o)
		if len(ds)+len(dds) > 0 {
			t.Fatalf("%q: %v %v", text, ds, dds)
		}
		out = append(out, obj)
	}
	return out
}

// corpus: AS64500 holds 10.0.0.0/8 up to /16 in the RPKI; AS64501 has a route
// inside it, so that route is Invalid. 192.0.2.0/24 has no ROA.
func filterCorpus(t testing.TB) (resolve.Source, *VRPs) {
	objs := decode(t,
		"as-set: AS-CONE\nmembers: AS64500, AS64501\nsource: TEST\n",
		"route-set: RS-LIST\nmembers: 10.9.0.0/24, RS-REF\nsource: TEST\n",
		"route-set: RS-REF\nmbrs-by-ref: ANY\nsource: TEST\n",
		"route: 10.0.0.0/8\norigin: AS64500\nmnt-by: M\nsource: TEST\n",
		"route: 10.1.0.0/24\norigin: AS64500\nmnt-by: M\nsource: TEST\n", // past maxLength: Invalid
		"route: 10.2.0.0/16\norigin: AS64501\nmember-of: RS-REF\nmnt-by: M\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS64501\nmember-of: RS-REF\nmnt-by: M\nsource: TEST\n",
		"route6: 2001:db8::/32\norigin: AS64501\nmember-of: RS-REF\nmnt-by: M\nsource: TEST\n",
		"route6: 2001:db8:1::/48\norigin: AS64500\nmnt-by: M\nsource: TEST\n",
	)
	v := mustVRPs(t, vrp("10.0.0.0/8", 64500, 16), vrp("2001:db8::/32", 64501, 32))
	return resolve.NewMemSource(objs), v
}

func TestFilterSource(t *testing.T) {
	src, v := filterCorpus(t)
	var mu sync.Mutex
	var dropped []string
	f := &Filter{Src: src, VRPs: v, OnSuppress: func(p netip.Prefix, as types.ASN) {
		mu.Lock()
		defer mu.Unlock()
		dropped = append(dropped, p.String()+" "+as.String())
	}}
	ctx := context.Background()
	for _, tc := range []struct {
		as   types.ASN
		afi  types.AFI
		want []string
	}{
		{64500, types.AFIAny, []string{"10.0.0.0/8"}}, // 10.1.0.0/24 past maxLength, 2001:db8:1::/48 not its ROA
		{64500, types.AFIv6, nil},
		{64501, types.AFIAny, []string{"192.0.2.0/24", "2001:db8::/32"}},
		{64501, types.AFIv4, []string{"192.0.2.0/24"}},
		{64999, types.AFIAny, nil},
	} {
		ps, err := f.OriginatedRoutes(ctx, tc.as, tc.afi)
		if err != nil {
			t.Fatal(err)
		}
		if got := strs(ps); !slices.Equal(got, tc.want) {
			t.Errorf("OriginatedRoutes(%s, %v) = %v, want %v", tc.as, tc.afi, got, tc.want)
		}
	}
	if len(dropped) == 0 {
		t.Error("OnSuppress never called")
	}

	name, _ := types.ParseSetName("RS-REF")
	set, err := f.GetSet(ctx, types.Ref(name))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.MembersByRef(ctx, set)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range claims {
		p, _, _ := route(o)
		got = append(got, p.String())
	}
	if want := []string{"192.0.2.0/24", "2001:db8::/32"}; !slices.Equal(got, want) {
		t.Errorf("MembersByRef = %v, want %v (10.2.0.0/16 is Invalid)", got, want)
	}
}

// TestFilterExpands runs the Expander over a Filter: a member AS's invalid
// routes and an invalid claimant are gone, and a route-set's literal prefix
// stays, even inside a ROA's space.
func TestFilterExpands(t *testing.T) {
	src, v := filterCorpus(t)
	ctx := context.Background()
	for _, tc := range []struct {
		set        string
		raw, clean []string
	}{
		{"AS-CONE",
			[]string{"10.0.0.0/8", "10.1.0.0/24", "10.2.0.0/16", "192.0.2.0/24", "2001:db8:1::/48", "2001:db8::/32"},
			[]string{"10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32"}},
		{"RS-LIST",
			[]string{"10.2.0.0/16", "10.9.0.0/24", "192.0.2.0/24", "2001:db8::/32"},
			[]string{"10.9.0.0/24", "192.0.2.0/24", "2001:db8::/32"}},
	} {
		name, _ := types.ParseSetName(tc.set)
		for _, run := range []struct {
			src  resolve.Source
			want []string
		}{{src, tc.raw}, {&Filter{Src: src, VRPs: v}, tc.clean}, {&Filter{Src: src}, tc.raw}} {
			ps, err := (&resolve.Expander{Src: run.src}).ExpandPrefixes(ctx, types.Ref(name))
			if err != nil {
				t.Fatal(err)
			}
			got := strs(ps.List())
			slices.Sort(got)
			if !slices.Equal(got, run.want) {
				t.Errorf("%s over %T: %v, want %v", tc.set, run.src, got, run.want)
			}
		}
	}
}

type errSource struct{ resolve.Source }

var errBoom = errors.New("boom")

func (errSource) OriginatedRoutes(context.Context, types.ASN, types.AFI) ([]netip.Prefix, error) {
	return nil, errBoom
}
func (errSource) MembersByRef(context.Context, object.NamedSet) ([]object.Object, error) {
	return nil, errBoom
}

func TestFilterPassesErrors(t *testing.T) {
	src, v := filterCorpus(t)
	f := &Filter{Src: errSource{src}, VRPs: v}
	ctx := context.Background()
	if _, err := f.OriginatedRoutes(ctx, 64500, types.AFIAny); !errors.Is(err, errBoom) {
		t.Errorf("OriginatedRoutes error %v", err)
	}
	if _, err := f.MembersByRef(ctx, nil); !errors.Is(err, errBoom) {
		t.Errorf("MembersByRef error %v", err)
	}
	name, _ := types.ParseSetName("AS-NONE")
	if _, err := f.GetSet(ctx, types.Ref(name)); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("GetSet error %v", err)
	}
}

func TestRouteOfPointers(t *testing.T) {
	objs := decode(t, "route: 10.0.0.0/8\norigin: AS1\nsource: T\n", "route6: 2001:db8::/32\norigin: AS2\nsource: T\n")
	r, r6 := objs[0].(object.Route), objs[1].(object.Route6)
	for _, o := range []object.Object{r, &r, r6, &r6} {
		if _, _, ok := route(o); !ok {
			t.Errorf("route(%T) not a route", o)
		}
	}
	for _, o := range []object.Object{(*object.Route)(nil), (*object.Route6)(nil), object.AutNum{}} {
		if _, _, ok := route(o); ok {
			t.Errorf("route(%T) is a route", o)
		}
	}
}

func strs(ps []netip.Prefix) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
