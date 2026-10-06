package rpki

import (
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func asns(xs ...uint32) []types.ASN {
	out := make([]types.ASN, len(xs))
	for i, x := range xs {
		out[i] = types.ASN(x)
	}
	return out
}

// Every §3.3 rule of draft-ietf-sidrops-aspa-profile-29 refuses its ASPA.
func TestNewASPAsRefuses(t *testing.T) {
	many := make([]types.ASN, MaxProviders+1)
	for i := range many {
		many[i] = types.ASN(i + 1)
	}
	for name, c := range map[string]struct {
		a    ASPA
		want string
	}{
		"customer AS0":      {ASPA{0, asns(1)}, "customer AS0"},
		"no providers":      {ASPA{1, nil}, "no providers"},
		"lists itself":      {ASPA{5, asns(2, 5)}, "lists itself"},
		"AS0 beside others": {ASPA{5, asns(0, 2)}, "AS0 beside"},
		"not ascending":     {ASPA{5, asns(3, 2)}, "not ascending"},
		"duplicate":         {ASPA{5, asns(2, 2)}, "not ascending"},
		"over MaxProviders": {ASPA{MaxProviders + 2, many}, "more than"},
	} {
		if _, err := NewASPAs([]ASPA{c.a}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want one containing %q", name, err, c.want)
		}
	}
}

// §5.2: one customer's ASPAs merge into the union of their providers; AS0
// stays only when every ASPA of the customer is AS0-only.
func TestNewASPAsMerges(t *testing.T) {
	s, err := NewASPAs([]ASPA{
		{10, asns(3, 7)}, {10, asns(2, 7, 9)},
		{20, asns(0)}, {20, asns(4)},
		{30, asns(0)}, {30, asns(0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cust uint32
		want []types.ASN
		ok   bool
	}{
		{10, asns(2, 3, 7, 9), true},
		{20, asns(4), true},
		{30, nil, true},
		{40, nil, false},
	} {
		got, ok := s.Providers(types.ASN(c.cust))
		if ok != c.ok || !slices.Equal(got, c.want) {
			t.Errorf("Providers(AS%d) = %v, %v; want %v, %v", c.cust, got, ok, c.want, c.ok)
		}
	}
	if s.Len() != 3 {
		t.Errorf("Len %d, want 3", s.Len())
	}
	var all []ASPA
	for a := range s.All() {
		all = append(all, a)
	}
	want := []ASPA{{10, asns(2, 3, 7, 9)}, {20, asns(4)}, {30, asns(0)}}
	if !slices.EqualFunc(all, want, func(a, b ASPA) bool { return a.Customer == b.Customer && slices.Equal(a.Providers, b.Providers) }) {
		t.Errorf("All %v, want %v", all, want)
	}
	// All's output is valid input and gives the same set.
	again, err := NewASPAs(all)
	if err != nil || again.Len() != s.Len() {
		t.Fatalf("NewASPAs(All()): %v, %v", again, err)
	}
}

// The cap holds after merging too.
func TestNewASPAsCapAfterMerge(t *testing.T) {
	half := func(from int) []types.ASN {
		out := make([]types.ASN, MaxProviders/2+1)
		for i := range out {
			out[i] = types.ASN(from + i)
		}
		return out
	}
	if _, err := NewASPAs([]ASPA{{1, half(10)}, {1, half(100_000)}}); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("err %v, want the cap after merging", err)
	}
}

// The zero value and a nil *ASPAs hold nothing; Providers returns a copy.
func TestASPAsZeroAndCopy(t *testing.T) {
	var zero ASPAs
	if _, ok := zero.Providers(1); ok || zero.Len() != 0 {
		t.Error("the zero value holds an ASPA")
	}
	var nilSet *ASPAs
	if _, ok := nilSet.Providers(1); ok || nilSet.Len() != 0 {
		t.Error("a nil *ASPAs holds an ASPA")
	}
	for range nilSet.All() {
		t.Error("a nil *ASPAs yields an ASPA")
	}
	in := []ASPA{{1, asns(2, 3)}}
	s, err := NewASPAs(in)
	if err != nil {
		t.Fatal(err)
	}
	in[0].Providers[0] = 99 // NewASPAs copied its input
	got, _ := s.Providers(1)
	got[1] = 98 // Providers returned a copy
	if again, _ := s.Providers(1); !slices.Equal(again, asns(2, 3)) {
		t.Errorf("Providers %v after mutations, want [AS2 AS3]", again)
	}
}
