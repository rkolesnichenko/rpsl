package rpki

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// Verbatim records: rpki-client's from https://console.rpki-client.org/vrps.json
// (2026-10-06; output-json.c, 8.5 and later), Routinator's as src/output.rs
// writes them (json; jsonext adds "source").
const (
	rpkiClientASPAs = `{"metadata": {"aspas": 3}, "roas": [], "aspas": [
		{ "customer_asid": 43, "expires": 1791385200, "providers": [ 293 ] },
		{ "customer_asid": 80, "expires": 1791417600, "providers": [ 3356, 6461 ] },
		{ "customer_asid": 174, "expires": 1791385200, "providers": [ 0 ] }
	]}`
	routinatorASPAs = `{"metadata": {"generated": 1, "generatedTime": "2026-10-06T00:00:00Z"}, "roas": [], "aspas": [
		{ "customer": "AS64496", "providers": ["AS64497", "AS64498"], "ta": "ripe" },
		{ "customer": "AS64499", "providers": ["AS64500"], "ta": "arin", "source": [{"type": "aspa", "uri": "rsync://x/y.asa", "tal": "arin", "validity": {}, "chainValidity": {}, "stale": 0}] }
	]}`
)

func TestReadASPAsShapes(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want []ASPA
	}{
		"rpki-client": {rpkiClientASPAs, []ASPA{{43, asns(293)}, {80, asns(3356, 6461)}, {174, asns(0)}}},
		"routinator":  {routinatorASPAs, []ASPA{{64496, asns(64497, 64498)}, {64499, asns(64500)}}},
		// Review Focus 2: both shapes in one array.
		"mixed": {`{"aspas": [{"customer_asid": 1, "providers": [2]}, {"customer": "AS3", "providers": ["4", 5]}]}`,
			[]ASPA{{1, asns(2)}, {3, asns(4, 5)}}},
		// Two records of one customer merge (profile §5.2).
		"merged": {`{"aspas": [{"customer_asid": 1, "providers": [3]}, {"customer_asid": 1, "providers": [2]}]}`,
			[]ASPA{{1, asns(2, 3)}}},
	} {
		s, err := ReadASPAs(strings.NewReader(c.in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var got []ASPA
		for a := range s.All() {
			got = append(got, a)
		}
		if !slices.EqualFunc(got, c.want, func(a, b ASPA) bool { return a.Customer == b.Customer && slices.Equal(a.Providers, b.Providers) }) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Review Focus 1: an empty array is an export with no ASPAs; null is not an array.
func TestReadASPAsEmptyAndNull(t *testing.T) {
	s, err := ReadASPAs(strings.NewReader(`{"roas": [], "aspas": []}`))
	if err != nil || s.Len() != 0 {
		t.Errorf(`"aspas": []: %v, %v; want an empty set`, s, err)
	}
	if _, err := ReadASPAs(strings.NewReader(`{"aspas": null}`)); err == nil {
		t.Error(`"aspas": null accepted`)
	}
}

func TestReadASPAsErrors(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"no aspas":         {`{"roas": []}`, `no "aspas" member`},
		"per-AFI form":     {`{"provider_authorizations": {"ipv4": [], "ipv6": []}}`, "rpki-client 8.0-8.4"},
		"aspas twice":      {`{"aspas": [], "aspas": []}`, `"aspas" twice`},
		"not an object":    {`[]`, "not a JSON object"},
		"record not obj":   {`{"aspas": [1]}`, "record 0: not an object"},
		"both customers":   {`{"aspas": [{"customer_asid": 1, "customer": "AS1", "providers": [2]}]}`, "both"},
		"no customer":      {`{"aspas": [{"providers": [2]}]}`, `missing "customer_asid"`},
		"no providers key": {`{"aspas": [{"customer_asid": 1}]}`, `missing "providers"`},
		"providers null":   {`{"aspas": [{"customer_asid": 1, "providers": null}]}`, "not an array"},
		"empty providers":  {`{"aspas": [{"customer_asid": 1, "providers": []}]}`, "no providers"},
		"bad customer":     {`{"aspas": [{"customer_asid": "ASX", "providers": [2]}]}`, "customer"},
		"bad provider":     {`{"aspas": [{"customer_asid": 1, "providers": [2, -3]}]}`, "provider 1"},
		"unsorted":         {`{"aspas": [{"customer_asid": 1, "providers": [3, 2]}]}`, "not ascending"},
		"second record":    {`{"aspas": [{"customer_asid": 1, "providers": [2]}, {"customer_asid": 0, "providers": [2]}]}`, "record 1"},
		"trailing data":    {`{"aspas": []} x`, "data after the document"},
	} {
		if _, err := ReadASPAs(strings.NewReader(c.in)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want one containing %q", name, err, c.want)
		}
	}
}

// TestRealDataASPAs (opt-in: RPSL_REALDATA, filled by scripts/fetch-irr-dumps.sh
// rpki) reads NTT's export, which is rpki-client's: one record per unique VAP,
// so the set holds metadata.uniquevaps customers (3,269 of them on
// 2026-09-27, measured with jq: one record per customer, 63 AS0-only, at most
// 228 providers).
func TestRealDataASPAs(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	path := filepath.Join(dir, "rpki", "vrps.json")
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("no VRPs (scripts/fetch-irr-dumps.sh rpki): %v", err)
	}
	defer f.Close()
	s, err := ReadASPAs(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			UniqueVAPs int `json:"uniquevaps"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if s.Len() != doc.Metadata.UniqueVAPs {
		t.Errorf("%d customers, want metadata.uniquevaps %d", s.Len(), doc.Metadata.UniqueVAPs)
	}
	as0, most := 0, 0
	for a := range s.All() {
		if a.Providers[0] == 0 {
			as0++
		}
		most = max(most, len(a.Providers))
	}
	t.Logf("%d customers, %d AS0-only, at most %d providers", s.Len(), as0, most)
	if p, ok := s.Providers(43); !ok || !slices.Contains(p, 293) {
		t.Errorf("AS43's providers %v, %v; the console lists AS293", p, ok)
	}
}
