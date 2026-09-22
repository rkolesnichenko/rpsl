package resolve_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// The engine against bgpq4 itself: a real bgpq4 binary queries an in-process
// IRRd (irrtest) serving the same objects the engine expands. bgpq4 recurses
// through as-sets itself (-L), and resolves route-sets with the server's
// recursive "!i<set>,1", which irrtest implements as IRRd does. The tests skip
// when bgpq4 is not installed; CI installs it.

// bgpq4Args are the flags every run uses: JSON output, private-range and
// documentation ASNs kept (the tests use them), and client-side as-set
// recursion. Each run adds "-S" with the engine's source priority.
var bgpq4Args = []string{"-j", "-p", "-l", "x", "-L", "64"}

// modelSources is the source priority of the random IRRs.
const modelSources = "RIPE,RADB"

func needBgpq4(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bgpq4"); err != nil {
		t.Skip("bgpq4 is not installed")
	}
}

// runBgpq4 runs bgpq4 against addr with the given source priority and returns
// the JSON list it prints.
func runBgpq4(t *testing.T, addr, sources string, args ...string) []json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args = append(append(append([]string{"-h", addr}, bgpq4Args...), "-S", sources), args...)
	cmd := exec.CommandContext(ctx, "bgpq4", args...)
	out, err := cmd.Output() // bgpq4 reports members it cannot use on stderr
	if err != nil {
		t.Fatalf("bgpq4 %s: %v", strings.Join(cmd.Args[1:], " "), err)
	}
	var doc map[string][]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bgpq4 %s: bad JSON %q: %v", strings.Join(cmd.Args[1:], " "), out, err)
	}
	return doc["x"]
}

// bgpq4ASNs returns bgpq4's expansion of an as-set into AS numbers.
func bgpq4ASNs(t *testing.T, addr, sources, set string) []string {
	t.Helper()
	var out []string
	for _, raw := range runBgpq4(t, addr, sources, "-t", set) {
		var n uint32
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("bgpq4 -t %s: %s is not an AS number", set, raw)
		}
		out = append(out, types.ASN(n).String())
	}
	sort.Strings(out)
	return out
}

// bgpq4Prefixes returns bgpq4's prefix list for a set in one family, with any
// entry that is a range rather than an exact prefix enumerated.
func bgpq4Prefixes(t *testing.T, addr, sources, set string, v6 bool) []string {
	t.Helper()
	fam := "-4"
	if v6 {
		fam = "-6"
	}
	var out []string
	for _, raw := range runBgpq4(t, addr, sources, fam, set) {
		var e struct {
			Prefix string `json:"prefix"`
			Exact  bool   `json:"exact"`
			GE     *int   `json:"greater-equal"`
			LE     *int   `json:"less-equal"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("bgpq4 %s %s: bad entry %s", fam, set, raw)
		}
		p := netip.MustParsePrefix(e.Prefix)
		lo, hi := p.Bits(), p.Bits()
		if !e.Exact {
			if e.GE != nil {
				lo = *e.GE
			}
			hi = p.Addr().BitLen()
			if e.LE != nil {
				hi = *e.LE
			}
		}
		for _, q := range moreSpecifics(p, lo, hi) {
			out = append(out, q.String())
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// engineResults returns what the engine gives for a set: its AS numbers (for an
// as-set) and its IPv4 and IPv6 prefixes.
func engineResults(t *testing.T, src resolve.Source, set string) (asns, v4, v6 []string) {
	t.Helper()
	ctx, n := context.Background(), mustSet(t, set)
	if n.Class() == types.ClassAsSet {
		got, err := (&resolve.Expander{Src: src}).ExpandAS(ctx, n)
		if err != nil {
			t.Fatalf("ExpandAS(%s): %v", set, err)
		}
		for _, a := range got.List() {
			asns = append(asns, a.String())
		}
		sort.Strings(asns)
	}
	for _, afi := range []types.AFI{types.AFIv4, types.AFIv6} {
		got, err := (&resolve.Expander{Src: src, AFI: afi}).ExpandPrefixes(ctx, n)
		if err != nil {
			t.Fatalf("ExpandPrefixes(%s, %v): %v", set, afi, err)
		}
		if afi == types.AFIv4 {
			v4 = prefixStrings(got.List())
		} else {
			v6 = prefixStrings(got.List())
		}
	}
	return asns, v4, v6
}

// Random IRRs, limited to what bgpq4 and IRRd implement, expand the same with
// the engine and with bgpq4: AS numbers and both families' prefixes of every
// set.
func TestBgpq4Differential(t *testing.T) {
	needBgpq4(t)
	for seed := uint64(0); seed < 60; seed++ {
		r := rand.New(rand.NewPCG(seed, 7))
		m := randomModel(r, true)
		texts := m.texts(r)
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		var tops []string
		for name := range newOracle(m).sets {
			tops = append(tops, name)
		}
		sort.Strings(tops)
		for _, top := range tops {
			asns, v4, v6 := engineResults(t, src, top)
			fail := func(what string, ours, theirs []string) {
				t.Fatalf("seed %d %s %s:\nengine %v\nbgpq4  %v\nobjects:\n%s", seed, top, what, ours, theirs, strings.Join(texts, "\n"))
			}
			if setClass(top) == types.ClassAsSet {
				if b := bgpq4ASNs(t, addr, modelSources, top); !slices.Equal(asns, b) {
					fail("AS numbers", asns, b)
				}
			}
			if b := bgpq4Prefixes(t, addr, modelSources, top, false); !slices.Equal(v4, b) {
				fail("IPv4 prefixes", v4, b)
			}
			if b := bgpq4Prefixes(t, addr, modelSources, top, true); !slices.Equal(v6, b) {
				fail("IPv6 prefixes", v6, b)
			}
		}
	}
}

// Where the engine and bgpq4 knowingly differ. Each case pins both answers, so
// a change on either side fails here; the reasons are in
// testdata/bgpq4/divergences.md.
func TestBgpq4KnownDivergences(t *testing.T) {
	needBgpq4(t)
	common := []string{
		"route: 192.0.2.0/24\norigin: AS65001\nsource: RIPE\n",
		"route: 198.51.100.0/24\norigin: AS65002\nsource: RIPE\n",
		"route-set: RS-INNER\nmembers: 203.0.113.0/24\nsource: RIPE\n",
	}
	for _, c := range []struct {
		id         string
		objects    []string
		set        string
		ours, bgp4 string // IPv4 prefixes, or AS numbers when the set is an as-set
	}{
		{
			id:      "single-length-range",
			objects: []string{"route-set: RS-X\nmembers: 192.0.2.0/24^26\nsource: RIPE\n"},
			set:     "RS-X", ours: "192.0.2.0/26 192.0.2.128/26 192.0.2.192/26 192.0.2.64/26", bgp4: "",
		},
		{
			id:      "operator-on-set-member",
			objects: []string{"route-set: RS-X\nmembers: RS-INNER^25\nsource: RIPE\n"},
			set:     "RS-X", ours: "203.0.113.0/25 203.0.113.128/25", bgp4: "",
		},
		{
			id:      "operator-on-as-member",
			objects: []string{"route-set: RS-X\nmembers: AS65001^25\nsource: RIPE\n"},
			set:     "RS-X", ours: "192.0.2.0/25 192.0.2.128/25", bgp4: "",
		},
		{
			id:      "route-set-in-as-set",
			objects: []string{"as-set: AS-X\nmembers: AS65001, RS-Y\nsource: RIPE\n", "route-set: RS-Y\nmembers: AS65002\nsource: RIPE\n"},
			set:     "AS-X", ours: "AS65001", bgp4: "AS65001 AS65002",
		},
	} {
		texts := append(append([]string{}, common...), c.objects...)
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		asns, v4, _ := engineResults(t, src, c.set)
		ours, theirs := v4, bgpq4Prefixes(t, addr, modelSources, c.set, false)
		if setClass(c.set) == types.ClassAsSet {
			ours, theirs = asns, bgpq4ASNs(t, addr, modelSources, c.set)
		}
		if strings.Join(ours, " ") != c.ours || strings.Join(theirs, " ") != c.bgp4 {
			t.Errorf("%s: engine %q, bgpq4 %q; pinned engine %q, bgpq4 %q", c.id, ours, theirs, c.ours, c.bgp4)
		}
	}
	// AS-ANY: the engine refuses it (resolve.AnySetError); bgpq4 finds no such
	// set and expands the rest.
	texts := append(append([]string{}, common...), "as-set: AS-X\nmembers: AS65001, AS-ANY\nsource: RIPE\n")
	src := resolve.NewMemSource(decodeAll(t, texts), "RIPE")
	if _, err := (&resolve.Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-X")); err == nil {
		t.Error("as-any: the engine expanded AS-ANY")
	}
	if b := bgpq4ASNs(t, irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t), modelSources, "AS-X"); fmt.Sprint(b) != "[AS65001]" {
		t.Errorf("as-any: bgpq4 %v, pinned [AS65001]", b)
	}
}

// A prefix range starting above its prefix length is refused by both: the
// engine (an Error, the member is left out) and bgpq4 ("min < masklen").
func TestBgpq4RejectsRangeBelowPrefixLength(t *testing.T) {
	needBgpq4(t)
	texts := []string{"route-set: RS-X\nmp-members: 2001::/23^16-48, 2001:db8::/32\nsource: RIPE\n"}
	src := resolve.NewMemSource(decodeAll(t, texts), "RIPE")
	_, _, v6 := engineResults(t, src, "RS-X")
	b := bgpq4Prefixes(t, irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t), modelSources, "RS-X", true)
	if fmt.Sprint(v6) != "[2001:db8::/32]" || fmt.Sprint(b) != "[2001:db8::/32]" {
		t.Errorf("engine %v, bgpq4 %v; want both [2001:db8::/32]", v6, b)
	}
}
