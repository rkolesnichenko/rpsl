package resolve

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// fetchCounter counts GetSet calls per set name.
type fetchCounter struct {
	*MemSource
	mu    sync.Mutex
	calls map[string]int
}

func (c *fetchCounter) GetSet(ctx context.Context, n types.SetName) (object.NamedSet, error) {
	c.mu.Lock()
	c.calls[n.String()]++
	c.mu.Unlock()
	return c.MemSource.GetSet(ctx, n)
}

func excludeCorpus(t *testing.T) *fetchCounter {
	return &fetchCounter{MemSource: corpus(t,
		asSet("AS-TOP", "AS1, AS-BAD, AS-GOOD, AS-TOP"),
		asSet("AS-BAD", "AS2, AS-DEEP"),
		asSet("AS-DEEP", "AS3"),
		asSet("AS-GOOD", "AS4, AS5, AS-BAD"), // AS-BAD reachable another way: still out
		"as-set: AS-REF\nmembers: AS6\nmbrs-by-ref: ANY\nsource: TEST\n",
		"aut-num: AS7\nas-name: SEVEN\nmember-of: AS-REF\nmnt-by: M\nsource: TEST\n",
		routeSet("RS-TOP", "192.0.2.0/24, AS-GOOD, RS-BAD, AS5"),
		routeSet("RS-BAD", "198.51.100.0/24"),
		routeSet("RS-SELF", "192.0.2.0/24, RS-SELF^25"),
		"route: 10.4.0.0/16\norigin: AS4\nsource: TEST\n",
		"route: 10.5.0.0/24\norigin: AS5\nsource: TEST\n",
		"route: 10.7.0.0/16\norigin: AS7\nsource: TEST\n",
		fltrSet("FLTR-TOP", "RS-BAD OR AS4 OR AS-GOOD OR FLTR-BAD OR {203.0.113.0/24}"),
		fltrSet("FLTR-BAD", "{100.64.0.0/10}"),
	), calls: map[string]int{}}
}

func TestExcludeAS(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		ex   Exclusion
		top  string
		want string
	}{
		{"nothing excluded", Exclusion{}, "AS-TOP", "[1 2 3 4 5]"},
		{"a nested set, and what only it reaches", Exclusion{Sets: []types.SetName{mustSet(t, "AS-BAD")}}, "AS-TOP", "[1 4 5]"},
		{"a member AS", Exclusion{ASNs: []types.ASN{5}}, "AS-TOP", "[1 2 3 4]"},
		{"the top is expanded as asked", Exclusion{Sets: []types.SetName{mustSet(t, "AS-TOP")}}, "AS-TOP", "[1 2 3 4 5]"},
		{"an indirect aut-num member", Exclusion{ASNs: []types.ASN{7}}, "AS-REF", "[6]"},
	} {
		src := excludeCorpus(t)
		got, err := (&Expander{Src: src, Exclude: c.ex}).ExpandAS(ctx, mustSet(t, c.top))
		if err != nil || fmt.Sprint(asnList(got)) != c.want {
			t.Errorf("%s: ExpandAS(%s) = %v, %v; want %s", c.name, c.top, asnList(got), err, c.want)
		}
		if len(got.Missing()) != 0 {
			t.Errorf("%s: excluded sets reported missing: %v", c.name, got.Missing())
		}
		for _, n := range c.ex.Sets {
			if n.String() != c.top && src.calls[n.String()] != 0 {
				t.Errorf("%s: %s was fetched %d times", c.name, n, src.calls[n.String()])
			}
		}
	}
	// An excluded set that does not exist is not reported missing either.
	src := corpus(t, asSet("AS-TOP", "AS1, AS-GONE"))
	got, err := (&Expander{Src: src, Exclude: Exclusion{Sets: []types.SetName{mustSet(t, "AS-GONE")}}}).ExpandAS(ctx, mustSet(t, "AS-TOP"))
	if err != nil || len(got.Missing()) != 0 {
		t.Errorf("ExpandAS = %v, missing %v, %v; want nothing missing", asnList(got), got.Missing(), err)
	}
}

func TestExcludePrefixes(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		ex   Exclusion
		top  string
		want string
	}{
		{"nothing excluded", Exclusion{}, "RS-TOP",
			"10.4.0.0/16 10.5.0.0/24 192.0.2.0/24 198.51.100.0/24"},
		{"a nested route-set", Exclusion{Sets: []types.SetName{mustSet(t, "RS-BAD")}}, "RS-TOP",
			"10.4.0.0/16 10.5.0.0/24 192.0.2.0/24"},
		{"an AS, as a member and inside an as-set", Exclusion{ASNs: []types.ASN{5}}, "RS-TOP",
			"10.4.0.0/16 192.0.2.0/24 198.51.100.0/24"},
		{"a nested as-set", Exclusion{Sets: []types.SetName{mustSet(t, "AS-GOOD")}}, "RS-TOP",
			"10.5.0.0/24 192.0.2.0/24 198.51.100.0/24"},
		{"an indirect aut-num member's routes", Exclusion{ASNs: []types.ASN{7}}, "AS-REF", ""},
		{"a top listing itself", Exclusion{}, "RS-SELF", "192.0.2.0/24 192.0.2.0/25 192.0.2.128/25"},
		{"an excluded top listing itself", Exclusion{Sets: []types.SetName{mustSet(t, "RS-SELF")}}, "RS-SELF", "192.0.2.0/24"},
	} {
		got, err := (&Expander{Src: excludeCorpus(t), Exclude: c.ex}).ExpandPrefixes(ctx, mustSet(t, c.top))
		var ps []string
		for _, p := range got.List() {
			ps = append(ps, p.String())
		}
		if err != nil || strings.Join(ps, " ") != c.want {
			t.Errorf("%s: ExpandPrefixes(%s) = %v, %v; want %s", c.name, c.top, ps, err, c.want)
		}
	}
}

func TestExcludeFilterSet(t *testing.T) {
	ctx := context.Background()
	e := &Expander{Src: excludeCorpus(t).MemSource, Exclude: Exclusion{
		Sets: []types.SetName{mustSet(t, "RS-BAD"), mustSet(t, "FLTR-BAD"), mustSet(t, "FLTR-TOP")},
		ASNs: []types.ASN{4},
	}}
	// Inside FLTR-TOP, the excluded references denote nothing; AS-GOOD is
	// expanded without AS4. The filter-set asked for is expanded regardless.
	got, err := e.ExpandFilterSet(ctx, mustSet(t, "FLTR-TOP"))
	if want := "10.5.0.0/24 203.0.113.0/24"; err != nil || strings.Join(rangeList(got), " ") != want {
		t.Errorf("ExpandFilterSet = %v, %v; want %s", rangeList(got), err, want)
	}
	// The terms of a filter passed to EvalFilter are the caller's own.
	got, err = e.EvalFilter(ctx, mustFilter(t, "RS-BAD OR AS4 OR FLTR-BAD"))
	if want := "10.4.0.0/16 100.64.0.0/10 198.51.100.0/24"; err != nil || strings.Join(rangeList(got), " ") != want {
		t.Errorf("EvalFilter = %v, %v; want %s", rangeList(got), err, want)
	}
}
