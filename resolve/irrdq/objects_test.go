package irrdq

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// snapshotOf is a snapshot of one registry per corpus text list, named in
// order, route text kept.
func snapshotOf(t *testing.T, regs map[string][]string, order ...string) *Snapshot {
	t.Helper()
	var rs []*Registry
	for _, name := range order {
		r, err := NewRegistry(name, 0, corpusOf(t, true, regs[name]...))
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	snap, err := NewSnapshot(rs, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// Without KeepRouteText a registry refuses what needs a route's text, and
// still answers what does not.
func TestRouteTextNotKept(t *testing.T) {
	c := corpusOf(t, false, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n")
	r, err := NewRegistry("RIPE", 0, c)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := NewSnapshot([]*Registry{r}, SnapshotOptions{})
	for cmd, want := range map[string]string{
		"!mroute,192.0.2.0/24AS1": "F Route text is not kept by this mirror (rpsld -keep-route-text)\n",
		"!r192.0.2.0/24":          "F Route text is not kept by this mirror (rpsld -keep-route-text)\n",
		"!r192.0.2.0/24,o":        "A4\nAS1\nC\n",
		"-i origin AS1":           "%% ERROR: Route text is not kept by this mirror (rpsld -keep-route-text)\n\n\n",
		"-T route 192.0.2.0/24":   "%% ERROR: Route text is not kept by this mirror (rpsld -keep-route-text)\n\n\n",
		"-x 192.0.2.0/24":         "%% ERROR: Route text is not kept by this mirror (rpsld -keep-route-text)\n\n\n",
		"!gAS1":                   "A13\n192.0.2.0/24\nC\n",
		// -K needs no text: a route's key is its prefix and origin.
		"-K -i origin AS1": "route: 192.0.2.0/24\norigin: AS1\n\n\n",
		// Nothing to serve is no refusal.
		"!r198.51.100.0/24": "D\n",
		"-i origin AS2":     "%  No entries found for the selected source(s).\n\n\n",
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

func TestObjectTextDropsLeadingTrivia(t *testing.T) {
	c := corpusOf(t, true, "# a comment the dump had\n\nas-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	r, _ := NewRegistry("RIPE", 0, c)
	snap, _ := NewSnapshot([]*Registry{r}, SnapshotOptions{})
	if got := ask(t, snap, "!mas-set,AS-X"); !strings.HasPrefix(got, "A") || !strings.Contains(got, "\nas-set: AS-X\n") || strings.Contains(got, "#") {
		t.Errorf("!m: %q", got)
	}
}

// TestRouteSearchOptions pins a divergence: IRRd fails "!r…,o,l" with an
// internal error (it splits the parameter into exactly two parts); rpsld
// names the option.
func TestRouteSearchOptions(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, want := range map[string]string{
		"!r192.0.2.0/24,o,l": "F Invalid route search option: o,l\n",
		"!r::/129":           "F Invalid input for route search: ::/129\n",
		// IRRd names the whole parameter, option and all.
		"!rfoo,o": "F Invalid input for route search: foo,o\n",
		"!r,o":    "F Invalid input for route search: ,o\n",
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// "l" is the most specific less specific prefix over every selected
// registry together (IRRd sizes it in one query), not one per registry.
func TestRouteSearchOneLevelAcrossRegistries(t *testing.T) {
	snap := snapshotOf(t, map[string][]string{
		"RIPE": {"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n"},
		"RADB": {"route: 10.0.0.0/16\norigin: AS2\nsource: RADB\n"},
	}, "RIPE", "RADB")
	want := framed("route: 10.0.0.0/16\norigin: AS2\nsource: RADB")
	if got := ask(t, snap, "!r10.0.0.0/24,l"); got != want {
		t.Errorf("!r…,l: %q, want %q", got, want)
	}
	if got := ask(t, snap, "!r10.0.0.0/24,L,o"); got != "F Invalid route search option: L,o\n" {
		t.Errorf("!r…,L,o: %q", got)
	}
	if got := ask(t, snap, "!r10.0.0.0/24,L"); !strings.Contains(got, "10.0.0.0/8") || !strings.Contains(got, "10.0.0.0/16") {
		t.Errorf("!r…,L: %q", got)
	}
}

// "!m" keys are matched as IRRd matches primary keys: upper-cased and
// stripped, then compared with the canonical key, so a non-canonical
// spelling of an AS number or set name finds nothing.
func TestObjectKeys(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, found := range map[string]bool{
		"!maut-num, AS65001":            true,
		"!maut-num,AS065001":            false,
		"!maut-num,AS1.10":              false,
		"!mas-set, as-foo":              true,
		"!mas-set,RS-FOO":               false,
		"!mroute-set,RS-FOO":            true,
		"!mroute,192.0.2.0/24AS065001":  false,
		"!mroute,2001:db8::/32AS65001":  false, // a route6's key under route
		"!mroute6,2001:db8::/32AS65001": true,
		"!minet-rtr, rtr1.example.net":  true,
		"!mir,rtr1.example.net":         true,
		"!mfilter-set,fltr-foo":         true,
	} {
		got := ask(t, snap, cmd)
		if found != strings.HasPrefix(got, "A") || !found && got != "D\n" {
			t.Errorf("%s: %q, found %v", cmd, got, found)
		}
	}
}

// A class is matched case-sensitively, as IRRd matches it: "AUT-NUM" is no
// class, so not one the mirror refuses either.
func TestObjectClassCase(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, want := range map[string]string{
		"!mMNTNER,MNT-A": "D\n",
		"!mmntner,MNT-A": "F Class mntner is not kept by this mirror\n",
		"!minetnum,x":    "F Class inetnum is not kept by this mirror\n",
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// TestNotServed pins the IRRd commands rpsld refuses (Refinement 10).
func TestNotServed(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, want := range map[string]string{
		"!eAS-FOO":                     "F Command !e is not served by this mirror\n",
		"!e":                           "F Command !e is not served by this mirror\n",
		"!J-*":                         "F Command !J is not served by this mirror\n",
		"!fno-rpki-filter":             "F Command !fno-rpki-filter is not served by this mirror\n",
		"!FNO-RPKI-FILTER":             "F Command !fno-rpki-filter is not served by this mirror\n",
		"!fno-scope-filter":            "F Command !fno-scope-filter is not served by this mirror\n",
		"!fno-route-preference-filter": "F Command !fno-route-preference-filter is not served by this mirror\n",
		"!fsomething":                  "F Unrecognised command: f\n",
		"!oMNT-A":                      "F Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only\n",
		"!o":                           "F Missing parameter for o query\n",
		"-a AS65001":                   "%% ERROR: Flag -a is not served by this mirror\n\n\n",
		"-t aut-num":                   "%% ERROR: Flag -t is not served by this mirror\n\n\n",
		"-q sources":                   "%% ERROR: Flag -q is not served by this mirror\n\n\n",
		"-g RIPE:3:1-LAST":             "%% ERROR: Flag -g is not served by this mirror\n\n\n",
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// TestObjectsContext: a context that ends partway through an answer stops
// it — an "M" scan of many routes (checked every checkEvery routes) and the
// loops over many registries — and Do returns its error. countingCtx ends
// after n checks; with the checks removed only Do's own final check would
// run, n would never be passed, and Do would return no error.
func TestObjectsContext(t *testing.T) {
	var routes []string
	for i := 0; i < 20*checkEvery; i++ {
		routes = append(routes, fmt.Sprintf("route: 10.%d.%d.0/24\norigin: AS1\nsource: WIDE\n", i/256%256, i%256))
	}
	regs := map[string][]string{"WIDE": routes}
	order := []string{"WIDE"}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("R%d", i)
		regs[name] = []string{"as-set: AS-X\nmembers: AS2\nmbrs-by-ref: ANY\nsource: " + name + "\n"}
		order = append(order, name)
	}
	many := snapshotOf(t, regs, order...)
	wide := snapshotOf(t, map[string][]string{"WIDE": routes}, "WIDE") // the M scan's own checks
	for _, c := range []struct {
		snap *Snapshot
		line string
	}{
		{wide, "!r0.0.0.0/0,M"}, {wide, "-M 0.0.0.0/0"},
		{many, "!r0.0.0.0/0,M"}, {many, "-M 0.0.0.0/0"}, {many, "!maut-num,AS9"}, {many, "-T aut-num AS9"},
		{many, "-i origin AS9"}, {many, "-i members AS2"}, {many, "-T route 192.0.2.0/24"}, {many, "!r192.0.2.0/24,l"},
	} {
		snap, line := c.snap, c.line
		ctx := &countingCtx{Context: context.Background(), n: 5}
		s := NewSession(func() *Snapshot { return snap })
		s.Do(context.Background(), "!!")
		if _, err := s.Do(ctx, line); !errors.Is(err, context.Canceled) {
			t.Errorf("%s cancelled partway: %v (%d checks)", line, err, ctx.calls)
		}
		if ctx.calls > 10 {
			t.Errorf("%s went on for %d checks of an ended context", line, ctx.calls)
		}
	}
}

// "-V <agent> !<command>" runs the IRRd command (IRRd's handle_query, irrd
// issue #985); "-V <agent>" before anything else is a RIPE-style flag.
func TestUserAgentPrefix(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, want := range map[string]string{
		"-V bgpq4/1.0 !gAS65003":  framed("203.0.113.0/24 203.0.113.128/25"),
		"-V  !v":                  version, // an empty agent, split at single spaces
		"-V x !maut-num,AS65999":  "D\n",
		"-V x -T aut-num AS65999": noEntriesText,
		"-V x AS65999":            refusedLookup("AS65999"),
		"-V !v":                   noEntriesText, // "!v" is the agent; nothing else is asked
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
	got := replay(t, snap, "-V a !!\n!v\n")
	if got != version {
		t.Errorf("-V a !!: %q", got)
	}
}
