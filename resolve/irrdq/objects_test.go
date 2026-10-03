package irrdq

import (
	"context"
	"errors"
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
		"192.0.2.0/24":            "%% ERROR: Route text is not kept by this mirror (rpsld -keep-route-text)\n\n\n",
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

// A context that has ended is reported, whatever the command.
func TestObjectsHonourContext(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, cmd := range []string{"!r0.0.0.0/0,M", "!maut-num,AS65001", "-i origin AS65001", "AS-FOO"} {
		s := NewSession(func() *Snapshot { return snap })
		if _, err := s.Do(ctx, cmd); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", cmd, err)
		}
	}
}
