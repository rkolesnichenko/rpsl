package irrdq

import (
	"strings"
	"testing"
)

const noEntriesText = "%  No entries found for the selected source(s).\n\n\n"

func TestRIPEInverse(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, wantPrefix := range map[string]string{
		"-i members AS-BAR":              "as-set:",    // AS-FOO lists AS-BAR
		"-i mbrs-by-ref MNT-A":           "as-set:",    // AS-REF; RS-INNER too
		"-i members 192.0.2.0/24":        "route-set:", // RS-FOO
		"-i members as65001":             "as-set:",    // AS-FOO, then RS-FOO
		"-T route-set -i members AS-BAR": "route-set:",
	} {
		if got := ask(t, snap, cmd); !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("%s: %q", cmd, got)
		}
	}
	// IRRd upper-cases the value, and stores an IPv6 prefix lower-case: RS-FOO's
	// 2001:db8::/32 is never found (recorded, ripe/-i mp-members 2001:db8::/32).
	for _, cmd := range []string{"-i members AS-NOSUCH", "-i origin AS065001", "-i mbrs-by-ref MNT-B", "-T aut-num -i members AS-BAR",
		"-i mp-members 2001:db8::/32"} {
		if got := ask(t, snap, cmd); got != noEntriesText {
			t.Errorf("%s: %q", cmd, got)
		}
	}
	// -i is case-sensitive in the attribute, as IRRd's is.
	if got := ask(t, snap, "-i ORIGIN AS65001"); !strings.HasPrefix(got, "%% ERROR: Inverse attribute search not supported for ORIGIN,") {
		t.Errorf("-i ORIGIN: %q", got)
	}
}

func TestRIPEKeepsConnectionWithK(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	got := replay(t, snap, "-k -T as-set AS-NOSUCH\n-T as-set AS-NOSUCH\n")
	want := noEntriesText + noEntriesText
	if got != want {
		t.Errorf("-k: %q", got)
	}
}

// A query line is read left to right as IRRd reads it: a search takes the
// flags given before it, -T restricts the next search only, the last search
// answers, and -i and the route searches end the query.
func TestRIPEQueryOrder(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for cmd, wantPrefix := range map[string]string{
		"-T aut-num AS-NOSUCH -T as-set AS65001 AS-FOO": "",                         // each -T for one search: refused below
		"-T as-set AS-FOO -K":                           "as-set:         AS-FOO\n", // -K after the search
		"-K -T as-set AS-FOO":                           "as-set: AS-FOO\nmembers: AS65001\n",
		"-i origin AS65003 -T aut-num":                  "route:          203.0.113.0/24\n",
		"-x 192.0.2.0/25 AS65001":                       "route:          192.0.2.0/25\n",
		"-F -V client-1.0 -r -T aut-num AS65001":        "aut-num:        AS65001\n", // IRRd accepts -F and -V
		"-T route,route6 -i origin AS65001":             "route:",
		"-T as-set AS65001 -T as-set AS-FOO":            "as-set:         AS-FOO\n",
	} {
		if got := ask(t, snap, cmd); !strings.HasPrefix(got, wantPrefix) || !strings.HasSuffix(got, "\n\n\n") {
			t.Errorf("%s: %q", cmd, got)
		}
	}
	for cmd, want := range map[string]string{
		"-rK AS65001":         "%% ERROR: Unrecognised flag/search: rK\n\n\n", // no combined flags
		"- AS65001":           "%% ERROR: Unrecognised flag/search: \n\n\n",
		"-V":                  "%% ERROR: Missing argument for flag/search: V\n\n\n",
		"-T":                  "%% ERROR: Missing argument for flag/search: T\n\n\n",
		"-s":                  "%% ERROR: Missing argument for flag/search: s\n\n\n",
		"-x":                  "%% ERROR: Missing argument for flag/search: x\n\n\n",
		"-i":                  "%% ERROR: Missing argument for flag/search: i\n\n\n",
		"-M foo":              "%% ERROR: Invalid input for route search: foo\n\n\n",
		"-x 192.0.2.1/24":     "%% ERROR: Invalid input for route search: 192.0.2.1/24\n\n\n",
		"-k":                  noEntriesText,
		"-T aut-num MNT-A":    noEntriesText, // only kept classes asked for: certain
		"-T inet-rtr rtr9":    noEntriesText,
		"-T foo X":            noEntriesText, // no class foo, in IRRd either
		"-T foo,mntner X":     "%% ERROR: Class mntner is not kept by this mirror\n\n\n",
		"-s RADB,NOSUCH X":    "%% ERROR: One or more selected sources are unavailable.\n\n\n",
		"-l 192.0.2.0/24":     noEntriesText,
		"-T as-set AS-NOSUCH": noEntriesText,
		"-T aut-num AS65999":  noEntriesText,
		// Without -T, IRRd's text search also answers with classes the
		// mirror does not keep: refused.
		"AS65999":                    refusedLookup("AS65999"),    // an as-block may cover it
		"10.0.0.0/8":                 refusedLookup("10.0.0.0/8"), // an inetnum may be it
		"AS-FOO -K":                  refusedLookup("AS-FOO"),
		"-T route AS-NOSUCH AS65001": refusedLookup("AS65001"), // -T spent on AS-NOSUCH
		"-T aut-num AS-NOSUCH -T as-set AS65001 AS-FOO": refusedLookup("AS-FOO"),
		"RIPE::AS-FOO": refusedLookup("RIPE::AS-FOO"),
	} {
		if got := ask(t, snap, cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// A plain prefix or address is IRRd's text search: the routes of that
// prefix and every less specific one.
func TestRIPEPlainPrefixLessSpecific(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	got := ask(t, snap, "-T route 192.0.2.0/25")
	if n := strings.Count(got, "\nsource:"); n != 4 || !strings.HasPrefix(got, "route:          192.0.2.0/24\n") {
		t.Errorf("192.0.2.0/25: %d objects: %q", n, got)
	}
	got = ask(t, snap, "-T route,route6 192.0.2.1")
	if n := strings.Count(got, "\nsource:"); n != 4 {
		t.Errorf("192.0.2.1: %d objects: %q", n, got)
	}
	if got := ask(t, snap, "-T route6 192.0.2.0/25"); got != noEntriesText {
		t.Errorf("-T route6 192.0.2.0/25: %q", got)
	}
}

// An aut-num, an inet-rtr or a route named by its key is answered from every
// selected registry, as a set is: IRRd's text search has no precedence.
func TestRIPEPlainEveryRegistry(t *testing.T) {
	snap := snapshotOf(t, map[string][]string{
		"RIPE": {"aut-num: AS1\nas-name: A\nsource: RIPE\n", "inet-rtr: r.example\nsource: RIPE\n",
			"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n"},
		"RADB": {"aut-num: AS1\nas-name: B\nsource: RADB\n", "inet-rtr: R.EXAMPLE\nsource: RADB\n",
			"route: 192.0.2.0/24\norigin: AS1\nsource: RADB\n"},
	}, "RIPE", "RADB")
	for _, key := range []string{"AS1", "r.example", "192.0.2.0/24AS1", "192.0.2.0/24as1"} {
		got := ask(t, snap, "-T aut-num,inet-rtr,route "+key)
		if !strings.Contains(got, "source: RIPE\n\n") || !strings.HasSuffix(got, "source: RADB\n\n\n") {
			t.Errorf("%s: %q", key, got)
		}
	}
	if got := ask(t, snap, "-K -T inet-rtr r.example"); got != "inet-rtr: R.EXAMPLE\n\n\n" {
		t.Errorf("-K r.example: %q", got)
	}
	if got := ask(t, snap, "-T route 192.0.2.0/24AS2"); got != noEntriesText {
		t.Errorf("192.0.2.0/24AS2: %q", got)
	}
}

// "-s" changes the session's selection, even when the query then fails.
func TestRIPESourcesStick(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	got := replay(t, snap, "!!\n-s RADB -Z\n!s-lc\n")
	want := "%% ERROR: Unrecognised flag/search: Z\n\n\n" + framed("RADB")
	if got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// TestRIPEInverseOrder: an inverse search answers in the order of class,
// primary key, then the registries' order — never the order objects were
// loaded in, which a mirror's delta changes.
func TestRIPEInverseOrder(t *testing.T) {
	ripe := []string{
		"route-set: RS-Z\nmembers: AS1\nmbrs-by-ref: MNT-A\nsource: RIPE\n",
		"as-set: AS-Z\nmembers: AS1\nmbrs-by-ref: MNT-A\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS2\nmember-of: AS-Z, RS-Z\nmnt-by: MNT-A\nsource: RIPE\n",
		"as-set: AS-A\nmembers: AS1\nmbrs-by-ref: MNT-A\nsource: RIPE\n",
		"aut-num: AS7\nas-name: SEVEN\nmember-of: AS-Z\nmnt-by: MNT-A\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-Z\nmnt-by: MNT-A\nsource: RIPE\n",
		"route: 10.0.0.0/8\norigin: AS1\nmember-of: RS-Z\nmnt-by: MNT-A\nsource: RIPE\n",
	}
	radb := []string{
		"as-set: AS-A\nmembers: AS1\nsource: RADB\n",
		"aut-num: AS3\nas-name: THREE\nmember-of: AS-Z\nsource: RADB\n",
	}
	order := func(texts []string, reverse bool) []string {
		out := append([]string(nil), texts...)
		if reverse {
			for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
				out[i], out[j] = out[j], out[i]
			}
		}
		return out
	}
	keys := func(answer string) []string {
		var out []string
		for _, block := range strings.Split(strings.TrimSpace(answer), "\n\n") {
			lines := strings.SplitN(block, "\n", 3)
			out = append(out, strings.Join(strings.Fields(lines[0]+" "+lines[1]), " "))
		}
		return out
	}
	want := map[string][]string{
		"-i members AS1":       {"as-set: AS-A members: AS1", "as-set: AS-A members: AS1", "as-set: AS-Z members: AS1", "route-set: RS-Z members: AS1"},
		"-i member-of AS-Z":    {"aut-num: AS3 as-name: THREE", "aut-num: AS7 as-name: SEVEN", "route: 192.0.2.0/24 origin: AS2"},
		"-i member-of RS-Z":    {"route: 10.0.0.0/8 origin: AS1", "route: 192.0.2.0/24 origin: AS1", "route: 192.0.2.0/24 origin: AS2"},
		"-i mbrs-by-ref MNT-A": {"as-set: AS-A members: AS1", "as-set: AS-Z members: AS1", "route-set: RS-Z members: AS1"},
	}
	for _, reverse := range []bool{false, true} {
		snap, err := NewSnapshot([]*Registry{mustRegistry(t, "RIPE", order(ripe, reverse)...), mustRegistry(t, "RADB", order(radb, reverse)...)}, SnapshotOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for cmd, w := range want {
			got := keys(ask(t, snap, cmd))
			if strings.Join(got, "|") != strings.Join(w, "|") {
				t.Errorf("reversed %v, %s:\n got %q\nwant %q", reverse, cmd, got, w)
			}
		}
		// Two registries' objects of one key keep the registries' order.
		if got := ask(t, snap, "-i members AS1"); !strings.Contains(got, "source: RIPE\n\nas-set: AS-A\nmembers: AS1\nsource: RADB") {
			t.Errorf("reversed %v: the RIPE and RADB AS-A out of order:\n%s", reverse, got)
		}
	}
}
