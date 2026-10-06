package consist

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

func newASPAs(t *testing.T, as ...rpki.ASPA) *rpki.ASPAs {
	t.Helper()
	s, err := rpki.NewASPAs(as)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func aspa(customer uint32, providers ...uint32) rpki.ASPA {
	a := rpki.ASPA{Customer: types.ASN(customer)}
	for _, p := range providers {
		a.Providers = append(a.Providers, types.ASN(p))
	}
	return a
}

// lintASPA lints as with aspas and returns its issues of the given rules
// (none given: every lint/aspa-* rule) as "rule attr index peers afs:
// message", sorted, so a test reads one rule without the others.
func lintASPA(t *testing.T, c *Checker, as types.ASN, aspas *rpki.ASPAs, rules ...string) []string {
	t.Helper()
	c.ASPAs = aspas
	issues, err := c.Lint(context.Background(), as)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, is := range issues {
		if !strings.HasPrefix(is.Rule, "lint/aspa-") || (len(rules) > 0 && !slices.Contains(rules, is.Rule)) {
			continue
		}
		var afs []string
		for _, af := range is.AFs {
			afs = append(afs, af.String())
		}
		out = append(out, fmt.Sprintf("%s %s %d %v %v: %s", is.Rule, is.Attr, is.Index, is.Peers, afs, is.Message))
	}
	slices.Sort(out)
	return out
}

const (
	missingAS2 = "imports a full table from AS2, but AS1's ASPA does not list it as a provider"
	as0AS2     = "imports a full table from AS2, but AS1's ASPA declares no transit providers (AS0)"
)

func TestASPAMissingProvider(t *testing.T) {
	v4 := "[ipv4.unicast]"
	for _, c := range []struct {
		name     string
		lines    []string
		aspas    []rpki.ASPA
		setPeers bool
		want     []string
	}{
		{"ANY, provider missing", []string{"import: from AS2 accept ANY"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + missingAS2}},
		{"ANY, provider listed", []string{"import: from AS2 accept ANY"}, []rpki.ASPA{aspa(1, 2)}, false, nil},
		{"ANY, AS0 ASPA", []string{"import: from AS2 accept ANY"}, []rpki.ASPA{aspa(1, 0)},
			false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + as0AS2}},
		{"no ASPA", []string{"import: from AS2 accept ANY"}, nil, false, nil},
		{"bogon filter", []string{"import: from AS2 accept ANY AND NOT {10.0.0.0/8^+}"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + missingAS2}},
		{"negated regexp", []string{"import: from AS2 accept NOT <^AS64999>"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + missingAS2}},
		{"positive regexp", []string{"import: from AS2 accept <^PeerAS+$>"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"positive community", []string{"import: from AS2 accept ANY AND community(65000:1)"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"prefix list", []string{"import: from AS2 accept {10.0.0.0/8^+}"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"imports nothing", []string{"import: from AS2 accept NOT {0.0.0.0/0^0-32}"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"undecided: router not given", []string{"import: from AS2 192.0.2.1 accept ANY"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"both families", []string{"mp-import: from AS2 accept ANY"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider mp-import 0 [AS2] [ipv4.unicast ipv6.unicast]: " + missingAS2}},
		{"through AS-ANY", []string{"import: from AS-ANY accept ANY", "export: to AS2 announce AS1"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"through a set, without SetPeers", []string{"import: from AS-PEERS accept ANY"}, []rpki.ASPA{aspa(1, 2)}, false, nil},
		{"through a set, with SetPeers", []string{"import: from AS-PEERS accept ANY"}, []rpki.ASPA{aspa(1, 2)},
			true, []string{"lint/aspa-missing-provider import 0 [AS3] " + v4 + ": imports a full table from AS3, but AS1's ASPA does not list it as a provider"}},
		{"OR with AS-ANY, toward the named AS", []string{"import: from AS2 OR AS-ANY accept ANY"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"OR with AS-ANY, toward another peer", []string{"import: from AS2 OR AS-ANY accept ANY", "export: to AS5 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"AS-ANY EXCEPT an AS", []string{"import: from AS-ANY EXCEPT AS3 accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"reverse-only peer through a set", []string{"import: from AS-PEERS accept ANY"}, []rpki.ASPA{aspa(1, 2)}, false,
			[]string{"lint/aspa-missing-provider import 0 [AS3] " + v4 + ": " + "imports a full table from AS3, but AS1's ASPA does not list it as a provider"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			objs := []string{autNum(2), autNum(3)} // other aut-nums, unless the case names its own
			switch c.name {
			case "OR with AS-ANY, toward another peer":
				objs = append(objs, autNum(5))
			case "reverse-only peer through a set":
				objs = []string{autNum(2), autNum(3, "export: to AS1 announce AS3")}
			}
			ch := checker(t, append([]string{autNum(1, c.lines...)}, objs...)...)
			ch.SetPeers = c.setPeers
			var aspas *rpki.ASPAs
			if c.aspas != nil {
				aspas = newASPAs(t, c.aspas...)
			}
			got := lintASPA(t, ch, 1, aspas, RuleASPAMissingProvider)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// Without ASPAs, Lint is unchanged: no lint/aspa-* issue, whatever the policy.
func TestASPARulesOffWithoutASPAs(t *testing.T) {
	ch := checker(t, autNum(1, "import: from AS2 accept ANY"), autNum(2))
	if got := lintASPA(t, ch, 1, nil); len(got) != 0 {
		t.Errorf("issues without ASPAs: %v", got)
	}
}

func TestASPAStaleProvider(t *testing.T) {
	stale := func(p int) string {
		return fmt.Sprintf("lint/aspa-stale-provider  -1 [AS%d] []: AS1's ASPA lists AS%d as a provider, but no peering of AS1 names it", p, p)
	}
	for _, c := range []struct {
		name  string
		lines []string
		aspa  rpki.ASPA
		want  []string
	}{
		{"named", []string{"import: from AS2 accept ANY"}, aspa(1, 2), nil},
		{"one not named", []string{"import: from AS2 accept ANY"}, aspa(1, 2, 3), []string{stale(3)}},
		{"named in an export", []string{"export: to AS3 announce AS1"}, aspa(1, 3), nil},
		{"through a set", []string{"import: from AS-PEERS accept {10.0.0.0/8^+}"}, aspa(1, 3), nil},
		{"AS-ANY could name it", []string{"import: from AS-ANY accept ANY"}, aspa(1, 3), nil},
		{"AS0 ASPA", []string{"import: from AS2 accept ANY"}, aspa(1, 0), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			ch := checker(t, autNum(1, c.lines...), autNum(2), autNum(3))
			got := lintASPA(t, ch, 1, newASPAs(t, c.aspa), RuleASPAStaleProvider)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// Review Focus 5: hundreds of providers no peering names give one Info
// issue each, in Lint's own order (issues sort by line, index, rule and
// message), the same on every run.
func TestASPAStaleManyProviders(t *testing.T) {
	providers := []uint32{2}
	for p := uint32(100); p < 400; p++ {
		providers = append(providers, p)
	}
	ch := checker(t, autNum(1, "import: from AS2 accept ANY"), autNum(2))
	ch.ASPAs = newASPAs(t, aspa(1, providers...))
	run := func() []Issue {
		issues, err := ch.Lint(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		var out []Issue
		for _, is := range issues {
			if is.Rule == RuleASPAStaleProvider {
				out = append(out, is)
			}
		}
		return out
	}
	first := run()
	if len(first) != 300 {
		t.Fatalf("%d issues, want 300", len(first))
	}
	seen := map[types.ASN]bool{}
	for _, is := range first {
		if len(is.Peers) != 1 || is.Severity.String() != "info" {
			t.Fatalf("issue %+v: want one peer, info", is)
		}
		seen[is.Peers[0]] = true
	}
	for p := types.ASN(100); p < 400; p++ {
		if !seen[p] {
			t.Errorf("no issue for AS%d", p)
		}
	}
	second := run()
	for i := range first {
		if first[i].Message != second[i].Message {
			t.Fatalf("issue %d differs between runs: %q, %q", i, first[i].Message, second[i].Message)
		}
	}
}
