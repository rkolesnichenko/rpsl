package consist

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
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
		// Ruling R7: a set reaching AS-ANY, directly or nested, and a
		// peering-set naming AS-ANY, name no peer.
		{"as-set reaching AS-ANY", []string{"import: from AS2 accept AS2", "import: from AS-UP accept ANY"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"as-set reaching AS-ANY through a nested set", []string{"import: from AS2 accept AS2", "import: from AS-UP accept ANY"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"as-set reaching AS-ANY, in an AND", []string{"import: from AS2 accept AS2", "import: from AS-UP AND AS2 accept ANY"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"peering-set naming AS-ANY", []string{"import: from AS2 accept AS2", "import: from PRNG-UP accept ANY"}, []rpki.ASPA{aspa(1, 3)}, false, nil},
		{"as-set listing the peer", []string{"import: from AS2 accept AS2", "import: from AS-UP accept ANY"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider import 1 [AS2] " + v4 + ": " + missingAS2}},
		{"peering-set listing the peer", []string{"import: from AS2 accept AS2", "import: from PRNG-UP accept ANY"}, []rpki.ASPA{aspa(1, 3)},
			false, []string{"lint/aspa-missing-provider import 1 [AS2] " + v4 + ": " + missingAS2}},
		// Ruling R9: a set template is instantiated for the session's peer.
		{"template naming the peer", []string{"import: from AS1:AS-UP:PeerAS accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + missingAS2}},
		{"template reaching AS-ANY", []string{"import: from AS1:AS-UP:PeerAS accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"template's set missing", []string{"import: from AS1:AS-UP:PeerAS accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
		{"template in a peering-set", []string{"import: from PRNG-UP accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, []string{"lint/aspa-missing-provider import 0 [AS2] " + v4 + ": " + missingAS2}},
		{"template in a peering-set reaching AS-ANY", []string{"import: from PRNG-UP accept ANY", "export: to AS2 announce AS1"},
			[]rpki.ASPA{aspa(1, 3)}, false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			objs := []string{autNum(2), autNum(3)} // other aut-nums, unless the case names its own
			switch c.name {
			case "OR with AS-ANY, toward another peer":
				objs = append(objs, autNum(5))
			case "reverse-only peer through a set":
				objs = []string{autNum(2), autNum(3, "export: to AS1 announce AS3")}
			case "as-set reaching AS-ANY", "as-set reaching AS-ANY, in an AND":
				objs = append(objs, asSetText("AS-UP", "AS3, AS2, AS-ANY"))
			case "as-set reaching AS-ANY through a nested set":
				objs = append(objs, asSetText("AS-UP", "AS3, AS2, AS-MID"), asSetText("AS-MID", "AS-ANY"))
			case "as-set listing the peer":
				objs = append(objs, asSetText("AS-UP", "AS3, AS2"))
			case "peering-set naming AS-ANY":
				objs = append(objs, peeringSetText("PRNG-UP", "AS-ANY"))
			case "peering-set listing the peer":
				objs = append(objs, peeringSetText("PRNG-UP", "AS2"))
			case "template naming the peer":
				objs = append(objs, asSetText("AS1:AS-UP:AS2", "AS2"))
			case "template reaching AS-ANY":
				objs = append(objs, asSetText("AS1:AS-UP:AS2", "AS3, AS-ANY"))
			case "template in a peering-set":
				objs = append(objs, peeringSetText("PRNG-UP", "AS1:AS-UP:PeerAS"), asSetText("AS1:AS-UP:AS2", "AS2"))
			case "template in a peering-set reaching AS-ANY":
				objs = append(objs, peeringSetText("PRNG-UP", "AS1:AS-UP:PeerAS"), asSetText("AS1:AS-UP:AS2", "AS2, AS-ANY"))
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
		// Ruling R8: a set a peering reaches that the Source lacks could
		// name the provider.
		{"missing set", []string{"import: from AS2 accept ANY", "import: from AS-UPSTREAMS accept ANY"}, aspa(1, 2, 3), nil},
		{"missing nested set", []string{"import: from AS2 accept ANY", "import: from AS-UP accept ANY"}, aspa(1, 2, 3), nil},
		{"every set present", []string{"import: from AS2 accept ANY", "import: from AS-UP accept ANY"}, aspa(1, 2, 3), []string{stale(3)}},
		{"missing peering-set", []string{"import: from AS2 accept ANY", "import: from PRNG-UP accept ANY"}, aspa(1, 2, 3), nil},
		{"missing set in a peering-set", []string{"import: from AS2 accept ANY", "import: from PRNG-UP accept ANY"}, aspa(1, 2, 3), nil},
		{"missing peering-set in a peering-set", []string{"import: from AS2 accept ANY", "import: from PRNG-UP accept ANY"}, aspa(1, 2, 3), nil},
		{"every peering-set present", []string{"import: from AS2 accept ANY", "import: from PRNG-UP accept ANY"}, aspa(1, 2, 3), []string{stale(3)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			objs := []string{autNum(1, c.lines...), autNum(2), autNum(3)}
			switch c.name {
			case "missing nested set":
				objs = append(objs, asSetText("AS-UP", "AS2, AS-ELSEWHERE"))
			case "every set present":
				objs = append(objs, asSetText("AS-UP", "AS2, AS-ELSEWHERE"), asSetText("AS-ELSEWHERE", "AS4"))
			case "missing set in a peering-set":
				objs = append(objs, peeringSetText("PRNG-UP", "AS-ELSEWHERE"))
			case "missing peering-set in a peering-set":
				objs = append(objs, peeringSetText("PRNG-UP", "PRNG-ELSEWHERE"))
			case "every peering-set present":
				objs = append(objs, peeringSetText("PRNG-UP", "PRNG-ELSEWHERE"), peeringSetText("PRNG-ELSEWHERE", "AS-ELSEWHERE"),
					asSetText("AS-ELSEWHERE", "AS4"))
			}
			ch := checker(t, objs...)
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

// The customer-set fixture: AS-CUST lists AS1 (the announcer), AS10, AS11
// and AS-NESTED (AS12); AS13 claims membership with MNT-A, which
// mbrs-by-ref admits, AS14 with MNT-B, which it does not.
var customerObjects = []string{
	"as-set: AS-CUST\nmembers: AS1, AS10, AS11, AS-NESTED\nmbrs-by-ref: MNT-A\nmnt-by: MNT-A\nsource: RIPE\n",
	"as-set: AS-NESTED\nmembers: AS12\nmnt-by: MNT-A\nsource: RIPE\n",
	"aut-num: AS13\nas-name: X\nmember-of: AS-CUST\nmnt-by: MNT-A\nsource: RIPE\n",
	"aut-num: AS14\nas-name: X\nmember-of: AS-CUST\nmnt-by: MNT-B\nsource: RIPE\n",
}

var customerASPAs = []rpki.ASPA{
	aspa(10, 1), // names AS1: fine
	aspa(11, 2), // does not: a finding
	aspa(12, 2), // nested: not followed
	aspa(13, 0), // AS0: a finding
	aspa(14, 2), // a refused claim: not a member
}

func TestASPACustomerSet(t *testing.T) {
	finding := func(attr string, m int, as0 bool) string {
		msg := fmt.Sprintf("announces AS-CUST, whose member AS%d has an ASPA that does not list AS1 as a provider", m)
		if as0 {
			msg = fmt.Sprintf("announces AS-CUST, whose member AS%d declares no transit providers (AS0)", m)
		}
		return fmt.Sprintf("lint/aspa-customer-set %s 0 [AS%d] []: %s", attr, m, msg)
	}
	both := []string{finding("export", 11, false), finding("export", 13, true)}
	for _, c := range []struct {
		name string
		line string
		want []string
	}{
		{"announced", "export: to AS2 announce AS-CUST", both},
		{"in an OR", "export: to AS2 announce AS1 OR AS-CUST", both},
		{"mp-export", "mp-export: to AS2 announce AS-CUST", []string{finding("mp-export", 11, false), finding("mp-export", 13, true)}},
		{"announcer's own ASPA", "export: to AS2 announce AS-CUST", both},
		{"under NOT", "export: to AS2 announce ANY AND NOT AS-CUST", nil},
		{"inside a regexp", "export: to AS2 announce <AS-CUST>", nil},
		{"missing set", "export: to AS2 announce AS-MISSING", nil},
		{"the nested set itself", "export: to AS2 announce AS-NESTED", []string{
			"lint/aspa-customer-set export 0 [AS12] []: announces AS-NESTED, whose member AS12 has an ASPA that does not list AS1 as a provider"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ch := checker(t, append([]string{autNum(1, c.line), autNum(2)}, customerObjects...)...)
			aspas := customerASPAs
			if c.name == "announcer's own ASPA" {
				aspas = append([]rpki.ASPA{aspa(1, 99)}, aspas...)
			}
			got := lintASPA(t, ch, 1, newASPAs(t, aspas...), RuleASPACustomerSet)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// The filter parser builds no AS expression with an operator, so EXCEPT's
// right side is tested on a constructed filter.
func TestPositiveASSetsExcept(t *testing.T) {
	mk := func(s string) policy.ASSetRef {
		n, err := types.ParseSetName(s)
		if err != nil {
			t.Fatal(err)
		}
		return policy.ASSetRef{Name: n}
	}
	f := policy.FilterASExpr{AS: policy.ASExprBinary{Op: policy.ASExcept, L: mk("AS-NESTED"), R: mk("AS-CUST")}}
	got := positiveASSets(nil, f)
	if len(got) != 1 || got[0].String() != "AS-NESTED" {
		t.Errorf("got %v, want [AS-NESTED]", got)
	}
}

func asSetText(name, members string) string {
	return "as-set: " + name + "\nmembers: " + members + "\nmnt-by: MNT-A\nsource: RIPE\n"
}

func peeringSetText(name, peering string) string {
	return "peering-set: " + name + "\npeering: " + peering + "\nmnt-by: MNT-A\nsource: RIPE\n"
}
