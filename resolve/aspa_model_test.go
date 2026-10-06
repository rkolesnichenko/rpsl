package resolve_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// The ASPA model: aspaLocal's aut-num with random imports and exports toward
// a handful of peers, random customer as-sets and claims, random ASPAs. The
// oracle decides each lint/aspa-* rule from the generator's choices; every
// filter comes from a menu whose full-table classification is known.

const aspaLocal = types.ASN(64500)

var aspaPeers = []types.ASN{64501, 64502, 64503, 64504}

type aspaImp struct {
	peering string // "as", "router", "any", "set", "or"
	as, as2 types.ASN
	form    string // "import", "v6", "mp"
	filter  string
	full    bool
}

type aspaExp struct {
	to     types.ASN
	filter string
	sets   []string // the as-sets it names positively
}

type aspaSet struct {
	name    string
	members []string // "AS…" or a set name
	mbrs    string   // mbrs-by-ref: "", "MNT-A" or "ANY"
}

type aspaModel struct {
	imps   []aspaImp
	exps   []aspaExp
	up     []types.ASN               // AS-UP's members
	sets   []aspaSet                 // AS-C1, AS-C2
	namesL map[types.ASN]bool        // peers whose aut-num imports from aspaLocal
	aspas  map[types.ASN][]types.ASN // customer -> providers ([0]: AS0)
	texts  []string
}

// The filter menu: full tables, then filters that are not.
func aspaFilters(form string) (full, partial []string) {
	pfx := map[string]string{"import": "{10.0.0.0/8^+}", "v6": "{2001:db8::/32^+}", "mp": "{10.0.0.0/8^+, 2001:db8::/32^+}"}[form]
	full = []string{"ANY", "ANY AND NOT " + pfx, "NOT <^AS64999>"}
	partial = []string{"<^PeerAS+$>", "ANY AND community(65000:1)", pfx, "AS-C1", "PeerAS"}
	return full, partial
}

func randomASPAModel(r *rand.Rand) *aspaModel {
	m := &aspaModel{namesL: map[types.ASN]bool{}, aspas: map[types.ASN][]types.ASN{}}
	peer := func() types.ASN { return aspaPeers[r.IntN(len(aspaPeers))] }
	for n := 1 + r.IntN(4); n > 0; n-- {
		im := aspaImp{peering: []string{"as", "router", "any", "set", "or"}[r.IntN(5)], as: peer(), as2: peer(),
			form: []string{"import", "v6", "mp"}[r.IntN(3)]}
		full, partial := aspaFilters(im.form)
		if im.full = r.IntN(2) == 0; im.full {
			im.filter = full[r.IntN(len(full))]
		} else {
			im.filter = partial[r.IntN(len(partial))]
		}
		m.imps = append(m.imps, im)
	}
	exports := []aspaExp{
		{filter: "AS-C1", sets: []string{"AS-C1"}},
		{filter: "AS64500 OR AS-C2", sets: []string{"AS-C2"}},
		{filter: "ANY AND NOT AS-C1"},
		{filter: "<AS-C1>"},
		{filter: "AS-C2 AND {10.0.0.0/8^+}", sets: []string{"AS-C2"}},
	}
	for n := r.IntN(4); n > 0; n-- {
		e := exports[r.IntN(len(exports))]
		e.to = peer()
		m.exps = append(m.exps, e)
	}
	for _, p := range aspaPeers {
		if r.IntN(2) == 0 {
			m.up = append(m.up, p)
		}
		if r.IntN(2) == 0 {
			m.namesL[p] = true
		}
	}
	if len(m.up) == 0 {
		m.up = []types.ASN{aspaPeers[0]}
	}
	mbrs := func() string { return []string{"", "MNT-A", "ANY"}[r.IntN(3)] }
	c1 := aspaSet{name: "AS-C1", mbrs: mbrs()}
	for _, x := range []string{"AS64500", "AS64510", "AS64511", "AS64512", "AS-C2"} {
		if r.IntN(2) == 0 {
			c1.members = append(c1.members, x)
		}
	}
	c2 := aspaSet{name: "AS-C2", mbrs: mbrs()}
	for _, x := range []string{"AS64512", "AS64513"} {
		if r.IntN(2) == 0 {
			c2.members = append(c2.members, x)
		}
	}
	m.sets = []aspaSet{c1, c2}
	pick := func(from []types.ASN) []types.ASN {
		var out []types.ASN
		for _, a := range from {
			if r.IntN(2) == 0 {
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			out = from[:1]
		}
		return out
	}
	switch r.IntN(4) {
	case 1:
		m.aspas[aspaLocal] = []types.ASN{0}
	case 2, 3:
		m.aspas[aspaLocal] = pick(append(slices.Clone(aspaPeers), 64599))
	}
	for _, c := range []types.ASN{64510, 64511, 64512, 64513, 64514, 64515} {
		switch r.IntN(3) {
		case 1:
			m.aspas[c] = []types.ASN{0}
		case 2:
			m.aspas[c] = pick([]types.ASN{aspaLocal, 64598})
		}
	}
	m.texts = m.render()
	return m
}

func (m *aspaModel) render() []string {
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: %s\nas-name: L\n", aspaLocal)
	for _, im := range m.imps {
		var peering string
		switch im.peering {
		case "as":
			peering = im.as.String()
		case "router":
			peering = im.as.String() + " 192.0.2.1"
		case "any":
			peering = "AS-ANY"
		case "set":
			peering = "AS-UP"
		case "or":
			peering = "(" + im.as.String() + " OR " + im.as2.String() + ")"
		}
		switch im.form {
		case "import":
			fmt.Fprintf(&b, "import: from %s accept %s\n", peering, im.filter)
		case "v6":
			fmt.Fprintf(&b, "mp-import: afi ipv6.unicast from %s accept %s\n", peering, im.filter)
		case "mp":
			fmt.Fprintf(&b, "mp-import: from %s accept %s\n", peering, im.filter)
		}
	}
	for _, e := range m.exps {
		fmt.Fprintf(&b, "export: to %s announce %s\n", e.to, e.filter)
	}
	b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
	texts := []string{b.String()}
	for _, p := range aspaPeers {
		policy := ""
		if m.namesL[p] {
			policy = fmt.Sprintf("import: from %s accept ANY\n", aspaLocal)
		}
		texts = append(texts, fmt.Sprintf("aut-num: %s\nas-name: P\n%smnt-by: MNT-A\nsource: RIPE\n", p, policy))
	}
	var up []string
	for _, a := range m.up {
		up = append(up, a.String())
	}
	texts = append(texts, "as-set: AS-UP\nmembers: "+strings.Join(up, ", ")+"\nmnt-by: MNT-A\nsource: RIPE\n")
	for _, s := range m.sets {
		t := "as-set: " + s.name + "\n"
		if len(s.members) > 0 {
			t += "members: " + strings.Join(s.members, ", ") + "\n"
		}
		if s.mbrs != "" {
			t += "mbrs-by-ref: " + s.mbrs + "\n"
		}
		texts = append(texts, t+"mnt-by: MNT-A\nsource: RIPE\n")
	}
	texts = append(texts,
		"aut-num: AS64514\nas-name: M\nmember-of: AS-C1\nmnt-by: MNT-A\nsource: RIPE\n",
		"aut-num: AS64515\nas-name: M\nmember-of: AS-C1, AS-C2\nmnt-by: MNT-B\nsource: RIPE\n")
	return texts
}

func (m *aspaModel) set() *rpki.ASPAs {
	var as []rpki.ASPA
	for c, ps := range m.aspas {
		as = append(as, rpki.ASPA{Customer: c, Providers: ps})
	}
	s, err := rpki.NewASPAs(as)
	if err != nil {
		panic(err)
	}
	return s
}

// oracle returns the lint/aspa-* issues the model's choices imply, as
// "rule index peers afs|S" lines, sorted.
func (m *aspaModel) oracle(setPeers, index bool) []string {
	forward := map[types.ASN]bool{}
	anyPeering, setPeering := false, false
	for _, im := range m.imps {
		switch im.peering {
		case "as", "router":
			forward[im.as] = true
		case "or":
			forward[im.as], forward[im.as2] = true, true
		case "any":
			anyPeering = true
		case "set":
			setPeering = true
		}
	}
	for _, e := range m.exps {
		forward[e.to] = true
	}
	viaSets := map[types.ASN]bool{}
	if setPeering {
		for _, a := range m.up {
			if !forward[a] {
				viaSets[a] = true
			}
		}
	}
	real := maps.Clone(forward)
	if index {
		for p := range m.namesL {
			real[p] = true
		}
	}
	if setPeers {
		for p := range viaSets {
			real[p] = true
		}
	}
	var out []string
	providers, hasASPA := m.aspas[aspaLocal]
	lists := func(ps []types.ASN, x types.ASN) bool { return slices.Contains(ps, x) }
	// Missing providers: one line per import attribute and peer, with its families.
	if hasASPA {
		for i, im := range m.imps {
			if !im.full {
				continue
			}
			var cands []types.ASN
			switch im.peering {
			case "as":
				cands = []types.ASN{im.as}
			case "or":
				cands = []types.ASN{im.as, im.as2}
			case "set":
				cands = m.up
			}
			afs := map[string]string{"import": "[ipv4.unicast]", "v6": "[ipv6.unicast]", "mp": "[ipv4.unicast ipv6.unicast]"}[im.form]
			seen := map[types.ASN]bool{}
			for _, x := range cands {
				if seen[x] || !real[x] || lists(providers, x) {
					continue
				}
				seen[x] = true
				out = append(out, fmt.Sprintf("%s %d [%s] %s", consist.RuleASPAMissingProvider, i, x, afs))
			}
		}
	}
	// Stale providers.
	if hasASPA && providers[0] != 0 && !anyPeering {
		for _, p := range providers {
			if !forward[p] && !viaSets[p] {
				out = append(out, fmt.Sprintf("%s -1 [%s] []", consist.RuleASPAStaleProvider, p))
			}
		}
	}
	// Customer sets.
	members := func(s aspaSet) []types.ASN {
		var out []types.ASN
		for _, x := range s.members {
			if a, err := types.ParseASN(x); err == nil {
				out = append(out, a)
			}
		}
		claim := func(as types.ASN, mnt string, of ...string) {
			if slices.Contains(of, s.name) && (s.mbrs == "ANY" || (s.mbrs != "" && s.mbrs == mnt)) && !slices.Contains(out, as) {
				out = append(out, as)
			}
		}
		claim(64514, "MNT-A", "AS-C1")
		claim(64515, "MNT-B", "AS-C1", "AS-C2")
		return out
	}
	byName := map[string]aspaSet{"AS-C1": m.sets[0], "AS-C2": m.sets[1]}
	for i, e := range m.exps {
		for _, sn := range e.sets {
			for _, mm := range members(byName[sn]) {
				ps, ok := m.aspas[mm]
				if mm == aspaLocal || !ok || (ps[0] != 0 && lists(ps, aspaLocal)) {
					continue
				}
				out = append(out, fmt.Sprintf("%s %d [%s] []|%s", consist.RuleASPACustomerSet, i, mm, sn))
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// lintLines lints aspaLocal and renders its lint/aspa-* issues as the oracle
// does.
func lintLines(t *testing.T, label string, src resolve.PolicySource, aspas *rpki.ASPAs, setPeers bool) []string {
	t.Helper()
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: setPeers, ASPAs: aspas}
	issues, err := c.Lint(context.Background(), aspaLocal)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	var out []string
	for _, is := range issues {
		if !strings.HasPrefix(is.Rule, "lint/aspa-") {
			continue
		}
		var afs []string
		for _, af := range is.AFs {
			afs = append(afs, af.String())
		}
		line := fmt.Sprintf("%s %d %v [%s]", is.Rule, is.Index, is.Peers, strings.Join(afs, " "))
		if is.Rule == consist.RuleASPACustomerSet {
			set := strings.Fields(strings.TrimPrefix(is.Message, "announces "))[0]
			line += "|" + strings.TrimSuffix(set, ",")
		}
		out = append(out, line)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestModelASPA(t *testing.T) {
	seeds, full := resolve.ModelSeeds(300)
	counts := map[string]int{}
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 61))
		m := randomASPAModel(r)
		aspas := m.set()
		label := fmt.Sprintf("seed %d", seed)
		m.count(counts)
		l := &resolve.DumpLoader{Sources: []string{"RIPE"}, IndexPeers: true}
		if err := l.Read(strings.NewReader(strings.Join(m.texts, "\n"))); err != nil {
			t.Fatal(err)
		}
		db := irrtest.New(m.texts...).WithSources("RIPE")
		rs := rpsldtest.Serve(t, rpsldtest.Snapshot(t, m.texts, irrdq.SnapshotOptions{}, "RIPE"))
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, Pipeline: 8, Timeout: 5 * time.Second}
		rp := &irrd.Source{Addr: rs, Sources: []string{"RIPE"}, Pipeline: 8, Timeout: 5 * time.Second}
		backends := []struct {
			name  string
			src   resolve.PolicySource
			index bool
		}{
			{"memsource", resolve.NewMemSource(decodeAll(t, m.texts), "RIPE"), true},
			{"unchecked claims", uncheckedClaims{resolve.NewMemSource(decodeAll(t, m.texts), "RIPE"), decodeAll(t, m.texts)}, true},
			{"corpus", l.Source(), true},
			{"irrd", ir, false},
			{"whois", &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}, false},
			{"rpsld", rp, false},
			{"rpsld whois", &whois.Source{Addr: rs, Sources: []string{"RIPE"}, Timeout: 5 * time.Second}, false},
		}
		for _, b := range backends {
			for _, setPeers := range []bool{false, true} {
				want := m.oracle(setPeers, b.index)
				got := lintLines(t, label+" "+b.name, b.src, aspas, setPeers)
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Fatalf("%s %s setPeers=%v:\ngot\n%s\nwant\n%s\nobjects:\n%s\nASPAs %v", label, b.name, setPeers,
						strings.Join(got, "\n"), strings.Join(want, "\n"), strings.Join(m.texts, "\n"), m.aspas)
				}
			}
		}
		ir.Close()
		rp.Close()
	}
	t.Logf("cases: %v", counts)
	if !full {
		return
	}
	for _, k := range []string{
		consist.RuleASPAMissingProvider, consist.RuleASPAMissingProvider + " AS0", consist.RuleASPAMissingProvider + " both families",
		consist.RuleASPAStaleProvider, consist.RuleASPACustomerSet, consist.RuleASPACustomerSet + " AS0",
		consist.RuleASPACustomerSet + " claimant", "reverse peers change it", "set peers change it",
	} {
		if counts[k] < 10 {
			t.Errorf("%q: %d seeds, want at least 10", k, counts[k])
		}
	}
}

// uncheckedClaims is a Source whose MembersByRef returns every aut-num
// claiming member-of a set, mbrs-by-ref and maintainers unchecked, so the
// rule's own ClaimAllowed is what keeps a refused claim out.
type uncheckedClaims struct {
	*resolve.MemSource
	objs []object.Object
}

func (u uncheckedClaims) MembersByRef(_ context.Context, set object.NamedSet) ([]object.Object, error) {
	var out []object.Object
	for _, o := range u.objs {
		if an, ok := o.(object.AutNum); ok && slices.Contains(an.MemberOf, set.SetName()) {
			out = append(out, o)
		}
	}
	return out, nil
}

// count adds, for each case the oracle can tell apart, one to counts when
// this model gives an issue of it, so the test fails if the generator stops
// drawing one.
func (m *aspaModel) count(counts map[string]int) {
	seen := map[string]bool{}
	for _, idx := range []bool{false, true} {
		for _, sp := range []bool{false, true} {
			for _, line := range m.oracle(sp, idx) {
				rule := strings.Fields(line)[0]
				seen[rule] = true
				f := strings.Fields(line)
				member, _ := types.ParseASN(strings.Trim(f[2], "[]"))
				switch rule {
				case consist.RuleASPAMissingProvider:
					if m.aspas[aspaLocal][0] == 0 {
						seen[rule+" AS0"] = true
					}
					if strings.Contains(line, "ipv4.unicast ipv6.unicast") {
						seen[rule+" both families"] = true
					}
				case consist.RuleASPACustomerSet:
					if m.aspas[member][0] == 0 {
						seen[rule+" AS0"] = true
					}
					if member == 64514 || member == 64515 {
						seen[rule+" claimant"] = true
					}
				}
			}
		}
		if !slices.Equal(m.oracle(false, idx), m.oracle(true, idx)) {
			seen["set peers change it"] = true
		}
	}
	for _, sp := range []bool{false, true} {
		if !slices.Equal(m.oracle(sp, false), m.oracle(sp, true)) {
			seen["reverse peers change it"] = true
		}
	}
	for k := range seen {
		counts[k]++
	}
}
