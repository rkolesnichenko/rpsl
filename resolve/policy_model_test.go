package resolve_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// peval against a per-route model of RFC 2622 §6: random import policies of
// one aut-num — factors with several peer clauses, lists, EXCEPT and REFINE,
// peerings by AS, as-set, AS-ANY, AS expression and peering-set, routers by
// address, inet-rtr and rtr-set, afi clauses and protocols — are decided route
// by route and session by session from the model, and the first clause of
// peval's Policy that accepts a route must be the model's, with its actions.

const localAS = types.ASN(64500)

var (
	peerRtrs     = []string{"", "192.0.2.1", "192.0.2.2", "192.0.2.9"}
	localRtrs    = []string{"", "198.51.100.1", "198.51.100.3"}
	modelActions = []string{"pref = 10", "med = 5", "community.append(1:3)"}
	families     = []types.AddrFamily{{AFI: types.AFIv4, SAFI: types.SAFIUnicast}, {AFI: types.AFIv6, SAFI: types.SAFIUnicast}}
	routerTexts  = []string{
		"inet-rtr: r1.example.net\nlocal-as: AS65001\nifaddr: 192.0.2.1 masklen 24\nmnt-by: MNT-A\nsource: RIPE\n",
		"inet-rtr: r2.example.net\nlocal-as: AS65002\nifaddr: 192.0.2.2 masklen 24\nmnt-by: MNT-A\nsource: RIPE\n",
		"rtr-set: RTRS-LOCAL\nmembers: 198.51.100.1, 198.51.100.2\nmnt-by: MNT-A\nsource: RIPE\n",
	}
)

type mPeering struct {
	kind    string // "as", "set", "any", "or", "except", "prng"
	as, as2 types.ASN
	set     string
	peerRtr string // "", an address, or an inet-rtr name
	atRtr   string // "", an address, or RTRS-LOCAL
}

func (p *mPeering) text() string {
	var s string
	switch p.kind {
	case "as":
		s = p.as.String()
	case "set", "prng":
		s = p.set
	case "any":
		s = "AS-ANY"
	case "or":
		s = "(" + p.as.String() + " OR " + p.as2.String() + ")"
	case "except":
		s = "(" + p.set + " EXCEPT " + p.as.String() + ")"
	}
	if p.peerRtr != "" {
		s += " " + p.peerRtr
	}
	if p.atRtr != "" {
		s += " at " + p.atRtr
	}
	return s
}

func (p *mPeering) plainAny() bool { return p.kind == "any" && p.peerRtr == "" && p.atRtr == "" }

type mPeerAct struct {
	p       *mPeering
	actions []string
}

type mFactor struct {
	peers  []mPeerAct
	filter *mFilter
}

func (f mFactor) text() string {
	var b strings.Builder
	for _, pa := range f.peers {
		fmt.Fprintf(&b, "from %s ", pa.p.text())
		if len(pa.actions) > 0 {
			fmt.Fprintf(&b, "action %s; ", strings.Join(pa.actions, "; "))
		}
	}
	return b.String() + "accept " + f.filter.text()
}

type mAttr struct {
	mp          bool
	afi         string // mp-import only: "", "ipv4.unicast" or "ipv6.unicast"
	protocol    string // "" or "OSPF"
	kind        string // "factor", "list", "except", "refine"
	left, right []mFactor
}

func block(fs []mFactor, braces bool) string {
	if len(fs) == 1 && !braces {
		return fs[0].text()
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = f.text()
	}
	return "{ " + strings.Join(parts, "; ") + "; }"
}

func (a *mAttr) line() string {
	var b strings.Builder
	if a.mp {
		b.WriteString("mp-import: ")
	} else {
		b.WriteString("import: ")
	}
	if a.protocol != "" {
		b.WriteString("protocol " + a.protocol + " ")
	}
	if a.afi != "" {
		b.WriteString("afi " + a.afi + " ")
	}
	switch a.kind {
	case "factor":
		b.WriteString(block(a.left, false))
	case "list":
		b.WriteString(block(a.left, true))
	case "except":
		b.WriteString(block(a.left, false) + " except " + block(a.right, true))
	case "refine":
		b.WriteString(block(a.left, false) + " refine " + block(a.right, true))
	}
	return b.String()
}

func (a *mAttr) applies(af types.AddrFamily) bool {
	switch {
	case !a.mp:
		return af.AFI == types.AFIv4
	case a.afi == "":
		return true
	}
	return a.afi == af.String()
}

// oTerm is one term of the oracle's reading: a peering, the filters a route
// must pass, those it must fail, and the actions it takes.
type oTerm struct {
	p       *mPeering
	filters []*mFilter
	notAny  []*mFilter
	actions []string
}

type policyGen struct {
	fg     *filterGen
	prngs  map[string][]*mPeering
	asSets []string
}

func (pg *policyGen) asn() types.ASN { return types.ASN(firstAS + pg.fg.r.IntN(4)) }

func (pg *policyGen) peering(allowPrng bool) *mPeering {
	r := pg.fg.r
	var p *mPeering
	switch r.IntN(6) {
	case 0:
		p = &mPeering{kind: "as", as: pg.asn()}
	case 1:
		p = &mPeering{kind: "any"}
		if len(pg.asSets) > 0 {
			p = &mPeering{kind: "set", set: pg.asSets[r.IntN(len(pg.asSets))]}
		}
	case 2:
		p = &mPeering{kind: "any"}
	case 3:
		p = &mPeering{kind: "or", as: pg.asn(), as2: pg.asn()}
	case 4:
		p = &mPeering{kind: "any"}
		if len(pg.asSets) > 0 {
			p = &mPeering{kind: "except", set: pg.asSets[r.IntN(len(pg.asSets))], as: pg.asn()}
		}
	default:
		if allowPrng {
			return &mPeering{kind: "prng", set: fmt.Sprintf("PRNG-P%d", r.IntN(2))}
		}
		p = &mPeering{kind: "as", as: pg.asn()}
	}
	if r.IntN(4) == 0 {
		p.peerRtr = []string{"192.0.2.1", "192.0.2.2", "r1.example.net", "r2.example.net"}[r.IntN(4)]
	}
	if r.IntN(4) == 0 {
		p.atRtr = []string{"198.51.100.1", "RTRS-LOCAL"}[r.IntN(2)]
	}
	return p
}

func (pg *policyGen) factor(nPeers int, peering func() *mPeering) mFactor {
	f := mFactor{filter: pg.fg.filter(2)}
	for i := 0; i < nPeers; i++ {
		pa := mPeerAct{p: peering()}
		for n := pg.fg.r.IntN(3); n > 0; n-- {
			pa.actions = append(pa.actions, modelActions[pg.fg.r.IntN(len(modelActions))])
		}
		f.peers = append(f.peers, pa)
	}
	return f
}

func (pg *policyGen) attr() *mAttr {
	r := pg.fg.r
	a := &mAttr{mp: r.IntN(2) == 0}
	if a.mp && r.IntN(2) == 0 {
		a.afi = []string{"ipv4.unicast", "ipv6.unicast"}[r.IntN(2)]
	}
	if r.IntN(12) == 0 {
		a.protocol = "OSPF"
	}
	pg.fg.v4only = !a.mp
	defer func() { pg.fg.v4only = false }()
	any := func() *mPeering { return pg.peering(true) }
	switch r.IntN(5) {
	case 0, 1:
		a.kind, a.left = "factor", []mFactor{pg.factor(1+r.IntN(2), any)}
	case 2:
		a.kind, a.left = "list", []mFactor{pg.factor(1, any), pg.factor(1, any)}
	case 3:
		a.kind = "except"
		a.left = []mFactor{pg.factor(1, any)}
		a.right = []mFactor{pg.factor(1, any)}
		if r.IntN(2) == 0 {
			a.right = append(a.right, pg.factor(1, any))
		}
	default:
		a.kind = "refine"
		left := pg.factor(1, any)
		if r.IntN(2) == 0 {
			left.peers[0].p = &mPeering{kind: "any"}
		}
		a.left = []mFactor{left}
		a.right = []mFactor{pg.factor(1, func() *mPeering {
			switch r.IntN(3) {
			case 0:
				return left.peers[0].p
			case 1:
				return &mPeering{kind: "any"}
			}
			return pg.peering(true)
		})}
	}
	return a
}

func flat(fs []mFactor) []oTerm {
	var out []oTerm
	for _, f := range fs {
		for _, pa := range f.peers {
			out = append(out, oTerm{p: pa.p, filters: []*mFilter{f.filter}, actions: pa.actions})
		}
	}
	return out
}

// meet is the peering intersection policy/flatten.go documents: written
// alike, or one is AS-ANY with no router; the more specific one is kept.
func meet(a, b *mPeering) (*mPeering, bool) {
	switch {
	case a.plainAny():
		return b, true
	case b.plainAny():
		return a, true
	case a.text() == b.text():
		return a, true
	}
	return nil, false
}

func (pg *policyGen) terms(a *mAttr) []oTerm {
	L := flat(a.left)
	switch a.kind {
	case "except":
		R := flat(a.right)
		var out []oTerm
		for _, l := range L {
			for _, r := range R {
				out = append(out, oTerm{p: r.p, filters: append(append([]*mFilter{}, l.filters...), r.filters...), actions: r.actions})
			}
		}
		var rf []*mFilter
		for _, r := range R {
			rf = append(rf, r.filters...)
		}
		for _, l := range L {
			out = append(out, oTerm{p: l.p, filters: l.filters, notAny: rf, actions: l.actions})
		}
		return out
	case "refine":
		var out []oTerm
		for _, l := range L {
			for _, r := range flat(a.right) {
				if p, ok := meet(l.p, r.p); ok {
					out = append(out, oTerm{p: p, filters: append(append([]*mFilter{}, l.filters...), r.filters...),
						actions: append(append([]string{}, l.actions...), r.actions...)})
				}
			}
		}
		return out
	}
	return L
}

// matches is whether a peering covers the session: 0 no, 1 yes, 2 undecided.
func (pg *policyGen) matches(p *mPeering, s peval.Session) int {
	if p.kind == "prng" {
		best := 0
		for _, q := range pg.prngs[p.set] {
			switch pg.matches(q, s) {
			case 1:
				return 1
			case 2:
				best = 2
			}
		}
		return best
	}
	o := pg.fg.o
	in := func(set string) bool {
		for _, a := range o.asns(set) {
			if a == s.Peer {
				return true
			}
		}
		return false
	}
	var ok bool
	switch p.kind {
	case "as":
		ok = p.as == s.Peer
	case "set":
		ok = in(p.set)
	case "any":
		ok = true
	case "or":
		ok = p.as == s.Peer || p.as2 == s.Peer
	case "except":
		ok = in(p.set) && p.as != s.Peer
	}
	if !ok {
		return 0
	}
	v := 1
	for _, side := range []struct {
		rtr  string
		addr netip.Addr
	}{{p.peerRtr, s.PeerRtr}, {p.atRtr, s.LocalRtr}} {
		if side.rtr == "" {
			continue
		}
		if !side.addr.IsValid() {
			v = 2
			continue
		}
		if !rtrIs(side.rtr, side.addr) {
			return 0
		}
	}
	return v
}

func rtrIs(name string, a netip.Addr) bool {
	switch name {
	case "r1.example.net":
		return a == netip.MustParseAddr("192.0.2.1")
	case "r2.example.net":
		return a == netip.MustParseAddr("192.0.2.2")
	case "RTRS-LOCAL":
		return a == netip.MustParseAddr("198.51.100.1") || a == netip.MustParseAddr("198.51.100.2")
	}
	return netip.MustParseAddr(name) == a
}

// evaluate is the oracle for a session: the terms that cover it, in order,
// and how many were undecided per attribute.
func (pg *policyGen) evaluate(attrs []*mAttr, s peval.Session) ([]oTerm, map[int]int) {
	var terms []oTerm
	und := map[int]int{}
	for i, a := range attrs {
		if !a.applies(s.AF) {
			continue
		}
		if a.protocol != "" {
			und[i]++
			continue
		}
		for _, t := range pg.terms(a) {
			switch pg.matches(t.p, s) {
			case 1:
				terms = append(terms, t)
			case 2:
				und[i]++
			}
		}
	}
	return terms, und
}

// prefixAFI is the address family of a route's prefix.
func prefixAFI(p netip.Prefix) types.AFI {
	if p.Addr().Is4() {
		return types.AFIv4
	}
	return types.AFIv6
}

// decide is the oracle's per-route answer for the session's address family af
// (peval.Evaluator binds it whole to Expander.AFI for the call — see
// Evaluator.newCall). A route of the other family is refused before any term
// is tried: every literal prefix a filter can denote, including the implicit
// "ANY" a purely symbolic filter (a community test, an unconstrained NOT)
// normalizes to, passes through Expander.afiAllows/put (expander.go,
// normalize.go's finish), so with AFI fixed for the whole call no clause can
// ever accept a route of the other family, whatever its filter text says.
// samplePrefixes mixes both families (it is shared with Task 5's filterGen,
// whose model has no per-call AFI), so this check belongs here rather than in
// filterGen.accepts.
func (pg *policyGen) decide(terms []oTerm, rt routemodel.Route, peer types.ASN, af types.AFI) (bool, string) {
	if prefixAFI(rt.Prefix) != af {
		return false, ""
	}
	for _, t := range terms {
		ok := true
		for _, f := range t.filters {
			ok = ok && pg.fg.accepts(f, rt, peer)
		}
		for _, f := range t.notAny {
			ok = ok && !pg.fg.accepts(f, rt, peer)
		}
		if ok {
			return true, strings.Join(t.actions, "; ")
		}
	}
	return false, ""
}

func randomPolicy(t *testing.T, r *rand.Rand, seed uint64) ([]string, *policyGen, []*mAttr) {
	t.Helper()
	m := randomModel(r, false)
	fg := newFilterGen(r, newOracle(m))
	pg := &policyGen{fg: fg, prngs: map[string][]*mPeering{}, asSets: fg.asSets}
	texts := append(m.texts(r), fg.filterSets(2)...)
	texts = append(texts, routerTexts...)
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("PRNG-P%d", i)
		var b strings.Builder
		fmt.Fprintf(&b, "peering-set: %s\n", name)
		for n := 1 + r.IntN(2); n > 0; n-- {
			p := pg.peering(false)
			pg.prngs[name] = append(pg.prngs[name], p)
			fmt.Fprintf(&b, "peering: %s\n", p.text())
		}
		b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
		texts = append(texts, b.String())
	}
	var attrs []*mAttr
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: %s\nas-name: LOCAL\n", localAS)
	for n := 1 + r.IntN(4); n > 0; n-- {
		a := pg.attr()
		attrs = append(attrs, a)
		b.WriteString(a.line() + "\n")
	}
	b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
	raw, _ := rpsl.ParseObject(b.String())
	if _, ds := rpsl.Decode(raw); len(ds) > 0 {
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("seed %d: the generated aut-num does not decode: %v\n%s", seed, d, b.String())
			}
		}
	}
	return append(texts, b.String()), pg, attrs
}

func checkPolicyModel(t *testing.T, label string, pg *policyGen, attrs []*mAttr, v *peval.Evaluator, r *rand.Rand) {
	t.Helper()
	ctx := context.Background()
	for k := 0; k < 6; k++ {
		s := peval.Session{Local: localAS, Peer: types.ASN(firstAS + r.IntN(4)), AF: families[r.IntN(2)]}
		if a := peerRtrs[r.IntN(len(peerRtrs))]; a != "" {
			s.PeerRtr = netip.MustParseAddr(a)
		}
		if a := localRtrs[r.IntN(len(localRtrs))]; a != "" {
			s.LocalRtr = netip.MustParseAddr(a)
		}
		pol, err := v.Import(ctx, s)
		if err != nil {
			t.Fatalf("%s: Import(%+v): %v", label, s, err)
		}
		terms, wantUnd := pg.evaluate(attrs, s)
		gotUnd := map[int]int{}
		for _, u := range pol.Undecided {
			gotUnd[u.Index]++
		}
		if !maps.Equal(gotUnd, wantUnd) {
			t.Fatalf("%s: Import(%+v): undecided %v, the model says %v", label, s, gotUnd, wantUnd)
		}
		for j := 0; j < 60; j++ {
			rt := randomRoute(r, s.Peer)
			wantOK, wantActs := pg.decide(terms, rt, s.Peer, s.AF.AFI)
			gotOK, gotActs := false, ""
			for _, c := range pol.Clauses {
				ok, err := routemodel.Match(c.Filter, rt)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				if ok {
					var acts []string
					for _, a := range c.Actions {
						acts = append(acts, a.String())
					}
					gotOK, gotActs = true, strings.Join(acts, "; ")
					break
				}
			}
			if gotOK != wantOK || gotActs != wantActs {
				var lines []string
				for _, a := range attrs {
					lines = append(lines, a.line())
				}
				t.Fatalf("%s: session %+v, route %v: peval accepts %v with %q; the model %v with %q\npolicy:\n%s",
					label, s, rt, gotOK, gotActs, wantOK, wantActs, strings.Join(lines, "\n"))
			}
		}
	}
}

func TestModelPolicy(t *testing.T) {
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, attrs := randomPolicy(t, r, seed)
		v := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")}
		checkPolicyModel(t, fmt.Sprintf("seed %d", seed), pg, attrs, v, r)
	}
}

// The same, over a Corpus kept with KeepPolicy and over the network
// backends against an IRRd-like server.
func TestModelPolicyBackends(t *testing.T) {
	for seed := uint64(0); seed < 25; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, attrs := randomPolicy(t, r, seed)
		l := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}, KeepPolicy: true}
		if err := l.Read(strings.NewReader(strings.Join(texts, "\n"))); err != nil {
			t.Fatal(err)
		}
		checkPolicyModel(t, fmt.Sprintf("corpus seed %d", seed), pg, attrs, &peval.Evaluator{Src: l.Source()}, r)
		db := irrtest.New(texts...).WithSources("RIPE", "RADB")
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 8, Timeout: 5 * time.Second}
		checkPolicyModel(t, fmt.Sprintf("irrd seed %d", seed), pg, attrs, &peval.Evaluator{Src: ir}, r)
		ir.Close()
		wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		checkPolicyModel(t, fmt.Sprintf("whois seed %d", seed), pg, attrs, &peval.Evaluator{Src: wh}, r)
	}
}

// Expander.Exclude only narrows a policy: with a random Exclude on the
// Evaluator's Expander, the terms that cover a session — and those undecided —
// are the model's without it, and every route peval accepts the model accepts
// without it (actions aside: a narrower clause may pass a route to a later one).
func TestModelPolicyExclude(t *testing.T) {
	ctx := context.Background()
	narrowed := 0
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, attrs := randomPolicy(t, r, seed)
		ex := randomExclusion(rand.New(rand.NewPCG(seed, 29)), pg.fg.o.m)
		v := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB"), Expander: resolve.Expander{Exclude: ex}}
		label := fmt.Sprintf("seed %d: exclude %v", seed, ex)
		for k := 0; k < 6; k++ {
			s := peval.Session{Local: localAS, Peer: types.ASN(firstAS + r.IntN(4)), AF: families[r.IntN(2)]}
			if a := peerRtrs[r.IntN(len(peerRtrs))]; a != "" {
				s.PeerRtr = netip.MustParseAddr(a)
			}
			if a := localRtrs[r.IntN(len(localRtrs))]; a != "" {
				s.LocalRtr = netip.MustParseAddr(a)
			}
			pol, err := v.Import(ctx, s)
			if err != nil {
				t.Fatalf("%s: Import(%+v): %v", label, s, err)
			}
			terms, wantUnd := pg.evaluate(attrs, s)
			gotUnd := map[int]int{}
			for _, u := range pol.Undecided {
				gotUnd[u.Index]++
			}
			if !maps.Equal(gotUnd, wantUnd) {
				t.Fatalf("%s: Import(%+v): undecided %v, the model says %v", label, s, gotUnd, wantUnd)
			}
			if len(pol.Clauses) != len(terms) {
				t.Fatalf("%s: Import(%+v): %d clauses, the model %d terms", label, s, len(pol.Clauses), len(terms))
			}
			for j := 0; j < 60; j++ {
				rt := randomRoute(r, s.Peer)
				want, _ := pg.decide(terms, rt, s.Peer, s.AF.AFI)
				got := false
				for _, c := range pol.Clauses {
					ok, err := routemodel.Match(c.Filter, rt)
					if err != nil {
						t.Fatalf("%s: %v", label, err)
					}
					if ok {
						got = true
						break
					}
				}
				if got && !want {
					t.Fatalf("%s: session %+v, route %v: peval accepts it; without Exclude the model refuses it", label, s, rt)
				}
				if want && !got {
					narrowed++
				}
			}
		}
	}
	if narrowed == 0 {
		t.Fatal("Exclude never left out a route the model accepts")
	}
}
