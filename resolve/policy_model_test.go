package resolve_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// peval against a per-route model of RFC 2622 §6: random policies of one
// aut-num — import:, export:, import-via: (draft-ietf-grow-rpsl-via) or
// default:, each with its mp- form; factors with several peer clauses, lists,
// EXCEPT and REFINE, peerings by AS, as-set, AS-ANY, AS expression and
// peering-set, routers by address, inet-rtr and rtr-set, afi clauses and
// protocols — are decided route by route and session by session from the
// model, and the first clause of peval's Policy that accepts a route must be
// the model's, with its actions.

const (
	localAS = types.ASN(64500)
	// routeServerAS is the via peering of every generated import-via:.
	routeServerAS = types.ASN(64777)
)

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

// kw is how an attribute writes its factors: the peer keyword ("from" or
// "to"), the filter keyword ("accept" or "announce"), and the via peering
// written before each peer clause ("" for none).
type kw struct{ peer, filter, via string }

func (f mFactor) text(k kw) string {
	var b strings.Builder
	for _, pa := range f.peers {
		if k.via != "" {
			b.WriteString(k.via + " ")
		}
		fmt.Fprintf(&b, "%s %s ", k.peer, pa.p.text())
		if len(pa.actions) > 0 {
			fmt.Fprintf(&b, "action %s; ", strings.Join(pa.actions, "; "))
		}
	}
	return b.String() + k.filter + " " + f.filter.text()
}

type mAttr struct {
	mp          bool
	afi         string // mp only: "", "ipv4.unicast" or "ipv6.unicast"
	protocol    string // "" or "OSPF"
	kind        string // "factor", "list", "except", "refine"
	left, right []mFactor
	export      bool      // export:/mp-export: rather than import:/mp-import:
	via         *mPeering // import-via: only: the route server's peering
}

func (a *mAttr) kw() kw {
	k := kw{peer: "from", filter: "accept"}
	if a.export {
		k.peer, k.filter = "to", "announce"
	}
	if a.via != nil {
		k.via = a.via.text()
	}
	return k
}

func block(fs []mFactor, braces bool, k kw) string {
	if len(fs) == 1 && !braces {
		return fs[0].text(k)
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = f.text(k)
	}
	return "{ " + strings.Join(parts, "; ") + "; }"
}

func (a *mAttr) line() string {
	var b strings.Builder
	switch {
	case a.via != nil:
		b.WriteString("import-via: ")
	case a.export && a.mp:
		b.WriteString("mp-export: ")
	case a.export:
		b.WriteString("export: ")
	case a.mp:
		b.WriteString("mp-import: ")
	default:
		b.WriteString("import: ")
	}
	if a.protocol != "" {
		b.WriteString("protocol " + a.protocol + " ")
	}
	if a.afi != "" {
		b.WriteString("afi " + a.afi + " ")
	}
	k := a.kw()
	switch a.kind {
	case "factor":
		b.WriteString(block(a.left, false, k))
	case "list":
		b.WriteString(block(a.left, true, k))
	case "except":
		b.WriteString(block(a.left, false, k) + " except " + block(a.right, true, k))
	case "refine":
		b.WriteString(block(a.left, false, k) + " refine " + block(a.right, true, k))
	}
	return b.String()
}

// applies is whether the attribute covers af. import-via: is always mp
// (draft-ietf-grow-rpsl-via): with no afi clause it covers every family.
func (a *mAttr) applies(af types.AddrFamily) bool {
	switch {
	case !a.mp && a.via == nil:
		return af.AFI == types.AFIv4
	case a.afi == "":
		return true
	}
	return a.afi == af.String()
}

// mPolicy is the policy generated for the local aut-num: one kind of
// attribute, so that one Evaluator method answers for all of it.
type mPolicy struct {
	kind     string // "import", "export", "via" or "default"
	attrs    []*mAttr
	defaults []*mDefault
}

// lines are the policy's attributes as the aut-num carries them.
func (pol *mPolicy) lines() []string {
	var out []string
	for _, a := range pol.attrs {
		out = append(out, a.line())
	}
	for _, d := range pol.defaults {
		out = append(out, d.line())
	}
	return out
}

// mDefault is a default: or mp-default: attribute.
type mDefault struct {
	mp       bool
	afi      string // mp only: "", "ipv4.unicast" or "ipv6.unicast"
	p        *mPeering
	actions  []string
	networks *mFilter // nil: no networks clause
}

func (d *mDefault) line() string {
	var b strings.Builder
	if d.mp {
		b.WriteString("mp-default: ")
		if d.afi != "" {
			b.WriteString("afi " + d.afi + " ")
		}
	} else {
		b.WriteString("default: ")
	}
	b.WriteString("to " + d.p.text())
	if len(d.actions) > 0 {
		b.WriteString(" action " + strings.Join(d.actions, "; ") + ";")
	}
	if d.networks != nil {
		b.WriteString(" networks " + d.networks.text())
	}
	return b.String()
}

func (d *mDefault) applies(af types.AddrFamily) bool {
	switch {
	case !d.mp:
		return af.AFI == types.AFIv4
	case d.afi == "":
		return true
	}
	return d.afi == af.String()
}

// oTerm is one term of the oracle's reading: a peering, the filters a route
// must pass, those it must fail, and the actions it takes. peer is the AS its
// filters bind PeerAS to; zero means the session's peer.
type oTerm struct {
	p       *mPeering
	filters []*mFilter
	notAny  []*mFilter
	actions []string
	peer    types.ASN
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

// attr draws an import:, export: or import-via: attribute (kind "import",
// "export" or "via"). An import-via: is mp, its via peering the route server
// AS, its remote peerings drawn without routers or peering-sets; it has no
// REFINE, since its terms would meet only on the via peering, which is always
// the same.
func (pg *policyGen) attr(kind string) *mAttr {
	r := pg.fg.r
	a := &mAttr{mp: r.IntN(2) == 0, export: kind == "export"}
	any := func() *mPeering { return pg.peering(true) }
	kinds := 5
	if kind == "via" {
		a.mp, a.via = true, &mPeering{kind: "as", as: routeServerAS}
		any = func() *mPeering {
			p := pg.peering(false)
			p.peerRtr, p.atRtr = "", ""
			return p
		}
		kinds = 4
	}
	if a.mp && r.IntN(2) == 0 {
		a.afi = []string{"ipv4.unicast", "ipv6.unicast"}[r.IntN(2)]
	}
	if r.IntN(12) == 0 {
		a.protocol = "OSPF"
	}
	pg.fg.v4only = !a.mp
	defer func() { pg.fg.v4only = false }()
	switch r.IntN(kinds) {
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

// defaultAttr draws a default: or mp-default: attribute.
func (pg *policyGen) defaultAttr() *mDefault {
	r := pg.fg.r
	d := &mDefault{mp: r.IntN(2) == 0}
	if d.mp && r.IntN(2) == 0 {
		d.afi = []string{"ipv4.unicast", "ipv6.unicast"}[r.IntN(2)]
	}
	d.p = pg.peering(true)
	for n := r.IntN(3); n > 0; n-- {
		d.actions = append(d.actions, modelActions[r.IntN(len(modelActions))])
	}
	if r.IntN(2) == 0 {
		pg.fg.v4only = !d.mp
		d.networks = pg.fg.filter(2)
		pg.fg.v4only = false
	}
	return d
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

// evaluateVia is evaluate for import-via: attributes. A term covers the
// session when its via peering does; its filters bind PeerAS to the remote
// peering's AS when that is one AS number, and a term whose filters name the
// peer when it is not is undecided.
func (pg *policyGen) evaluateVia(attrs []*mAttr, s peval.Session) ([]oTerm, map[int]int) {
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
		if pg.matches(a.via, s) != 1 {
			continue
		}
		for _, t := range pg.terms(a) {
			if t.p.kind == "as" {
				t.peer = t.p.as
			} else if namesPeer(t) {
				und[i]++
				continue
			}
			terms = append(terms, t)
		}
	}
	return terms, und
}

// namesPeer is whether any of a term's filters names the peer: PeerAS, in a
// filter, a set template or an AS-path regexp. The model's filter-sets never
// do (filterNoPeer).
func namesPeer(t oTerm) bool {
	for _, f := range append(append([]*mFilter{}, t.filters...), t.notAny...) {
		if strings.Contains(f.text(), "PeerAS") {
			return true
		}
	}
	return false
}

// evaluateDefaults is the oracle for default: attributes: the indexes of those
// that cover the session, in order, and how many were undecided per attribute.
func (pg *policyGen) evaluateDefaults(ds []*mDefault, s peval.Session) ([]int, map[int]int) {
	var out []int
	und := map[int]int{}
	for i, d := range ds {
		if !d.applies(s.AF) {
			continue
		}
		switch pg.matches(d.p, s) {
		case 1:
			out = append(out, i)
		case 2:
			und[i]++
		}
	}
	return out, und
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
func (pg *policyGen) decide(terms []oTerm, rt routemodel.Route, sessionPeer types.ASN, af types.AFI) (bool, string) {
	if prefixAFI(rt.Prefix) != af {
		return false, ""
	}
	for _, t := range terms {
		peer := sessionPeer
		if t.peer != 0 {
			peer = t.peer
		}
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

// policyKinds are the kinds of policy randomPolicy draws, with equal weight.
var policyKinds = []string{"import", "export", "via", "default"}

// randomPolicy draws a random IRR (with the set templates' as-sets, so a
// template in a filter denotes something for every peer a session names), its
// filter-sets, routers and peering-sets, and an aut-num for localAS carrying
// a random policy of one kind. It returns the objects' RPSL, the generator
// and the policy.
func randomPolicy(t *testing.T, r *rand.Rand, seed uint64) ([]string, *policyGen, *mPolicy) {
	t.Helper()
	m := withTemplateSets(r, randomModel(r, false))
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
	pol := &mPolicy{kind: policyKinds[r.IntN(len(policyKinds))]}
	if pol.kind == "default" {
		for n := 1 + r.IntN(3); n > 0; n-- {
			pol.defaults = append(pol.defaults, pg.defaultAttr())
		}
	} else {
		for n := 1 + r.IntN(4); n > 0; n-- {
			pol.attrs = append(pol.attrs, pg.attr(pol.kind))
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: %s\nas-name: LOCAL\n", localAS)
	for _, l := range pol.lines() {
		b.WriteString(l + "\n")
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
	return append(texts, b.String()), pg, pol
}

// session draws a session for pol: the peer one of the model's AS numbers,
// or, for import-via:, the route server half the time; each router given or
// not.
func (pol *mPolicy) session(r *rand.Rand) peval.Session {
	s := peval.Session{Local: localAS, Peer: types.ASN(firstAS + r.IntN(4)), AF: families[r.IntN(2)]}
	if pol.kind == "via" && r.IntN(2) == 0 {
		s.Peer = routeServerAS
	}
	if a := peerRtrs[r.IntN(len(peerRtrs))]; a != "" {
		s.PeerRtr = netip.MustParseAddr(a)
	}
	if a := localRtrs[r.IntN(len(localRtrs))]; a != "" {
		s.LocalRtr = netip.MustParseAddr(a)
	}
	return s
}

// evaluate is the Evaluator method answering for pol's kind (not "default").
func (pol *mPolicy) evaluate(v *peval.Evaluator, s peval.Session) (peval.Policy, error) {
	ctx := context.Background()
	switch pol.kind {
	case "export":
		return v.Export(ctx, s)
	case "via":
		return v.ImportVia(ctx, s)
	}
	return v.Import(ctx, s)
}

// expect is the oracle's reading of pol (not "default") for the session.
func (pg *policyGen) expect(pol *mPolicy, s peval.Session) ([]oTerm, map[int]int) {
	if pol.kind == "via" {
		return pg.evaluateVia(pol.attrs, s)
	}
	return pg.evaluate(pol.attrs, s)
}

func undecidedByIndex(us []peval.Undecided) map[int]int {
	out := map[int]int{}
	for _, u := range us {
		out[u.Index]++
	}
	return out
}

func actionsText(as []policy.Action) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = a.String()
	}
	return strings.Join(parts, "; ")
}

// checkSession holds peval's answer for one session to the model's, over 60
// random routes, and returns how many clauses peval found. exact asks for the
// same routes accepted, by the same first clause's actions; otherwise (under
// Exclude, which only narrows) the same clauses and a subset of the routes,
// and *narrowed counts the routes the model accepts and peval does not.
func checkSession(t *testing.T, label string, pg *policyGen, pol *mPolicy, v *peval.Evaluator, s peval.Session, r *rand.Rand, exact bool, narrowed *int) int {
	t.Helper()
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s: session %+v: %s\npolicy:\n%s", label, s, fmt.Sprintf(format, args...), strings.Join(pol.lines(), "\n"))
	}
	compare := func(got, want bool, what string) {
		t.Helper()
		switch {
		case got && !want && exact:
			fail("%s: peval accepts it; the model refuses it", what)
		case got && !want:
			fail("%s: peval accepts it; without Exclude the model refuses it", what)
		case want && !got && exact:
			fail("%s: peval refuses it; the model accepts it", what)
		case want && !got:
			*narrowed++
		}
	}
	if pol.kind == "default" {
		d, err := v.Default(context.Background(), s)
		if err != nil {
			fail("Default: %v", err)
		}
		want, wantUnd := pg.evaluateDefaults(pol.defaults, s)
		if got := undecidedByIndex(d.Undecided); !maps.Equal(got, wantUnd) {
			fail("undecided %v, the model says %v", got, wantUnd)
		}
		var got, wantText []string
		for _, dc := range d.Clauses {
			got = append(got, fmt.Sprintf("%d: %s", dc.Index, actionsText(dc.Actions)))
		}
		for _, i := range want {
			wantText = append(wantText, fmt.Sprintf("%d: %s", i, strings.Join(pol.defaults[i].actions, "; ")))
		}
		if !slices.Equal(got, wantText) {
			fail("clauses %q, the model %q", got, wantText)
		}
		for k, dc := range d.Clauses {
			md := pol.defaults[want[k]]
			if (dc.Networks == nil) != (md.networks == nil) {
				fail("default %d: networks %v, the model %v", dc.Index, dc.Networks, md.networks)
			}
			if md.networks == nil {
				continue
			}
			for j := 0; j < 60; j++ {
				rt := randomRoute(r, s.Peer)
				ok, err := routemodel.Match(*dc.Networks, rt)
				if err != nil {
					fail("%v", err)
				}
				compare(ok, prefixAFI(rt.Prefix) == s.AF.AFI && pg.fg.accepts(md.networks, rt, s.Peer),
					fmt.Sprintf("default %d, networks %s, route %v", dc.Index, *dc.Networks, rt))
			}
		}
		return len(d.Clauses)
	}
	p, err := pol.evaluate(v, s)
	if err != nil {
		fail("%s: %v", pol.kind, err)
	}
	terms, wantUnd := pg.expect(pol, s)
	if got := undecidedByIndex(p.Undecided); !maps.Equal(got, wantUnd) {
		fail("undecided %v, the model says %v", got, wantUnd)
	}
	if !exact && len(p.Clauses) != len(terms) {
		fail("%d clauses, the model %d terms", len(p.Clauses), len(terms))
	}
	for j := 0; j < 60; j++ {
		rt := randomRoute(r, s.Peer)
		wantOK, wantActs := pg.decide(terms, rt, s.Peer, s.AF.AFI)
		gotOK, gotActs := false, ""
		for _, c := range p.Clauses {
			ok, err := routemodel.Match(c.Filter, rt)
			if err != nil {
				fail("%v", err)
			}
			if ok {
				gotOK, gotActs = true, actionsText(c.Actions)
				break
			}
		}
		if exact && gotOK && wantOK && gotActs != wantActs {
			fail("route %v: peval accepts it with %q; the model with %q", rt, gotActs, wantActs)
		}
		compare(gotOK, wantOK, fmt.Sprintf("route %v", rt))
	}
	return len(p.Clauses)
}

// kindCounts tallies, per kind of policy, the policies, the sessions with a
// clause, and the clauses checked.
type kindCounts map[string]*[3]int

func (kc kindCounts) add(kind string, clauses int) {
	if kc[kind] == nil {
		kc[kind] = &[3]int{}
	}
	if clauses > 0 {
		kc[kind][1]++
	}
	kc[kind][2] += clauses
}

func (kc kindCounts) log(t *testing.T, label string) {
	t.Helper()
	for _, k := range policyKinds {
		if c := kc[k]; c != nil {
			t.Logf("%s %s: %d policies, %d sessions with a clause, %d clauses", label, k, c[0], c[1], c[2])
		}
	}
}

// checkPolicyModel holds v to the model over six random sessions.
func checkPolicyModel(t *testing.T, label string, pg *policyGen, pol *mPolicy, v *peval.Evaluator, r *rand.Rand, kc kindCounts) {
	t.Helper()
	if kc[pol.kind] == nil {
		kc[pol.kind] = &[3]int{}
	}
	kc[pol.kind][0]++
	for k := 0; k < 6; k++ {
		kc.add(pol.kind, checkSession(t, label, pg, pol, v, pol.session(r), r, true, nil))
	}
}

func TestModelPolicy(t *testing.T) {
	kc := kindCounts{}
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, pol := randomPolicy(t, r, seed)
		v := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")}
		checkPolicyModel(t, fmt.Sprintf("seed %d", seed), pg, pol, v, r, kc)
	}
	kc.log(t, "memsource")
	for _, k := range policyKinds {
		if c := kc[k]; c == nil || c[1] < 20 {
			t.Errorf("%s: only %v policies, sessions with a clause and clauses checked", k, c)
		}
	}
}

// The same, over a Corpus kept with KeepPolicy and over the network
// backends against an IRRd-like server. 100 seeds, so that each of the four
// kinds randomPolicy draws gets about 25 policies, as import alone had before.
func TestModelPolicyBackends(t *testing.T) {
	kcs := map[string]kindCounts{"corpus": {}, "irrd": {}, "whois": {}}
	for seed := uint64(0); seed < 100; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, pol := randomPolicy(t, r, seed)
		l := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}, KeepPolicy: true}
		if err := l.Read(strings.NewReader(strings.Join(texts, "\n"))); err != nil {
			t.Fatal(err)
		}
		checkPolicyModel(t, fmt.Sprintf("corpus seed %d", seed), pg, pol, &peval.Evaluator{Src: l.Source()}, r, kcs["corpus"])
		db := irrtest.New(texts...).WithSources("RIPE", "RADB")
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 8, Timeout: 5 * time.Second}
		checkPolicyModel(t, fmt.Sprintf("irrd seed %d", seed), pg, pol, &peval.Evaluator{Src: ir}, r, kcs["irrd"])
		ir.Close()
		wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		checkPolicyModel(t, fmt.Sprintf("whois seed %d", seed), pg, pol, &peval.Evaluator{Src: wh}, r, kcs["whois"])
	}
	for _, b := range []string{"corpus", "irrd", "whois"} {
		kcs[b].log(t, b)
		for _, k := range policyKinds {
			if c := kcs[b][k]; c == nil || c[1] < 10 {
				t.Errorf("%s %s: only %v policies, sessions with a clause and clauses checked", b, k, c)
			}
		}
	}
}

// Expander.Exclude only narrows a policy: with a random Exclude on the
// Evaluator's Expander, the clauses that cover a session — and those
// undecided — are the model's without it, and every route peval accepts (for
// a default, every route its networks filter accepts) the model accepts
// without it (actions aside: a narrower clause may pass a route to a later
// one).
func TestModelPolicyExclude(t *testing.T) {
	narrowed := 0
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		texts, pg, pol := randomPolicy(t, r, seed)
		ex := randomExclusion(rand.New(rand.NewPCG(seed, 29)), pg.fg.o.m)
		v := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB"), Expander: resolve.Expander{Exclude: ex}}
		label := fmt.Sprintf("seed %d: exclude %v", seed, ex)
		for k := 0; k < 6; k++ {
			checkSession(t, label, pg, pol, v, pol.session(r), r, false, &narrowed)
		}
	}
	if narrowed == 0 {
		t.Fatal("Exclude never left out a route the model accepts")
	}
}
