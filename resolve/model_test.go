package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// The whole engine against a brute-force model of RPSL (RFC 2622 §5, RFC 4012):
// random IRRs of as-sets, route-sets, aut-nums and routes in two sources, with
// range operators, indirect members, cycles, missing and invalid members, and
// sets defined in both sources. The oracle computes what each set denotes
// straight from the model — never from parsed text or engine code — and every
// backend must agree with it.

// ---- the model ----

var (
	v4Universe = netip.MustParsePrefix("10.0.0.0/29")
	v6Universe = netip.MustParsePrefix("2001:db8::/126")
	mntners    = []string{"MNT-A", "MNT-B", "MNT-C"}
)

const firstAS = 65001

type mMember struct {
	kind string // "as", "set", "pfx" or "junk"
	as   types.ASN
	set  string // canonical set name
	pfx  netip.Prefix
	op   string // "", "^+", "^-", "^n" or "^n-m"
	text string // as written in the object
}

type mSet struct {
	name      string // canonical
	class     types.SetClass
	source    string
	members   []mMember
	mbrsByRef []string
}

// mObject is an aut-num or a route/route6: a possible indirect member, and for
// a route, a route its origin originates.
type mObject struct {
	class    string // "aut-num", "route" or "route6"
	as       types.ASN
	pfx      netip.Prefix
	memberOf []string // canonical set names
	mntBy    []string
	source   string
}

type model struct {
	sets []*mSet // may define a name in both sources
	objs []mObject
}

// setClass is the class a set name denotes (its prefix), or ClassUnknown.
func setClass(name string) types.SetClass {
	n, err := types.ParseSetName(name)
	if err != nil {
		return types.ClassUnknown
	}
	return n.Class()
}

// randomModel draws a random IRR. With compat it leaves out what bgpq4 and
// IRRd do not implement (see TestBgpq4KnownDivergences): range operators on
// set and AS members, AS-ANY/RS-ANY, route-sets listed in as-sets, and the
// single-length "^n" form, which it writes "^n-n".
func randomModel(r *rand.Rand, compat bool) model {
	var m model
	nAS, nRS, nASN := 1+r.IntN(3), 1+r.IntN(3), 1+r.IntN(4)
	asn := func() types.ASN { return types.ASN(firstAS + r.IntN(nASN)) }
	source := func() string {
		if r.IntN(5) == 0 {
			return "RADB"
		}
		return "RIPE"
	}
	pfx := func() netip.Prefix {
		u := v4Universe
		if r.IntN(3) == 0 {
			u = v6Universe
		}
		return netip.PrefixFrom(u.Addr(), u.Bits()+r.IntN(u.Addr().BitLen()-u.Bits()+1)).Masked()
	}
	// op draws an operator for a set or AS member, from either family's
	// lengths and sometimes below them, so it may delete what it applies to.
	op := func() string {
		if compat {
			return ""
		}
		lo, hi := 28, 32
		if r.IntN(2) == 0 {
			lo, hi = 125, 128
		}
		switch r.IntN(8) {
		case 0:
			return "^+"
		case 1:
			return "^-"
		case 2:
			return fmt.Sprintf("^%d", lo+r.IntN(hi-lo+1))
		case 3:
			n := lo + r.IntN(hi-lo+1)
			return fmt.Sprintf("^%d-%d", n, n+r.IntN(hi-n+1))
		}
		return ""
	}
	// literal draws an operator valid on prefix p itself.
	literal := func(p netip.Prefix) string {
		lo, hi := p.Bits(), p.Addr().BitLen()
		switch r.IntN(6) {
		case 0:
			return "^+"
		case 1:
			if lo < hi {
				return "^-"
			}
		case 2:
			n := lo + r.IntN(hi-lo+1)
			if compat {
				return fmt.Sprintf("^%d-%d", n, n)
			}
			return fmt.Sprintf("^%d", n)
		case 3:
			n := lo + r.IntN(hi-lo+1)
			return fmt.Sprintf("^%d-%d", n, n+r.IntN(hi-n+1))
		}
		return ""
	}
	names := func(prefix string, n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("%s-S%d", prefix, i))
		}
		return out
	}
	asNames, rsNames := names("AS", nAS), names("RS", nRS)
	ref := func(class types.SetClass) string {
		pool, pre := asNames, "AS"
		if class == types.ClassRouteSet {
			pool, pre = rsNames, "RS"
		}
		switch k := r.IntN(40); {
		case k == 0 && !compat:
			return pre + "-ANY"
		case k < 6:
			return fmt.Sprintf("%s-MISS%d", pre, r.IntN(2))
		}
		return pool[r.IntN(len(pool))]
	}
	spell := func(s string) string { // RPSL names are case-insensitive
		if r.IntN(3) == 0 {
			return strings.ToLower(s)
		}
		return s
	}
	mbrs := func() []string {
		if r.IntN(5) >= 2 {
			return nil
		}
		var out []string
		for k := 1 + r.IntN(2); k > 0; k-- {
			if r.IntN(4) == 0 {
				out = append(out, "ANY")
			} else {
				out = append(out, mntners[r.IntN(len(mntners))])
			}
		}
		return out
	}
	newSet := func(name string, class types.SetClass, src string) *mSet {
		s := &mSet{name: name, class: class, source: src, mbrsByRef: mbrs()}
		for k := r.IntN(5); k > 0; k-- {
			var mm mMember
			switch c := r.IntN(20); {
			case c == 0:
				mm = mMember{kind: "junk", text: "BAD!MEMBER"}
			case c == 1 && class == types.ClassAsSet && !compat: // not followed: RFC 2622 §5.1
				n := ref(types.ClassRouteSet)
				mm = mMember{kind: "set", set: n, text: spell(n)}
			case c == 1: // a filter-set in a route-set is not followed either
				mm = mMember{kind: "set", set: "FLTR-X", text: "FLTR-X"}
			case class == types.ClassAsSet && c < 11:
				a := asn()
				mm = mMember{kind: "as", as: a, text: spell(a.String())}
			case class == types.ClassAsSet:
				n := ref(types.ClassAsSet)
				mm = mMember{kind: "set", set: n, text: spell(n)}
			case c < 8:
				p := pfx()
				o := literal(p)
				text := p.String()
				if p.IsSingleIP() && r.IntN(2) == 0 { // "192.0.2.1": the host prefix, as IRRd reads it
					text = p.Addr().String()
				}
				mm = mMember{kind: "pfx", pfx: p, op: o, text: text + o}
			case c < 12:
				a, o := asn(), op()
				mm = mMember{kind: "as", as: a, op: o, text: spell(a.String()) + o}
			case c < 15:
				n, o := ref(types.ClassAsSet), op()
				mm = mMember{kind: "set", set: n, op: o, text: spell(n) + o}
			default:
				n, o := ref(types.ClassRouteSet), op()
				mm = mMember{kind: "set", set: n, op: o, text: spell(n) + o}
			}
			s.members = append(s.members, mm)
		}
		return s
	}
	for _, class := range []types.SetClass{types.ClassAsSet, types.ClassRouteSet} {
		pool := asNames
		if class == types.ClassRouteSet {
			pool = rsNames
		}
		for _, n := range pool {
			s := newSet(n, class, source())
			m.sets = append(m.sets, s)
			if s.source == "RIPE" && r.IntN(4) == 0 { // a same-named set in RADB, which RIPE outranks
				m.sets = append(m.sets, newSet(n, class, "RADB"))
			}
		}
	}
	memberOf := func(pool []string) []string {
		var out []string
		for k := r.IntN(3); k > 0; k-- {
			out = append(out, pool[r.IntN(len(pool))])
		}
		return out
	}
	mnts := func() []string { return []string{mntners[r.IntN(len(mntners))]} }
	for k := r.IntN(4); k > 0; k-- {
		pool := asNames
		if r.IntN(5) == 0 {
			pool = rsNames // an aut-num cannot join a route-set; the claim is ignored
		}
		m.objs = append(m.objs, mObject{class: "aut-num", as: asn(), memberOf: memberOf(pool), mntBy: mnts(), source: source()})
	}
	for i := 0; i < nASN; i++ {
		for k := r.IntN(4); k > 0; k-- {
			p := pfx()
			class := "route"
			if p.Addr().Is6() {
				class = "route6"
			}
			pool := rsNames
			if r.IntN(5) == 0 {
				pool = asNames // a route cannot join an as-set; the claim is ignored
			}
			m.objs = append(m.objs, mObject{class: class, as: types.ASN(firstAS + i), pfx: p,
				memberOf: memberOf(pool), mntBy: mnts(), source: source()})
		}
	}
	return m
}

// texts renders the model as RPSL objects in random order, spelling set names
// in random case and splitting member lists across lines and attributes.
func (m model) texts(r *rand.Rand) []string {
	var out []string
	list := func(b *strings.Builder, attr string, items []string) {
		for len(items) > 0 {
			n := 1 + r.IntN(len(items))
			fmt.Fprintf(b, "%s: %s\n", attr, strings.Join(items[:n], ", "))
			items = items[n:]
		}
	}
	for _, s := range m.sets {
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %s\n", s.class, strings.ToLower(s.name))
		var members, mp []string
		for _, mm := range s.members {
			if s.class == types.ClassRouteSet && (mm.kind == "pfx" && mm.pfx.Addr().Is6() && r.IntN(4) > 0 || r.IntN(4) == 0) {
				mp = append(mp, mm.text) // RFC 4012 mp-members; IPv6 in members: is used too, with a warning
			} else {
				members = append(members, mm.text)
			}
		}
		list(&b, "members", members)
		list(&b, "mp-members", mp)
		list(&b, "mbrs-by-ref", s.mbrsByRef)
		fmt.Fprintf(&b, "mnt-by: MNT-A\nsource: %s\n", s.source)
		out = append(out, b.String())
	}
	for _, o := range m.objs {
		var b strings.Builder
		if o.class == "aut-num" {
			fmt.Fprintf(&b, "aut-num: %s\nas-name: X\n", o.as)
		} else {
			fmt.Fprintf(&b, "%s: %s\norigin: %s\n", o.class, o.pfx, o.as)
		}
		list(&b, "member-of", o.memberOf)
		list(&b, "mnt-by", o.mntBy)
		fmt.Fprintf(&b, "source: %s\n", o.source)
		out = append(out, b.String())
	}
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ---- the oracle ----

type oracle struct {
	m    model
	sets map[string]*mSet // the definition in use: RIPE outranks RADB
}

func newOracle(m model) *oracle {
	o := &oracle{m: m, sets: map[string]*mSet{}}
	for _, s := range m.sets {
		if cur, ok := o.sets[s.name]; !ok || cur.source == "RADB" && s.source == "RIPE" {
			o.sets[s.name] = s
		}
	}
	return o
}

// honored applies RFC 2622 §5.1-5.2 and the same-source rule: an as-set's
// indirect members are aut-nums, a route-set's are routes, and each must name
// the set, come from its source, and be maintained by a mbrs-by-ref maintainer.
func honored(s *mSet, c mObject) bool {
	switch {
	case s.class == types.ClassAsSet && c.class == "aut-num":
	case s.class == types.ClassRouteSet && c.class != "aut-num":
	default:
		return false
	}
	if c.source != s.source || !slices.Contains(c.memberOf, s.name) {
		return false
	}
	for _, m := range s.mbrsByRef {
		if m == "ANY" || slices.Contains(c.mntBy, m) {
			return true
		}
	}
	return false
}

// nested reports whether a set of class parent includes a member set of class
// child: an as-set includes as-sets, a route-set route-sets and as-sets.
func nested(parent, child types.SetClass) bool {
	return child == types.ClassAsSet || parent == types.ClassRouteSet && child == types.ClassRouteSet
}

// reach walks the sets top includes, breadth first: each name's shortest
// distance from top, and whether AS-ANY or RS-ANY is among them.
func (o *oracle) reach(top string) (dist map[string]int, anySet bool) {
	dist = map[string]int{top: 0}
	for queue := []string{top}; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		if name == "AS-ANY" || name == "RS-ANY" {
			anySet = true
			continue
		}
		s, ok := o.sets[name]
		if !ok {
			continue
		}
		for _, mm := range s.members {
			if _, seen := dist[mm.set]; mm.kind != "set" || seen || !nested(s.class, setClass(mm.set)) {
				continue
			}
			dist[mm.set] = dist[name] + 1
			queue = append(queue, mm.set)
		}
	}
	return dist, anySet
}

// missing returns the names top includes that are not defined.
func (o *oracle) missing(top string) []string {
	dist, _ := o.reach(top)
	var out []string
	for name := range dist {
		if _, ok := o.sets[name]; !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// asns is what ExpandAS returns: the AS members of every as-set top includes
// and their honored aut-num members.
func (o *oracle) asns(top string) []types.ASN {
	dist, _ := o.reach(top)
	seen := map[types.ASN]bool{}
	for name := range dist {
		s, ok := o.sets[name]
		if !ok {
			continue
		}
		for _, mm := range s.members {
			if mm.kind == "as" {
				seen[mm.as] = true
			}
		}
		for _, c := range o.m.objs {
			if honored(s, c) {
				seen[c.as] = true
			}
		}
	}
	out := make([]types.ASN, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// routes returns what as originates, over both sources.
func (o *oracle) routes(as types.ASN) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range o.m.objs {
		if c.class != "aut-num" && c.as == as {
			out = append(out, c.pfx)
		}
	}
	return out
}

// moreSpecifics returns p's more-specifics (p included) with lengths in
// [lo, hi]; none when the window is empty.
func moreSpecifics(p netip.Prefix, lo, hi int) []netip.Prefix {
	lo, hi = max(lo, p.Bits()), min(hi, p.Addr().BitLen())
	var out []netip.Prefix
	for level := []netip.Prefix{p}; len(level) > 0 && level[0].Bits() <= hi; {
		var next []netip.Prefix
		for _, q := range level {
			if q.Bits() >= lo {
				out = append(out, q)
			}
			if q.Bits() < q.Addr().BitLen() {
				b := q.Addr().AsSlice()
				b[q.Bits()/8] |= 0x80 >> (q.Bits() % 8)
				a, _ := netip.AddrFromSlice(b)
				next = append(next, netip.PrefixFrom(q.Addr(), q.Bits()+1), netip.PrefixFrom(a, q.Bits()+1))
			}
		}
		level = next
	}
	return out
}

// apply is RFC 2622 §2's range operator on one prefix.
func apply(op string, p netip.Prefix) []netip.Prefix {
	var n, m int
	switch {
	case op == "":
		return []netip.Prefix{p}
	case op == "^+":
		return moreSpecifics(p, p.Bits(), 128)
	case op == "^-":
		return moreSpecifics(p, p.Bits()+1, 128)
	}
	if _, err := fmt.Sscanf(op, "^%d-%d", &n, &m); err != nil {
		fmt.Sscanf(op, "^%d", &n)
		m = n
	}
	return moreSpecifics(p, n, m)
}

// prefixes is what ExpandPrefixes returns for top under afi: the least fixpoint
// of the set definitions, where a route-set denotes its prefix members, the
// routes of its AS and as-set members and the sets it includes — each under the
// member's operator — and its honored routes; and an as-set, the routes of its
// ASes, of the as-sets it includes and of its honored aut-nums.
func (o *oracle) prefixes(top string, afi types.AFI) []netip.Prefix {
	val := map[string]map[netip.Prefix]bool{}
	for changed := true; changed; {
		changed = false
		for name, s := range o.sets {
			next := map[netip.Prefix]bool{}
			add := func(op string, ps []netip.Prefix) {
				for _, p := range ps {
					for _, q := range apply(op, p) {
						next[q] = true
					}
				}
			}
			for _, mm := range s.members {
				switch mm.kind {
				case "pfx":
					add(mm.op, []netip.Prefix{mm.pfx})
				case "as":
					add(mm.op, o.routes(mm.as))
				case "set":
					if nested(s.class, setClass(mm.set)) {
						for p := range val[mm.set] {
							add(mm.op, []netip.Prefix{p})
						}
					}
				}
			}
			for _, c := range o.m.objs {
				if !honored(s, c) {
					continue
				}
				if c.class == "aut-num" {
					add("", o.routes(c.as))
				} else {
					add("", []netip.Prefix{c.pfx})
				}
			}
			if len(next) != len(val[name]) {
				val[name], changed = next, true
			}
		}
	}
	var out []netip.Prefix
	for p := range val[top] {
		if afi == types.AFIv4 && !p.Addr().Is4() || afi == types.AFIv6 && !p.Addr().Is6() {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// ---- checking a Source against the oracle ----

func decodeAll(t *testing.T, texts []string) []object.Object {
	t.Helper()
	var objs []object.Object
	for _, text := range texts {
		raw, _ := rpsl.ParseObject(text)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	return objs
}

func names(ns []types.SetName) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.String())
	}
	sort.Strings(out)
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	sort.Strings(out)
	return out
}

// checkModel expands every set of the model through src and compares the
// results with the oracle. With limits, it also checks that MaxDepth and
// MaxPrefixes hold exactly at the true depth and size and fail just below.
func checkModel(t *testing.T, label string, o *oracle, texts []string, src resolve.Source, limits bool) {
	t.Helper()
	ctx := context.Background()
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s: %s\nobjects:\n%s", label, fmt.Sprintf(format, args...), strings.Join(texts, "\n"))
	}
	var tops []string
	for name := range o.sets {
		tops = append(tops, name)
	}
	sort.Strings(tops)
	for _, top := range tops {
		n := mustSet(t, top)
		_, anySet := o.reach(top)
		wantMissing := o.missing(top)
		if o.sets[top].class == types.ClassAsSet {
			got, err := (&resolve.Expander{Src: src}).ExpandAS(ctx, n)
			var anyErr *resolve.AnySetError
			switch {
			case anySet:
				if !errors.As(err, &anyErr) {
					fail("ExpandAS(%s) = %v, %v; want AnySetError", top, got, err)
				}
			case err != nil:
				fail("ExpandAS(%s): %v", top, err)
			case !slices.Equal(got.List(), o.asns(top)) || !slices.Equal(names(got.Missing()), wantMissing):
				fail("ExpandAS(%s) = %v missing %v; oracle %v missing %v", top, got.List(), names(got.Missing()), o.asns(top), wantMissing)
			}
		}
		for _, afi := range []types.AFI{types.AFIv4, types.AFIv6, types.AFIAny} {
			want := o.prefixes(top, afi)
			got, err := (&resolve.Expander{Src: src, AFI: afi}).ExpandPrefixes(ctx, n)
			var anyErr *resolve.AnySetError
			switch {
			case anySet:
				if !errors.As(err, &anyErr) {
					fail("ExpandPrefixes(%s, %v) = %v, %v; want AnySetError", top, afi, got, err)
				}
				continue
			case err != nil:
				fail("ExpandPrefixes(%s, %v): %v", top, afi, err)
			case !slices.Equal(prefixStrings(got.List()), prefixStrings(want)) || !slices.Equal(names(got.Missing()), wantMissing):
				fail("ExpandPrefixes(%s, %v) = %v missing %v;\noracle %v missing %v", top, afi,
					prefixStrings(got.List()), names(got.Missing()), prefixStrings(want), wantMissing)
			}
			if !limits || len(want) < 2 {
				continue
			}
			if _, err := (&resolve.Expander{Src: src, AFI: afi, MaxPrefixes: len(want)}).ExpandPrefixes(ctx, n); err != nil {
				fail("ExpandPrefixes(%s, %v) with MaxPrefixes = its size %d: %v", top, afi, len(want), err)
			}
			_, err = (&resolve.Expander{Src: src, AFI: afi, MaxPrefixes: len(want) - 1}).ExpandPrefixes(ctx, n)
			if tl := (*resolve.SetTooLargeError)(nil); !errors.As(err, &tl) || tl.Limit != resolve.LimitPrefixes {
				fail("ExpandPrefixes(%s, %v) with MaxPrefixes %d under its size: err %v", top, afi, len(want)-1, err)
			}
		}
		if !limits || anySet {
			continue
		}
		dist, _ := o.reach(top)
		depth := 0
		for _, d := range dist {
			depth = max(depth, d)
		}
		if depth < 2 {
			continue
		}
		if _, err := (&resolve.Expander{Src: src, MaxDepth: depth}).ExpandPrefixes(ctx, n); err != nil {
			fail("ExpandPrefixes(%s) with MaxDepth = its depth %d: %v", top, depth, err)
		}
		_, err := (&resolve.Expander{Src: src, MaxDepth: depth - 1}).ExpandPrefixes(ctx, n)
		if tl := (*resolve.SetTooLargeError)(nil); !errors.As(err, &tl) || tl.Limit != resolve.LimitDepth {
			fail("ExpandPrefixes(%s) with MaxDepth %d under its depth: err %v", top, depth-1, err)
		}
	}
}

// Every expansion of every random IRR matches the oracle, with objects loaded
// in random order and same-named sets in both sources.
func TestModelMemSource(t *testing.T) {
	for seed := uint64(0); seed < 3000; seed++ {
		r := rand.New(rand.NewPCG(seed, 5))
		m := randomModel(r, false)
		texts := m.texts(r)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		checkModel(t, fmt.Sprintf("seed %d", seed), newOracle(m), texts, src, true)
	}
}

// The network backends, served the same IRRs by an IRRd-like server, agree
// with the oracle too.
func TestModelBackends(t *testing.T) {
	for seed := uint64(0); seed < 150; seed++ {
		r := rand.New(rand.NewPCG(seed, 5))
		m := randomModel(r, false)
		texts := m.texts(r)
		db := irrtest.New(texts...).WithSources("RIPE", "RADB")
		o := newOracle(m)
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, KeepAlive: true, Timeout: 5 * time.Second}
		checkModel(t, fmt.Sprintf("irrd seed %d", seed), o, texts, ir, false)
		ir.Close()
		pl := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 8, MaxConns: 2, Timeout: 5 * time.Second}
		checkModel(t, fmt.Sprintf("pipelined irrd seed %d", seed), o, texts, pl, false)
		pl.Close()
		wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		checkModel(t, fmt.Sprintf("whois seed %d", seed), o, texts, wh, false)
	}
}
