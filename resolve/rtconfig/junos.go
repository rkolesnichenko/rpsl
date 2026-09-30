package rtconfig

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// junosWriter writes Junos: a policy-statement per session direction with one
// term per plan entry, whose conditions that need negation or range lists
// live in a subroutine policy (from policy X), and a final reject term — BGP's
// default import policy would otherwise accept.
type junosWriter struct{}

// jw writes indented Junos configuration.
type jw struct {
	b     *strings.Builder
	depth int
}

func (w *jw) line(format string, args ...any) {
	w.b.WriteString(strings.Repeat("    ", w.depth))
	fmt.Fprintf(w.b, format, args...)
	w.b.WriteByte('\n')
}

func (w *jw) open(format string, args ...any) {
	w.line(format+" {", args...)
	w.depth++
}

func (w *jw) close() {
	w.depth--
	w.line("}")
}

// junosRange writes a range as a route-filter's prefix and match type.
func junosRange(r types.PrefixRange) string {
	p, bits, max := r.Prefix(), r.Prefix().Bits(), r.Prefix().Addr().BitLen()
	switch {
	case r.Lo() == bits && r.Hi() == bits:
		return p.String() + " exact"
	case r.Lo() == bits && r.Hi() == max:
		return p.String() + " orlonger"
	case r.Lo() == bits+1 && r.Hi() == max:
		return p.String() + " longer"
	case r.Lo() == bits:
		return fmt.Sprintf("%s upto /%d", p, r.Hi())
	}
	return fmt.Sprintf("%s prefix-length-range /%d-/%d", p, r.Lo(), r.Hi())
}

// junosGroups splits ranges into groups whose prefixes are pairwise disjoint
// (none contains another, nor equals it), keeping their order: a term's
// route-filters are checked by longest match, which nested prefixes would
// defeat. Each group tracks its members and every ancestor of them, so a
// placement costs a walk up one prefix, not a scan of the group.
func junosGroups(rs []types.PrefixRange) [][]types.PrefixRange {
	type group struct {
		ranges    []types.PrefixRange
		members   map[netip.Prefix]bool
		ancestors map[netip.Prefix]bool // prefixes that contain (or equal) a member
	}
	var groups []*group
	nests := func(g *group, p netip.Prefix) bool {
		if g.ancestors[p] {
			return true // p contains or equals a member
		}
		for bits := p.Bits(); bits >= 0; bits-- {
			if g.members[netip.PrefixFrom(p.Addr(), bits).Masked()] {
				return true // a member contains p
			}
		}
		return false
	}
	for _, r := range rs {
		p := r.Prefix()
		var into *group
		for _, g := range groups {
			if !nests(g, p) {
				into = g
				break
			}
		}
		if into == nil {
			into = &group{members: map[netip.Prefix]bool{}, ancestors: map[netip.Prefix]bool{}}
			groups = append(groups, into)
		}
		into.ranges = append(into.ranges, r)
		into.members[p] = true
		for bits := p.Bits(); bits >= 0; bits-- {
			into.ancestors[netip.PrefixFrom(p.Addr(), bits).Masked()] = true
		}
	}
	out := make([][]types.PrefixRange, len(groups))
	for i, g := range groups {
		out[i] = g.ranges
	}
	return out
}

// sub writes a subroutine policy: the denied ranges, then the negated paths
// and communities, rejected; the permitted ranges accepted; the rest rejected
// — or accepted when any prefix is permitted.
func (junosWriter) sub(w *jw, name string, pc *prefixCond, negPaths []string, negComms []string) {
	w.open("policy-statement %s", name)
	term := func(kind string, k int, from func(), action string) {
		w.open("term %s-%d", kind, k)
		from()
		w.line("then %s;", action)
		w.close()
	}
	rfTerms := func(kind string, rs []types.PrefixRange, action string) {
		for k, g := range junosGroups(rs) {
			term(kind, k+1, func() {
				w.open("from")
				for _, r := range g {
					w.line("route-filter %s;", junosRange(r))
				}
				w.close()
			}, action)
		}
	}
	if pc != nil {
		rfTerms("deny", pc.deny, "reject")
	}
	for k, p := range negPaths {
		term("not-path", k+1, func() { w.line("from as-path %s;", p) }, "reject")
	}
	for k, c := range negComms {
		term("not-comm", k+1, func() { w.line("from community %s;", c) }, "reject")
	}
	rest := "accept"
	if pc != nil && !pc.any {
		rfTerms("permit", pc.permit, "accept")
		rest = "reject"
	}
	w.open("term rest")
	w.line("then %s;", rest)
	w.close()
	w.close()
}

func (jwr junosWriter) policy(g *Generator, b *strings.Builder, name string, pl plan) {
	w := &jw{b: b}
	w.open("policy-options")
	paths, comms := 0, 0
	defPath := func(re string) string {
		paths++
		n := fmt.Sprintf("%s-path-%d", name, paths)
		w.line("as-path %s %q;", n, re)
		return n
	}
	defComm := func(cs []community) string {
		comms++
		n := fmt.Sprintf("%s-comm-%d", name, comms)
		w.line("community %s members [ %s ];", n, spellAll(cs, Junos))
		return n
	}
	type term struct {
		from []string
		then []string
	}
	var terms []term
	for i, e := range pl.entries {
		var t term
		var negPaths, negComms []string
		for _, pc := range e.paths {
			n := defPath(pc.re)
			if pc.negated {
				negPaths = append(negPaths, n)
			} else {
				t.from = append(t.from, "as-path "+n)
			}
		}
		for _, none := range e.comm.none {
			negComms = append(negComms, defComm(none))
		}
		if len(e.comm.all) > 0 {
			t.from = append(t.from, "community "+defComm(e.comm.all))
		}
		if e.prefix != nil || len(negPaths) > 0 || len(negComms) > 0 {
			sub := fmt.Sprintf("%s-sub-%d", name, i+1)
			jwr.sub(w, sub, e.prefix, negPaths, negComms)
			t.from = append([]string{"policy " + sub}, t.from...)
		}
		o := e.ops
		if o.localPref >= 0 {
			t.then = append(t.then, fmt.Sprintf("local-preference %d", o.localPref))
		}
		if o.med >= 0 {
			t.then = append(t.then, fmt.Sprintf("metric %d", o.med))
		}
		if o.medIGP {
			t.then = append(t.then, "metric igp")
		}
		if o.commSetGiven {
			t.then = append(t.then, "community set "+defComm(o.commSet))
		}
		if len(o.commAdd) > 0 {
			t.then = append(t.then, "community add "+defComm(o.commAdd))
		}
		if len(o.commDel) > 0 {
			t.then = append(t.then, "community delete "+defComm(o.commDel))
		}
		if len(o.prepend) > 0 {
			var as []string
			for _, a := range o.prepend {
				as = append(as, num(a))
			}
			t.then = append(t.then, fmt.Sprintf("as-path-prepend %q", strings.Join(as, " ")))
		}
		if o.nextHop.IsValid() {
			t.then = append(t.then, "next-hop "+o.nextHop.String())
		}
		if o.nextHopSelf {
			t.then = append(t.then, "next-hop self")
		}
		terms = append(terms, t)
	}
	w.open("policy-statement %s", name)
	for i, t := range terms {
		w.open("term entry-%d", i+1)
		if len(t.from) > 0 {
			w.open("from")
			for _, f := range t.from {
				w.line("%s;", f)
			}
			w.close()
		}
		w.open("then")
		for _, x := range t.then {
			w.line("%s;", x)
		}
		w.line("accept;")
		w.close()
		w.close()
	}
	w.open("term reject")
	w.line("then reject;")
	w.close()
	w.close()
	w.close()
}

func (junosWriter) attach(g *Generator, b *strings.Builder, name string, s peval.Session, export bool) {
	w := &jw{b: b}
	dir, family := "import", "inet"
	if export {
		dir = "export"
	}
	if s.AF.AFI == types.AFIv6 {
		family = "inet6"
	}
	w.open("protocols")
	w.open("bgp")
	w.open("group peer-%s", s.PeerRtr)
	w.line("type external;")
	w.line("peer-as %d;", uint32(s.Peer))
	w.open("neighbor %s", s.PeerRtr)
	w.line("%s %s;", dir, name)
	w.open("family %s", family)
	w.line("unicast;")
	w.close()
	w.close()
	w.close()
	w.close()
	w.close()
}

func (jwr junosWriter) prefixList(g *Generator, b *strings.Builder, afi types.AFI, pc prefixCond) string {
	n := g.names()
	name := fmt.Sprintf("prefix-list-%d", n.AccessListNo+g.accessLists)
	g.accessLists++
	w := &jw{b: b}
	w.open("policy-options")
	jwr.sub(w, name, &pc, nil, nil)
	w.close()
	return name
}

func (jwr junosWriter) pathList(g *Generator, b *strings.Builder, pc pathCond) string {
	n := g.names()
	num := n.ASPathACLNo + g.pathLists
	g.pathLists++
	name := fmt.Sprintf("as-path-%d", num)
	w := &jw{b: b}
	w.open("policy-options")
	w.line("as-path %s %q;", name, pc.re)
	if pc.negated {
		pol := name + "-policy"
		jwr.sub(w, pol, nil, []string{name}, nil)
		name = pol
	}
	w.close()
	return name
}

func (junosWriter) defaults(g *Generator, b *strings.Builder, s peval.Session, d peval.Defaults) error {
	if len(d.Clauses) == 0 {
		return nil
	}
	return unsupported(g.Vendor, CauseDefault, fmt.Sprint(d.Clauses[0].Peering))
}

func (junosWriter) networks(g *Generator, b *strings.Builder, prefixes []netip.Prefix) error {
	return unsupported(g.Vendor, CauseNetworks, "networks")
}
