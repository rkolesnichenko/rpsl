package rtconfig

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// birdWriter writes BIRD 2: a filter per session direction, an if-block
// ending in accept per plan entry and a final reject. Every test is
// parenthesized, since BIRD gives &&, ||, = and ~ one precedence. Negations
// are "!" inside an entry's condition, so a route one entry refuses still
// reaches the next. BIRD does not merge two blocks for one protocol, so the
// neighbours' protocols are collected and written by WriteSessions.
type birdWriter struct{}

// birdSession is one neighbour's protocol: its filters, per family.
type birdSession struct {
	local, peer     types.ASN
	localAddr, addr netip.Addr
	channels        []birdChannel
}

type birdChannel struct {
	family   types.AFI
	imp, exp string // filter names; "" is none
}

// birdPrefix writes a range as a prefix-set element: p, p+ or p{a,b}.
func birdPrefix(r types.PrefixRange) string {
	p, bits, max := r.Prefix(), r.Prefix().Bits(), r.Prefix().Addr().BitLen()
	switch {
	case r.Lo() == bits && r.Hi() == bits:
		return p.String()
	case r.Lo() == bits && r.Hi() == max:
		return p.String() + "+"
	}
	return fmt.Sprintf("%s{%d,%d}", p, r.Lo(), r.Hi())
}

func birdSet(rs []types.PrefixRange) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = birdPrefix(r)
	}
	return "[ " + strings.Join(parts, ", ") + " ]"
}

func birdHas(c community) string { return "(" + c.spell(BIRD2) + " ~ bgp_community)" }

// birdAll is one parenthesized term: the route carries every community of cs.
func birdAll(cs []community) string {
	if len(cs) == 1 {
		return birdHas(cs[0])
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = birdHas(c)
	}
	return "(" + strings.Join(parts, " && ") + ")"
}

// birdExactly is one parenthesized term: the route carries exactly cs.
func birdExactly(cs []community) string {
	if len(cs) == 0 {
		return "(bgp_community.len = 0)"
	}
	pairs := make([]string, len(cs))
	for i, c := range cs {
		pairs[i] = c.spell(BIRD2)
	}
	terms := []string{"(delete(bgp_community, [ " + strings.Join(pairs, ", ") + " ]).len = 0)"}
	for _, c := range cs {
		terms = append(terms, birdHas(c))
	}
	return "(" + strings.Join(terms, " && ") + ")"
}

// birdConds writes an entry's tests, each one parenthesized term.
func birdConds(e entry) []string {
	var cond []string
	if pc := e.prefix; pc != nil {
		switch {
		case pc.any:
		case len(pc.permit) == 0:
			cond = append(cond, "false")
		default:
			cond = append(cond, "(net ~ "+birdSet(pc.permit)+")")
		}
		if len(pc.deny) > 0 {
			cond = append(cond, "!(net ~ "+birdSet(pc.deny)+")")
		}
	}
	for _, pc := range e.paths {
		t := "(bgp_path ~ " + pc.re + ")"
		if pc.negated {
			t = "!" + t
		}
		cond = append(cond, t)
	}
	for _, c := range e.comm.all {
		cond = append(cond, birdHas(c))
	}
	for _, none := range e.comm.none {
		cond = append(cond, "!"+birdAll(none))
	}
	if e.comm.hasEqual {
		cond = append(cond, birdExactly(e.comm.equal))
	}
	for _, ne := range e.comm.notEqual {
		cond = append(cond, "!"+birdExactly(ne))
	}
	return cond
}

// birdSets writes an entry's actions. BIRD's prepend puts one AS in front,
// so the list is prepended from its right end.
func birdSets(o setOps) []string {
	var out []string
	if o.localPref >= 0 {
		out = append(out, fmt.Sprintf("bgp_local_pref = %d;", o.localPref))
	}
	if o.med >= 0 {
		out = append(out, fmt.Sprintf("bgp_med = %d;", o.med))
	}
	if o.commSetGiven {
		out = append(out, "bgp_community = -empty-;")
		for _, c := range o.commSet {
			out = append(out, "bgp_community.add("+c.spell(BIRD2)+");")
		}
	}
	for _, c := range o.commAdd {
		out = append(out, "bgp_community.add("+c.spell(BIRD2)+");")
	}
	for _, c := range o.commDel {
		out = append(out, "bgp_community.delete("+c.spell(BIRD2)+");")
	}
	for i := len(o.prepend) - 1; i >= 0; i-- {
		out = append(out, "bgp_path.prepend("+num(o.prepend[i])+");")
	}
	if o.nextHop.IsValid() {
		out = append(out, "bgp_next_hop = "+o.nextHop.String()+";")
	}
	return out
}

func (birdWriter) policy(g *Generator, b *strings.Builder, name string, pl plan) {
	fmt.Fprintf(b, "filter %s {\n", name)
	for _, e := range pl.entries {
		cond := birdConds(e)
		indent := "  "
		if len(cond) > 0 {
			fmt.Fprintf(b, "  if %s then {\n", strings.Join(cond, " && "))
			indent = "    "
		}
		for _, s := range birdSets(e.ops) {
			b.WriteString(indent + s + "\n")
		}
		b.WriteString(indent + "accept;\n")
		if len(cond) > 0 {
			b.WriteString("  }\n")
		}
	}
	b.WriteString("  reject;\n}\n")
}

// attach records the filter for WriteSessions; it writes nothing.
func (birdWriter) attach(g *Generator, b *strings.Builder, name string, s peval.Session, export bool) {
	var ss *birdSession
	for _, x := range g.birdSessions {
		if x.addr == s.PeerRtr {
			ss = x
			break
		}
	}
	if ss == nil {
		ss = &birdSession{local: s.Local, peer: s.Peer, localAddr: s.LocalRtr, addr: s.PeerRtr}
		g.birdSessions = append(g.birdSessions, ss)
	}
	var ch *birdChannel
	for i := range ss.channels {
		if ss.channels[i].family == s.AF.AFI {
			ch = &ss.channels[i]
		}
	}
	if ch == nil {
		ss.channels = append(ss.channels, birdChannel{family: s.AF.AFI})
		ch = &ss.channels[len(ss.channels)-1]
	}
	if export {
		ch.exp = name
	} else {
		ch.imp = name
	}
}

func birdFilterRef(name string) string {
	if name == "" {
		return "none"
	}
	return "filter " + name
}

// sessions writes one protocol per neighbour attached since the last call.
func (birdWriter) sessions(g *Generator, b *strings.Builder) {
	for _, ss := range g.birdSessions {
		name := "peer_" + strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				return r
			}
			return '_'
		}, ss.addr.String())
		fmt.Fprintf(b, "protocol bgp %s {\n", name)
		if ss.localAddr.IsValid() {
			fmt.Fprintf(b, "  local %s as %d;\n", ss.localAddr, uint32(ss.local))
		} else {
			fmt.Fprintf(b, "  local as %d;\n", uint32(ss.local))
		}
		fmt.Fprintf(b, "  neighbor %s as %d;\n", ss.addr, uint32(ss.peer))
		for _, ch := range ss.channels {
			fam := "ipv4"
			if ch.family == types.AFIv6 {
				fam = "ipv6"
			}
			fmt.Fprintf(b, "  %s {\n    import %s;\n    export %s;\n  };\n", fam, birdFilterRef(ch.imp), birdFilterRef(ch.exp))
		}
		b.WriteString("}\n")
	}
	g.birdSessions = nil
}

// prefixList writes a named prefix set when nothing is denied, and otherwise
// a filter accepting what the list admits.
func (birdWriter) prefixList(g *Generator, b *strings.Builder, afi types.AFI, pc prefixCond) string {
	n := g.names()
	name := fmt.Sprintf("pl%d", n.PrefixACLNo+g.prefixLists)
	g.prefixLists++
	if len(pc.deny) == 0 && (pc.any || len(pc.permit) > 0) {
		set := birdSet(pc.permit)
		switch {
		case pc.any && afi == types.AFIv6:
			set = "[ ::/0+ ]"
		case pc.any:
			set = "[ 0.0.0.0/0+ ]"
		}
		fmt.Fprintf(b, "define %s = %s;\n", name, set)
		return name
	}
	fmt.Fprintf(b, "filter %s {\n  if %s then accept;\n  reject;\n}\n", name, strings.Join(birdConds(entry{prefix: &pc}), " && "))
	return name
}

func (birdWriter) pathList(g *Generator, b *strings.Builder, pc pathCond) string {
	n := g.names()
	name := fmt.Sprintf("as%d", n.ASPathACLNo+g.pathLists)
	g.pathLists++
	fmt.Fprintf(b, "filter %s {\n  if %s then accept;\n  reject;\n}\n", name, birdConds(entry{paths: []pathCond{pc}})[0])
	return name
}

func (birdWriter) defaults(g *Generator, b *strings.Builder, s peval.Session, d peval.Defaults) error {
	if len(d.Clauses) == 0 {
		return nil
	}
	return unsupported(g.Vendor, CauseDefault, fmt.Sprint(d.Clauses[0].Peering))
}

func (birdWriter) networks(g *Generator, b *strings.Builder, prefixes []netip.Prefix) error {
	return unsupported(g.Vendor, CauseNetworks, "networks")
}
