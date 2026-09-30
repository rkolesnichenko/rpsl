package rtconfig

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// xrWriter writes Cisco IOS-XR: a route-policy per session direction, an
// if-block ending in done per plan entry and a final drop, with a prefix-set,
// as-path-set or community-set per test. Negations are "not" inside an
// entry's condition, so a route one entry refuses still reaches the next.
type xrWriter struct{}

func (xrWriter) policy(g *Generator, b *strings.Builder, name string, pl plan) {
	type block struct{ cond, sets []string }
	var blocks []block
	for _, e := range pl.entries {
		var cond []string
		if e.prefix != nil {
			permit, deny := xrPrefixSets(g, b, *e.prefix)
			if permit != "" {
				cond = append(cond, "destination in "+permit)
			}
			if deny != "" {
				cond = append(cond, "not destination in "+deny)
			}
		}
		for _, pc := range e.paths {
			test := "as-path in " + xrPathSet(g, b, pc.re)
			if pc.negated {
				test = "not " + test
			}
			cond = append(cond, test)
		}
		if len(e.comm.all) > 0 {
			cond = append(cond, "community matches-every "+xrCommSet(g, b, e.comm.all))
		}
		for _, none := range e.comm.none {
			cond = append(cond, "not community matches-every "+xrCommSet(g, b, none))
		}
		blocks = append(blocks, block{cond, xrSets(e.ops)})
	}
	fmt.Fprintf(b, "!\nroute-policy %s\n", name)
	for _, bl := range blocks {
		indent := "  "
		if len(bl.cond) > 0 {
			fmt.Fprintf(b, "  if %s then\n", strings.Join(bl.cond, " and "))
			indent = "    "
		}
		for _, s := range bl.sets {
			b.WriteString(indent + s + "\n")
		}
		b.WriteString(indent + "done\n")
		if len(bl.cond) > 0 {
			b.WriteString("  endif\n")
		}
	}
	b.WriteString("  drop\nend-policy\n")
}

// xrSet writes a prefix-set, as-path-set or community-set.
func xrSet(b *strings.Builder, kind, name string, els []string) {
	fmt.Fprintf(b, "!\n%s %s\n", kind, name)
	for i, el := range els {
		sep := ","
		if i == len(els)-1 {
			sep = ""
		}
		fmt.Fprintf(b, "  %s%s\n", el, sep)
	}
	b.WriteString("end-set\n")
}

func xrRanges(rs []types.PrefixRange) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = iosRange(r)
	}
	return out
}

// xrPrefixSets writes an entry's prefix condition as prefix-sets: the
// permitted ranges ("" when any prefix is permitted) and the denied ones (""
// when none is denied).
func xrPrefixSets(g *Generator, b *strings.Builder, pc prefixCond) (permit, deny string) {
	n := g.names()
	base := fmt.Sprintf("pl%d", n.PrefixACLNo+g.prefixLists)
	g.prefixLists++
	if !pc.any {
		permit = base + "-permit"
		xrSet(b, "prefix-set", permit, xrRanges(pc.permit))
	}
	if len(pc.deny) > 0 {
		deny = base + "-deny"
		xrSet(b, "prefix-set", deny, xrRanges(pc.deny))
	}
	return permit, deny
}

func xrPathSet(g *Generator, b *strings.Builder, re string) string {
	n := g.names()
	name := fmt.Sprintf("as%d", n.ASPathACLNo+g.pathLists)
	g.pathLists++
	xrSet(b, "as-path-set", name, []string{"ios-regex '" + re + "'"})
	return name
}

func xrCommSet(g *Generator, b *strings.Builder, cs []community) string {
	n := g.names()
	name := fmt.Sprintf("cs%d", n.CommunityACLNo+g.commLists)
	g.commLists++
	els := make([]string, len(cs))
	for i, c := range cs {
		els[i] = c.spell(IOSXR)
	}
	xrSet(b, "community-set", name, els)
	return name
}

func xrList(cs []community) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.spell(IOSXR)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// xrSets writes an entry's actions.
func xrSets(o setOps) []string {
	var sets []string
	if o.localPref >= 0 {
		sets = append(sets, fmt.Sprintf("set local-preference %d", o.localPref))
	}
	if o.med >= 0 {
		sets = append(sets, fmt.Sprintf("set med %d", o.med))
	}
	if o.medIGP {
		sets = append(sets, "set med igp-cost")
	}
	switch {
	case o.commSetGiven && len(o.commSet) == 0:
		sets = append(sets, "delete community all")
	case o.commSetGiven:
		sets = append(sets, "set community "+xrList(o.commSet))
	}
	if len(o.commAdd) > 0 {
		sets = append(sets, "set community "+xrList(o.commAdd)+" additive")
	}
	if len(o.commDel) > 0 {
		sets = append(sets, "delete community in "+xrList(o.commDel))
	}
	// One line per run of one AS, the rightmost run first: each prepends to
	// what the last left, so the path ends up reading as o.prepend.
	for i := len(o.prepend); i > 0; {
		j := i - 1
		for j > 0 && o.prepend[j-1] == o.prepend[i-1] {
			j--
		}
		sets = append(sets, fmt.Sprintf("prepend as-path %s %d", num(o.prepend[i-1]), i-j))
		i = j
	}
	if o.nextHop.IsValid() {
		sets = append(sets, "set next-hop "+o.nextHop.String())
	}
	if o.nextHopSelf {
		sets = append(sets, "set next-hop self")
	}
	return sets
}

func (xrWriter) attach(g *Generator, b *strings.Builder, name string, s peval.Session, export bool) {
	dir, af := "in", "ipv4"
	if export {
		dir = "out"
	}
	if s.AF.AFI == types.AFIv6 {
		af = "ipv6"
	}
	fmt.Fprintf(b, "!\nrouter bgp %d\n neighbor %s\n  remote-as %d\n  address-family %s unicast\n   route-policy %s %s\n  !\n !\n!\n",
		uint32(s.Local), s.PeerRtr, uint32(s.Peer), af, name, dir)
}

// prefixList writes one prefix-set when nothing is denied. Otherwise a
// prefix-set cannot say it — its elements only permit — so it writes the
// permit and deny sets and a route-policy that passes what the list admits,
// and returns that policy's name.
func (xrWriter) prefixList(g *Generator, b *strings.Builder, afi types.AFI, pc prefixCond) string {
	if len(pc.deny) == 0 {
		n := g.names()
		name := fmt.Sprintf("pl%d", n.PrefixACLNo+g.prefixLists)
		g.prefixLists++
		els := xrRanges(pc.permit)
		switch {
		case pc.any && afi == types.AFIv6:
			els = []string{"::/0 le 128"}
		case pc.any:
			els = []string{"0.0.0.0/0 le 32"}
		}
		xrSet(b, "prefix-set", name, els)
		return name
	}
	permit, deny := xrPrefixSets(g, b, pc)
	name := strings.TrimSuffix(deny, "-deny")
	cond := "not destination in " + deny
	if permit != "" {
		cond = "destination in " + permit + " and " + cond
	}
	fmt.Fprintf(b, "!\nroute-policy %s\n  if %s then\n    done\n  endif\n  drop\nend-policy\n", name, cond)
	return name
}

// pathList writes an as-path-set; a negated one also gets a route-policy
// passing the paths the set does not match, whose name it returns.
func (xrWriter) pathList(g *Generator, b *strings.Builder, pc pathCond) string {
	name := xrPathSet(g, b, pc.re)
	if !pc.negated {
		return name
	}
	fmt.Fprintf(b, "!\nroute-policy %s-not\n  if not as-path in %s then\n    done\n  endif\n  drop\nend-policy\n", name, name)
	return name + "-not"
}

func (xrWriter) defaults(g *Generator, b *strings.Builder, s peval.Session, d peval.Defaults) error {
	if len(d.Clauses) == 0 {
		return nil
	}
	return unsupported(g.Vendor, CauseDefault, fmt.Sprint(d.Clauses[0].Peering))
}

// networks writes network statements per address family, for the operator
// to place under "router bgp", as rtconfig's networks output is placed.
func (xrWriter) networks(g *Generator, b *strings.Builder, prefixes []netip.Prefix) error {
	for _, v4 := range []bool{true, false} {
		var ps []netip.Prefix
		for _, p := range prefixes {
			if p.Addr().Is4() == v4 {
				ps = append(ps, p.Masked())
			}
		}
		if len(ps) == 0 {
			continue
		}
		af := "ipv6"
		if v4 {
			af = "ipv4"
		}
		fmt.Fprintf(b, "address-family %s unicast\n", af)
		for _, p := range ps {
			fmt.Fprintf(b, " network %s\n", p)
		}
		b.WriteString("!\n")
	}
	return nil
}
