package rtconfig

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// iosWriter writes Cisco IOS: a route-map per session direction, one permit
// entry per plan entry and a final deny, with named prefix-lists, numbered
// as-path access-lists and named standard community-lists. Negations are
// deny entries inside those lists, so a route one entry refuses still reaches
// the next.
type iosWriter struct{}

func (iosWriter) policy(g *Generator, b *strings.Builder, name string, pl plan) {
	n := g.names()
	fmt.Fprintf(b, "!\nno route-map %s\n", name)
	seq := n.MapFirstNo
	for _, e := range pl.entries {
		var lines []string
		if e.prefix != nil {
			list := iosWriter{}.prefixList(g, b, pl.family, *e.prefix)
			lines = append(lines, fmt.Sprintf("match %s address prefix-list %s", iosIP(pl.family), list))
		}
		if len(e.paths) > 0 {
			lines = append(lines, "match as-path "+iosPaths(g, b, e.paths))
		}
		if !e.comm.empty() {
			list, exact := iosCommunities(g, b, e.comm)
			line := "match community " + list
			if exact {
				line += " exact-match"
			}
			lines = append(lines, line)
		}
		sets := iosSets(g, b, pl.family, e.ops)
		fmt.Fprintf(b, "!\nroute-map %s permit %d\n", name, seq)
		for _, l := range append(lines, sets...) {
			b.WriteString(" " + l + "\n")
		}
		seq += n.MapIncrementBy
	}
	fmt.Fprintf(b, "!\nroute-map %s deny %d\n", name, seq)
}

func iosIP(afi types.AFI) string {
	if afi == types.AFIv6 {
		return "ipv6"
	}
	return "ip"
}

// iosRange writes a range as an IOS prefix-list entry: the prefix, then ge/le
// as the window needs.
func iosRange(r types.PrefixRange) string {
	p, bits, max := r.Prefix(), r.Prefix().Bits(), r.Prefix().Addr().BitLen()
	switch {
	case r.Lo() == bits && r.Hi() == bits:
		return p.String()
	case r.Lo() == bits:
		return fmt.Sprintf("%s le %d", p, r.Hi())
	case r.Hi() == max:
		return fmt.Sprintf("%s ge %d", p, r.Lo())
	}
	return fmt.Sprintf("%s ge %d le %d", p, r.Lo(), r.Hi())
}

func (iosWriter) prefixList(g *Generator, b *strings.Builder, afi types.AFI, pc prefixCond) string {
	n := g.names()
	name := fmt.Sprintf("pl%d", n.PrefixACLNo+g.prefixLists)
	g.prefixLists++
	kw := iosIP(afi)
	fmt.Fprintf(b, "!\nno %s prefix-list %s\n", kw, name)
	seq := 5
	entry := func(action, r string) {
		fmt.Fprintf(b, "%s prefix-list %s seq %d %s %s\n", kw, name, seq, action, r)
		seq += 5
	}
	for _, r := range pc.deny {
		entry("deny", iosRange(r))
	}
	switch {
	case pc.any && afi == types.AFIv6:
		entry("permit", "::/0 le 128")
	case pc.any:
		entry("permit", "0.0.0.0/0 le 32")
	default:
		for _, r := range pc.permit {
			entry("permit", iosRange(r))
		}
	}
	if seq == 5 { // nothing listed: a list that permits nothing
		if afi == types.AFIv6 {
			entry("deny", "::/0 le 128")
		} else {
			entry("deny", "0.0.0.0/0 le 32")
		}
	}
	return name
}

// iosPaths writes one as-path access-list for an entry's AS-path tests: the
// negated ones as deny entries, then the positive one (at most one; compile
// refused more) or permit-any.
func iosPaths(g *Generator, b *strings.Builder, paths []pathCond) string {
	n := g.names()
	num := n.ASPathACLNo + g.pathLists
	g.pathLists++
	fmt.Fprintf(b, "!\nno ip as-path access-list %d\n", num)
	positive := ".*"
	for _, pc := range paths {
		if pc.negated {
			fmt.Fprintf(b, "ip as-path access-list %d deny %s\n", num, pc.re)
		} else {
			positive = pc.re
		}
	}
	fmt.Fprintf(b, "ip as-path access-list %d permit %s\n", num, positive)
	return fmt.Sprint(num)
}

func (iosWriter) pathList(g *Generator, b *strings.Builder, pc pathCond) string {
	return iosPaths(g, b, []pathCond{pc})
}

func spellAll(cs []community, v Vendor) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.spell(v)
	}
	return strings.Join(parts, " ")
}

// iosCommunities writes a standard community-list for an entry's community
// tests. An exact match (compile allowed it only alone) is the list's one
// permit entry, matched with exact-match.
func iosCommunities(g *Generator, b *strings.Builder, c commCond) (string, bool) {
	n := g.names()
	name := fmt.Sprintf("cl%d", n.CommunityACLNo+g.commLists)
	g.commLists++
	fmt.Fprintf(b, "!\nno ip community-list standard %s\n", name)
	if c.hasEqual {
		fmt.Fprintf(b, "ip community-list standard %s permit %s\n", name, spellAll(c.equal, IOS))
		return name, true
	}
	for _, none := range c.none {
		fmt.Fprintf(b, "ip community-list standard %s deny %s\n", name, spellAll(none, IOS))
	}
	if len(c.all) > 0 {
		fmt.Fprintf(b, "ip community-list standard %s permit %s\n", name, spellAll(c.all, IOS))
	} else {
		fmt.Fprintf(b, "ip community-list standard %s permit internet\n", name)
	}
	return name, false
}

// iosSets writes an entry's set lines; a community delete needs a list of its
// own, written to b first.
func iosSets(g *Generator, b *strings.Builder, afi types.AFI, o setOps) []string {
	var sets []string
	if o.localPref >= 0 {
		sets = append(sets, fmt.Sprintf("set local-preference %d", o.localPref))
	}
	if o.med >= 0 {
		sets = append(sets, fmt.Sprintf("set metric %d", o.med))
	}
	if o.medIGP {
		sets = append(sets, "set metric-type internal")
	}
	switch {
	case o.commSetGiven && len(o.commSet) == 0:
		sets = append(sets, "set community none")
	case o.commSetGiven:
		sets = append(sets, "set community "+spellAll(o.commSet, IOS))
	}
	if len(o.commAdd) > 0 {
		sets = append(sets, "set community "+spellAll(o.commAdd, IOS)+" additive")
	}
	if len(o.commDel) > 0 {
		n := g.names()
		name := fmt.Sprintf("cl%d", n.CommunityACLNo+g.commLists)
		g.commLists++
		fmt.Fprintf(b, "!\nno ip community-list standard %s\n", name)
		for _, c := range o.commDel {
			fmt.Fprintf(b, "ip community-list standard %s permit %s\n", name, c.spell(IOS))
		}
		sets = append(sets, "set comm-list "+name+" delete")
	}
	if len(o.prepend) > 0 {
		var as []string
		for _, a := range o.prepend {
			as = append(as, num(a))
		}
		sets = append(sets, "set as-path prepend "+strings.Join(as, " "))
	}
	if o.nextHop.IsValid() {
		sets = append(sets, fmt.Sprintf("set %s next-hop %s", iosIP(afi), o.nextHop))
	}
	return sets
}

func (iosWriter) attach(g *Generator, b *strings.Builder, name string, s peval.Session, export bool) {
	dir := "in"
	if export {
		dir = "out"
	}
	fmt.Fprintf(b, "!\nrouter bgp %d\n neighbor %s remote-as %d\n", uint32(s.Local), s.PeerRtr, uint32(s.Peer))
	if s.AF.AFI == types.AFIv6 {
		fmt.Fprintf(b, " address-family ipv6 unicast\n  neighbor %s activate\n  neighbor %s route-map %s %s\n exit-address-family\n",
			s.PeerRtr, s.PeerRtr, name, dir)
	} else {
		fmt.Fprintf(b, " neighbor %s route-map %s %s\n", s.PeerRtr, name, dir)
	}
	b.WriteString("!\n")
}

func (iosWriter) defaults(g *Generator, b *strings.Builder, s peval.Session, d peval.Defaults) error {
	var lines []string
	for _, c := range d.Clauses {
		term := fmt.Sprint(c.Peering) // policy.Peering's concrete types are Stringers
		if len(c.Actions) > 0 || s.AF.AFI != types.AFIv4 {
			return unsupported(g.Vendor, CauseDefault, term)
		}
		if c.Networks == nil {
			lines = append(lines, "ip default-network 0.0.0.0")
			continue
		}
		nf := *c.Networks
		if len(nf.Conjuncts) != 1 {
			return unsupported(g.Vendor, CauseDefault, term)
		}
		conj := nf.Conjuncts[0]
		if conj.AnyPrefix() || conj.NotPrefixes.Len() > 0 || len(conj.Paths) > 0 || len(conj.Communities) > 0 {
			return unsupported(g.Vendor, CauseDefault, term)
		}
		for _, r := range conj.Prefixes.List() {
			if r.Lo() != r.Prefix().Bits() || r.Hi() != r.Prefix().Bits() {
				return unsupported(g.Vendor, CauseDefault, term)
			}
			lines = append(lines, "ip default-network "+r.Prefix().Addr().String())
		}
	}
	for _, l := range lines {
		b.WriteString("!\n" + l + "\n")
	}
	return nil
}

func (iosWriter) networks(g *Generator, b *strings.Builder, prefixes []netip.Prefix) error {
	for _, p := range prefixes {
		if p.Addr().Is4() {
			fmt.Fprintf(b, "network %s mask %s\n", p.Masked().Addr(), v4Mask(p.Bits()))
			continue
		}
		fmt.Fprintf(b, "network %s\n", p.Masked())
	}
	return nil
}

// v4Mask writes a netmask of bits ones, dotted: rtconfig's "network … mask …".
// (Not net.CIDRMask: rtconfig must not import package net.)
func v4Mask(bits int) string {
	m := ^uint32(0) << (32 - bits)
	if bits == 0 {
		m = 0
	}
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&0xff, m>>8&0xff, m&0xff)
}
