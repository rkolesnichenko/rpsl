package filtergen

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Each printer below is one of bgpq4 1.16's (printer.c), and writes what it
// writes, byte for byte: the tests hold them to the bgpq4 binary. The entries
// come in the order they are to be written (Tree.Entries is bgpq4's).

// ipWord is "ip" or "ipv6", as most vendors name the family.
func ipWord(v6 bool) string {
	if v6 {
		return "ipv6"
	}
	return "ip"
}

// anyPrefix is the family's default route, which empty lists deny.
func anyPrefix(v6 bool) string {
	if v6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// bounds are the lengths an aggregate entry is written with where the vendor
// has a lower bound: its own, unless the aggregate starts below the prefix.
func (e Entry) bounds() (lo, hi int) {
	lo = e.Prefix.Bits()
	if e.Lo > lo {
		lo = e.Lo
	}
	return lo, e.Hi
}

// longer reports whether an aggregate entry starts past the prefix itself:
// bgpq4 then writes both bounds ("ge … le …"), and otherwise only the upper.
func (e Entry) longer() bool { return e.Lo > e.Prefix.Bits() }

// WritePrefixes writes a prefix list, route-filter or route-filter-list of
// es, in o's vendor format.
func WritePrefixes(w io.Writer, o Options, es []Entry) error {
	if o.Kind.asKind() {
		return unsupported("%s are written from AS numbers", o.Kind)
	}
	if !supports(o.Vendor, o.Kind) {
		return unsupported("%s writes no %s", o.Vendor, o.Kind)
	}
	var b strings.Builder
	var err error
	switch o.Kind {
	case RouteFilter:
		routeFilter(&b, o, es)
	case RouteFilterList:
		fmt.Fprintf(&b, "policy-options {\nreplace:\n  route-filter-list %s {\n", o.name())
		if len(es) == 0 {
			fmt.Fprintf(&b, "    %s orlonger reject;\n", anyPrefix(o.V6))
		}
		for _, e := range es {
			junosFilter(&b, e, false)
		}
		b.WriteString("  }\n}\n")
	default:
		err = prefixList(&b, o, es)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, b.String())
	return err
}

func prefixList(b *strings.Builder, o Options, es []Entry) error {
	name, ip, v6 := o.name(), ipWord(o.V6), o.V6
	switch o.Vendor {
	case Cisco:
		fmt.Fprintf(b, "no %s prefix-list %s\n", ip, name)
		seq := 0
		if o.Sequence {
			seq = 1
		}
		if len(es) == 0 {
			seqno := ""
			if seq > 0 {
				seqno = " seq 1"
			}
			fmt.Fprintf(b, "! generated prefix-list %s is empty\n%s prefix-list %s%s deny %s\n", name, ip, name, seqno, anyPrefix(v6))
		}
		for _, e := range es {
			seqno := ""
			if seq > 0 {
				seqno = fmt.Sprintf(" seq %d", seq)
				seq++
			}
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "%s prefix-list %s%s permit %s\n", ip, name, seqno, ntp(e.Prefix))
			case e.longer():
				fmt.Fprintf(b, "%s prefix-list %s%s permit %s ge %d le %d\n", ip, name, seqno, ntp(e.Prefix), e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "%s prefix-list %s%s permit %s le %d\n", ip, name, seqno, ntp(e.Prefix), e.Hi)
			}
		}
	case CiscoXR:
		fmt.Fprintf(b, "no prefix-set %s\nprefix-set %s\n", name, name)
		for i, e := range es {
			sep := " "
			if i > 0 {
				sep = ",\n "
			}
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "%s%s", sep, ntp(e.Prefix))
			case e.longer():
				fmt.Fprintf(b, "%s%s ge %d le %d", sep, ntp(e.Prefix), e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "%s%s le %d", sep, ntp(e.Prefix), e.Hi)
			}
		}
		b.WriteString("\nend-set\n")
	case JSON:
		fmt.Fprintf(b, "{ \"%s\": [", name)
		for i, e := range es {
			comma := ""
			if i > 0 {
				comma = ","
			}
			p := jsonPrefix(e.Prefix)
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "%s\n    { \"prefix\": \"%s\", \"exact\": true }", comma, p)
			case e.longer():
				fmt.Fprintf(b, "%s\n    { \"prefix\": \"%s\", \"exact\": false,\n      \"greater-equal\": %d, \"less-equal\": %d }", comma, p, e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "%s\n    { \"prefix\": \"%s\", \"exact\": false, \"less-equal\": %d }", comma, p, e.Hi)
			}
		}
		b.WriteString("\n] }\n")
	case BIRD:
		if len(es) == 0 {
			break // bgpq4 writes an empty BIRD list as nothing at all
		}
		fmt.Fprintf(b, "%s = [", name)
		for i, e := range es {
			comma := ""
			if i > 0 {
				comma = ","
			}
			if !e.Aggregate {
				fmt.Fprintf(b, "%s\n    %s", comma, ntp(e.Prefix))
			} else {
				lo, hi := e.bounds()
				fmt.Fprintf(b, "%s\n    %s{%d,%d}", comma, ntp(e.Prefix), lo, hi)
			}
		}
		b.WriteString("\n];\n")
	case Junos:
		fmt.Fprintf(b, "policy-options {\nreplace:\n prefix-list %s {\n", name)
		for _, e := range es {
			if e.Aggregate {
				return unsupported("a Junos prefix-list holds exact prefixes, and %s is a range", e.Range())
			}
			fmt.Fprintf(b, "    %s;\n", ntp(e.Prefix))
		}
		b.WriteString(" }\n}\n")
	case OpenBGPD:
		if len(es) == 0 {
			fmt.Fprintf(b, "# generated prefix-list %s (AS %d) is empty\n", name, uint32(o.AS))
			if o.AS == 0 {
				b.WriteString("# use -a <asn> to generate \"deny from ASN <asn>\" instead of this list\n")
			}
		}
		if len(es) == 0 && o.AS != 0 {
			fmt.Fprintf(b, "deny from AS %d\n", uint32(o.AS))
			break
		}
		named := name != "NN"
		if named {
			fmt.Fprintf(b, "%s=\"", name)
		}
		b.WriteString("prefix { ")
		for _, e := range es {
			openbgpdPrefix(b, e)
		}
		b.WriteString("\n\t}")
		if named {
			b.WriteString("\"")
		}
		b.WriteString("\n")
	case Arista:
		fmt.Fprintf(b, "no %s prefix-list %s\n", ip, name)
		seq := 1 // -e always numbers its entries
		if len(es) == 0 {
			fmt.Fprintf(b, "! generated prefix-list %s is empty\n%s prefix-list %s\n   seq %d deny %s\n", name, ip, name, seq, anyPrefix(v6))
			break
		}
		fmt.Fprintf(b, "%s prefix-list %s\n", ip, name)
		for _, e := range es {
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "   seq %d permit %s\n", seq, ntp(e.Prefix))
			case e.longer():
				fmt.Fprintf(b, "   seq %d permit %s ge %d le %d\n", seq, ntp(e.Prefix), e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "   seq %d permit %s le %d\n", seq, ntp(e.Prefix), e.Hi)
			}
			seq++
		}
	case Nokia:
		fmt.Fprintf(b, "configure router policy-options\nbegin\nno prefix-list \"%s\"\nprefix-list \"%s\"\n", name, name)
		for _, e := range es {
			if !e.Aggregate {
				fmt.Fprintf(b, "    prefix %s exact\n", ntp(e.Prefix))
			} else {
				lo, hi := e.bounds()
				fmt.Fprintf(b, "    prefix %s prefix-length-range %d-%d\n", ntp(e.Prefix), lo, hi)
			}
		}
		b.WriteString("exit\ncommit\n")
	case NokiaMD:
		fmt.Fprintf(b, "/configure policy-options\ndelete prefix-list \"%s\"\nprefix-list \"%s\" {\n", name, name)
		for _, e := range es {
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "    prefix %s type exact {\n    }\n", ntp(e.Prefix))
			case e.longer():
				fmt.Fprintf(b, "    prefix %s type range {\n        start-length %d\n        end-length %d\n    }\n", ntp(e.Prefix), e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "    prefix %s type through {\n        through-length %d\n    }\n", ntp(e.Prefix), e.Hi)
			}
		}
		b.WriteString("}\n")
	case NokiaSRL:
		fmt.Fprintf(b, "/routing-policy\ndelete prefix-set \"%s\"\nprefix-set \"%s\" {\n", name, name)
		for _, e := range es {
			if !e.Aggregate {
				fmt.Fprintf(b, "    prefix %s mask-length-range exact { }\n", ntp(e.Prefix))
			} else {
				lo, hi := e.bounds()
				fmt.Fprintf(b, "    prefix %s mask-length-range %d..%d { }\n", ntp(e.Prefix), lo, hi)
			}
		}
		b.WriteString("}\n")
	case MikroTik6, MikroTik7:
		if len(es) == 0 {
			fmt.Fprintf(b, "# generated prefix-list %s is empty\n", name)
		}
		fam := "V4"
		if v6 {
			fam = "V6"
		}
		for _, e := range es {
			switch {
			case o.Vendor == MikroTik6 && e.Aggregate:
				fmt.Fprintf(b, "/routing filter add action=accept chain=\"%s-%s\" prefix=%s prefix-length=%d-%d\n", name, fam, ntp(e.Prefix), e.Lo, e.Hi)
			case o.Vendor == MikroTik6:
				fmt.Fprintf(b, "/routing filter add action=accept chain=\"%s-%s\" prefix=%s\n", name, fam, ntp(e.Prefix))
			case e.Aggregate:
				fmt.Fprintf(b, "/routing filter rule add chain=\"%s-%s\" rule=\"if (dst in %s && dst-len in %d-%d) {accept}\"\n", name, fam, ntp(e.Prefix), e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "/routing filter rule add chain=\"%s-%s\" rule=\"if (dst==%s) {accept}\"\n", name, fam, ntp(e.Prefix))
			}
		}
	case Huawei:
		fmt.Fprintf(b, "undo ip %s-prefix %s\n", ip, name)
		if len(es) == 0 {
			seqno := ""
			if o.Sequence {
				seqno = " seq 1"
			}
			fmt.Fprintf(b, "ip %s-prefix %s%s deny %s\n", ip, name, seqno, anyPrefix(v6))
		}
		for _, e := range es {
			p := spaced(e.Prefix)
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "ip %s-prefix %s permit %s\n", ip, name, p)
			case e.longer():
				fmt.Fprintf(b, "ip %s-prefix %s permit %s greater-equal %d less-equal %d\n", ip, name, p, e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "ip %s-prefix %s permit %s less-equal %d\n", ip, name, p, e.Hi)
			}
		}
	case HuaweiXPL:
		fmt.Fprintf(b, "no xpl %s-prefix-list %s\nxpl %s-prefix-list %s\n", ip, name, ip, name)
		for i, e := range es {
			sep := " "
			if i > 0 {
				sep = ",\n "
			}
			p := spaced(e.Prefix)
			switch {
			case !e.Aggregate:
				fmt.Fprintf(b, "%s %s", sep, p)
			case e.longer():
				fmt.Fprintf(b, "%s %s ge %d le %d", sep, p, e.Lo, e.Hi)
			default:
				fmt.Fprintf(b, "%s %s le %d", sep, p, e.Hi)
			}
		}
		b.WriteString("\nend-list\n")
	case UserFormat:
		for _, e := range es {
			lo, hi := e.Prefix.Bits(), e.Prefix.Bits()
			if e.Aggregate {
				lo, hi = e.bounds()
			}
			userFormat(b, o.Format, name, e.Prefix, lo, hi)
		}
		if f := o.Format; len(f) < 2 || f[len(f)-2:] != `\n` {
			b.WriteString("\n")
		}
	case Plain:
		for _, e := range es {
			b.WriteString(e.Range().String() + "\n")
		}
	default:
		return unsupported("%s writes no %s", o.Vendor, o.Kind)
	}
	return nil
}

// routeFilter writes -E: a Junos route-filter, a Cisco or Arista extended
// access-list, an OpenBGPD prefix-set, a Nokia ip-prefix-list, or an SR Linux
// ACL filter.
func routeFilter(b *strings.Builder, o Options, es []Entry) {
	name, v6 := o.name(), o.V6
	switch o.Vendor {
	case Junos:
		policy, term, hasTerm := strings.Cut(name, "/")
		if hasTerm {
			fmt.Fprintf(b, "policy-options {\n policy-statement %s {\n  term %s {\nreplace:\n   from {\n", policy, term)
		} else {
			fmt.Fprintf(b, "policy-options {\n policy-statement %s { \nreplace:\n  from {\n", name)
		}
		if o.Match != "" {
			fmt.Fprintf(b, "    %s;\n", o.Match)
		}
		if len(es) == 0 {
			fmt.Fprintf(b, "    route-filter %s orlonger reject;\n", anyPrefix(v6))
		}
		for _, e := range es {
			junosFilter(b, e, true)
		}
		if hasTerm {
			b.WriteString("   }\n  }\n }\n}\n")
		} else {
			b.WriteString("  }\n }\n}\n")
		}
	case Cisco, Arista:
		fmt.Fprintf(b, "no ip access-list extended %s\n", name)
		if len(es) == 0 {
			fmt.Fprintf(b, "! generated access-list %s is empty\nip access-list extended %s deny any any\n", name, name)
			return
		}
		fmt.Fprintf(b, "ip access-list extended %s\n", name)
		for _, e := range es {
			ciscoACL(b, e)
		}
	case OpenBGPD:
		fmt.Fprintf(b, "prefix-set %s {", name)
		for _, e := range es {
			openbgpdPrefix(b, e)
		}
		b.WriteString("\n}\n")
	case Nokia:
		ip := ipWord(v6)
		fmt.Fprintf(b, "configure filter match-list\nno %s-prefix-list \"%s\"\n%s-prefix-list \"%s\" create\n", ip, name, ip, name)
		if len(es) == 0 {
			fmt.Fprintf(b, "# generated ip-prefix-list %s is empty\n", name)
		}
		for _, e := range es {
			fmt.Fprintf(b, "    prefix %s\n", ntp(e.Prefix))
		}
		b.WriteString("exit\n")
	case NokiaMD:
		ip := ipWord(v6)
		fmt.Fprintf(b, "/configure filter match-list\ndelete %s-prefix-list \"%s\"\n%s-prefix-list \"%s\" {\n", ip, name, ip, name)
		if len(es) == 0 {
			fmt.Fprintf(b, "# generated %s-prefix-list %s is empty\n", ip, name)
		}
		for _, e := range es {
			fmt.Fprintf(b, "    prefix %s { }\n", ntp(e.Prefix))
		}
		b.WriteString("}\n")
	case NokiaSRL:
		fam := '4'
		if v6 {
			fam = '6'
		}
		fmt.Fprintf(b, "/acl \ndelete ipv%c-filter \"%s\"\nipv%c-filter \"%s\" {\n", fam, name, fam, name)
		if len(es) == 0 {
			fmt.Fprintf(b, "# generated ipv%c-filter '%s' is empty\n", fam, name)
		}
		for i, e := range es {
			fmt.Fprintf(b, " entry %d {\n  action { accept { } }\n  match { source-ip { prefix %s } } }\n", 10+10*i, ntp(e.Prefix))
		}
		b.WriteString("}\n")
	}
}

// junosFilter writes one Junos route-filter line; in a route-filter-list the
// lines are not prefixed.
func junosFilter(b *strings.Builder, e Entry, prefixed bool) {
	rf := ""
	if prefixed {
		rf = "route-filter "
	}
	switch {
	case !e.Aggregate:
		fmt.Fprintf(b, "    %s%s exact;\n", rf, ntp(e.Prefix))
	case e.longer():
		fmt.Fprintf(b, "    %s%s prefix-length-range /%d-/%d;\n", rf, ntp(e.Prefix), e.Lo, e.Hi)
	default:
		fmt.Fprintf(b, "    %s%s upto /%d;\n", rf, ntp(e.Prefix), e.Hi)
	}
}

func openbgpdPrefix(b *strings.Builder, e Entry) {
	switch {
	case !e.Aggregate:
		fmt.Fprintf(b, "\n\t%s", ntp(e.Prefix))
	case e.Lo == e.Hi:
		fmt.Fprintf(b, "\n\t%s prefixlen = %d", ntp(e.Prefix), e.Hi)
	default:
		lo, hi := e.bounds()
		fmt.Fprintf(b, "\n\t%s prefixlen %d - %d", ntp(e.Prefix), lo, hi)
	}
}

// ciscoACL writes an entry of a Cisco extended access-list, bgpq4's way: the
// prefix's address and the lengths it allows, each as an address and a
// wildcard (bgpq4_print_ceacl, its arithmetic kept).
func ciscoACL(b *strings.Builder, e Entry) {
	addr := e.Prefix.Addr()
	bits := e.Prefix.Bits()
	if !e.Aggregate {
		// A shift by 32 is undefined in C; the hardware bgpq4 runs on shifts
		// by the count modulo 32, which leaves the mask all ones.
		netmask := uint32(0xffffffff)
		if bits != 32 {
			netmask <<= uint(32-bits) % 32
		} else {
			netmask = 0
		}
		fmt.Fprintf(b, " permit ip host %s host %s\n", addr, dotted(netmask))
		return
	}
	shr := func(n int) uint32 { return uint32(uint64(0xffffffff) >> uint(n)) }
	var wild2 uint32
	if e.Hi != 32 {
		wild2 = shr(e.Hi)
	}
	wildaddr := shr(bits) &^ wild2
	mask := uint32(0xffffffff)
	if e.Lo != 32 {
		mask = uint32((uint64(0xffffffff) << uint(32-e.Lo)) & 0xffffffff)
	}
	wildmask := shr(e.Lo) &^ wild2
	if wildaddr != 0 {
		fmt.Fprintf(b, " permit ip %s %s ", addr, dotted(wildaddr))
	} else {
		fmt.Fprintf(b, " permit ip host %s ", addr)
	}
	if wildmask != 0 {
		fmt.Fprintf(b, "%s %s\n", dotted(mask), dotted(wildmask))
	} else {
		fmt.Fprintf(b, "host %s\n", dotted(mask))
	}
}

func dotted(v uint32) string {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

// ntp is a prefix printed as bgpq4 prints it, with inet_ntop.
type ntp netip.Prefix

func (p ntp) String() string {
	return fmt.Sprintf("%s/%d", ntop(netip.Prefix(p).Addr()), netip.Prefix(p).Bits())
}

// ntop writes an address as inet_ntop does (glibc's and the BSDs' alike).
// That is netip's form, but for an IPv4-compatible IPv6 address — the first
// 96 bits zero, the next 16 not — which inet_ntop writes with the last 32
// bits dotted: ::1.2.3.4, where netip writes ::102:304.
func ntop(a netip.Addr) string {
	if !a.Is6() || a.Is4In6() {
		return a.String()
	}
	b := a.As16()
	for _, x := range b[:12] {
		if x != 0 {
			return a.String()
		}
	}
	if b[12] == 0 && b[13] == 0 {
		return a.String() // ::, ::1, ::102: a run of seven zero words
	}
	return "::" + netip.AddrFrom4([4]byte(b[12:16])).String()
}

// spaced writes a prefix as Huawei takes it: "192.0.2.0 24".
func spaced(p netip.Prefix) string { return fmt.Sprintf("%s %d", ntop(p.Addr()), p.Bits()) }

// jsonPrefix writes a prefix as bgpq4's JSON does, its slash escaped.
func jsonPrefix(p netip.Prefix) string {
	return fmt.Sprintf("%s\\/%d", ntop(p.Addr()), p.Bits())
}

// userFormat expands one entry into bgpq4's -F template
// (sx_prefix_snprintf_fmt): %n or %r the address, %l the length, %a and %A
// the lengths allowed, %m and %i the netmask and its inverse, %N the list
// name, %% a percent sign; \n, \t and \\ are escapes, and \ before anything
// else stands for that character. The template has passed checkFormat.
func userFormat(b *strings.Builder, format, name string, p netip.Prefix, lo, hi int) {
	for i := 0; i < len(format); i++ {
		c := format[i]
		if (c != '%' && c != '\\') || i+1 == len(format) {
			b.WriteByte(c) // checkFormat refuses a lone % or \ at the end
			continue
		}
		i++
		if c == '\\' {
			switch format[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(format[i])
			}
			continue
		}
		switch format[i] {
		case 'r', 'n':
			b.WriteString(ntop(p.Addr()))
		case 'l':
			fmt.Fprintf(b, "%d", p.Bits())
		case 'a':
			fmt.Fprintf(b, "%d", lo)
		case 'A':
			fmt.Fprintf(b, "%d", hi)
		case '%':
			b.WriteByte('%')
		case 'N':
			b.WriteString(name)
		case 'm':
			b.WriteString(ntop(mask(p, false)))
		case 'i':
			b.WriteString(ntop(mask(p, true)))
		}
	}
}

// mask returns p's netmask, or with inverse its host mask, as an address of
// p's family.
func mask(p netip.Prefix, inverse bool) netip.Addr {
	b := make([]byte, p.Addr().BitLen()/8)
	for i := range b {
		for j := 0; j < 8; j++ {
			in := i*8+j < p.Bits()
			if in != inverse {
				b[i] |= 0x80 >> j
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Sort orders entries by address, then prefix length, then lengths: the order
// bgpq4 writes a list without aggregation in.
func Sort(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i].Prefix, es[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		li, hi := es[i].Range().Lo(), es[i].Range().Hi()
		lj, hj := es[j].Range().Lo(), es[j].Range().Hi()
		if li != lj {
			return li < lj
		}
		return hi < hj
	})
}
