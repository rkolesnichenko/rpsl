package policy

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// Ifaddr is a parsed ifaddr: value of an inet-rtr object (RFC 2622 §9): one of
// the router's interface addresses.
//
//	ifaddr: 1.1.1.1 masklen 30 action mtu = 1500;
type Ifaddr struct {
	Addr    netip.Addr
	Masklen int      // -1 when the value carried no valid masklen
	Actions []Action // "action <action>; <action>"
	Raw     string   // the value as written, trimmed
}

// Interface is a parsed interface: value (RFC 4012 §4), the RPSLng form of
// ifaddr: with an optional address family and tunnel endpoint.
//
//	interface: 2001:db8::1 masklen 48
//	interface: afi ipv6.unicast 2001:db8::1 masklen 48 tunnel 192.0.2.1,GRE
type Interface struct {
	AFI     types.AddrFamily // the address family; the zero value when absent
	Addr    netip.Addr
	Masklen int // -1 when the value carried no valid masklen
	Actions []Action
	Tunnel  *Tunnel // nil when the interface is not a tunnel
	Raw     string  // the value as written, trimmed
}

// Tunnel is an interface:'s "tunnel <remote-endpoint>,<encapsulation>" clause.
type Tunnel struct {
	Remote netip.Addr
	Type   string // the encapsulation, as written ("GRE", "IPSEC", …)
}

// Peer is a parsed peer: or mp-peer: value of an inet-rtr object
// (RFC 2622 §9, RFC 4012 §4): one protocol peering of the router.
//
//	peer: BGP4 192.0.2.1 asno(AS2), flap_damp()
type Peer struct {
	Protocol string       // the routing protocol, as written ("BGP4", "OSPF", …)
	Peer     RouterExpr   // the peer: an address, an inet-rtr name or an rtr-set
	Options  []PeerOption // the comma-separated peering options
	Raw      string       // the value as written, trimmed
}

// PeerOption is one "name(args)" peering option of a peer: value. Name is
// lower-cased; Args are the comma-separated arguments, empty for "flap_damp()".
type PeerOption struct {
	Name string
	Args []string
	Raw  string
}

// The extra clause keywords each inet-rtr sub-grammar adds, so that a clause
// does not swallow the one after it.
var (
	ifaddrStops = []string{"masklen"}
	ifStops     = []string{"masklen", "tunnel"}
)

// ParseIfaddr parses an ifaddr: value. It returns a best-effort Ifaddr plus
// diagnostics; it never panics.
func ParseIfaddr(s string) (Ifaddr, []ast.Diagnostic) {
	v, p := parseIfaddrValue(s)
	return v, p.diags
}

func parseIfaddrValue(s string) (Ifaddr, *parser) {
	p := newParser(s)
	p.stops = ifaddrStops
	v := Ifaddr{Masklen: -1, Raw: strings.TrimSpace(s)}
	if p.empty() {
		return v, p
	}
	v.Addr = p.routerAddr("policy/ifaddr")
	v.Masklen = p.masklen("policy/ifaddr", v.Addr)
	if p.cur().kw("action") {
		p.advance()
		v.Actions = p.parseActions()
	}
	p.finish()
	return v, p
}

// ParseInterface parses an RFC 4012 interface: value. It returns a best-effort
// Interface plus diagnostics; it never panics.
func ParseInterface(s string) (Interface, []ast.Diagnostic) {
	v, p := parseInterfaceValue(s)
	return v, p.diags
}

func parseInterfaceValue(s string) (Interface, *parser) {
	p := newParser(s)
	p.stops = ifStops
	p.mp = true // an interface: may carry an afi clause
	v := Interface{Masklen: -1, Raw: strings.TrimSpace(s)}
	if p.empty() {
		return v, p
	}
	v.AFI = p.interfaceAFI()
	v.Addr = p.routerAddr("policy/interface")
	v.Masklen = p.masklen("policy/interface", v.Addr)
	if p.cur().kw("action") {
		p.advance()
		v.Actions = p.parseActions()
	}
	if p.cur().kw("tunnel") {
		p.advance()
		v.Tunnel = p.tunnel()
	}
	p.finish()
	return v, p
}

// interfaceAFI reads the one optional address family RFC 4012 §4 allows ahead
// of the address, written either with the "afi" keyword or bare. A word that is
// not a family is left for the address parse, so the family really is optional.
func (p *parser) interfaceAFI() types.AddrFamily {
	kw := p.cur().kw("afi")
	if kw {
		p.advance()
	}
	t := p.cur()
	if t.kind != tWord {
		if kw {
			p.errf(t, "policy/interface", "expected an address family after 'afi'")
		}
		return types.AddrFamily{}
	}
	af, err := types.ParseAddrFamily(t.text)
	if err != nil {
		if kw {
			p.errf(t, "policy/interface", "invalid address family "+quote(t.text))
		}
		return types.AddrFamily{}
	}
	p.advance()
	return af
}

// routerAddr reads one interface address.
func (p *parser) routerAddr(rule string) netip.Addr {
	t := p.cur()
	if t.kind != tWord || p.clauseKw(t) {
		p.errf(t, rule, "expected an interface address")
		return netip.Addr{}
	}
	p.advance()
	a, err := netip.ParseAddr(t.text)
	if err != nil {
		p.errf(t, rule, "invalid interface address "+quote(t.text))
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// masklen reads the "masklen <n>" clause and checks n against addr's family.
// It returns -1 when the clause is missing or unusable.
func (p *parser) masklen(rule string, addr netip.Addr) int {
	t := p.cur()
	if !t.kw("masklen") {
		p.errf(t, rule, "expected masklen")
		return -1
	}
	p.advance()
	nt := p.cur()
	if nt.kind != tWord {
		p.errf(nt, rule, "expected a prefix length after masklen")
		return -1
	}
	p.advance()
	n, err := strconv.Atoi(nt.text)
	if err != nil || n < 0 {
		p.errf(nt, rule, "invalid prefix length "+quote(nt.text))
		return -1
	}
	if addr.IsValid() && n > addr.BitLen() {
		p.errf(nt, rule, "prefix length "+nt.text+" is longer than an "+addrFamilyName(addr)+" address")
		return -1
	}
	if !addr.IsValid() && n > 128 {
		p.errf(nt, rule, "prefix length "+nt.text+" is longer than any address")
		return -1
	}
	return n
}

// tunnel reads "<remote-endpoint>,<encapsulation>".
func (p *parser) tunnel() *Tunnel {
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/interface", "expected a tunnel endpoint address")
		return nil
	}
	p.advance()
	remote, err := netip.ParseAddr(t.text)
	if err != nil {
		p.errf(t, "policy/interface", "invalid tunnel endpoint "+quote(t.text))
		return nil
	}
	if p.cur().kind != tComma {
		p.errf(p.cur(), "policy/interface", "expected ',' after the tunnel endpoint")
		return &Tunnel{Remote: remote.Unmap().WithZone("")}
	}
	p.advance()
	e := p.cur()
	if e.kind != tWord {
		p.errf(e, "policy/interface", "expected a tunnel encapsulation after ','")
		return &Tunnel{Remote: remote.Unmap().WithZone("")}
	}
	p.advance()
	return &Tunnel{Remote: remote.Unmap().WithZone(""), Type: e.text}
}

// addrFamilyName names addr's address family for a diagnostic.
func addrFamilyName(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// ParsePeer parses a peer: or mp-peer: value. It returns a best-effort Peer
// plus diagnostics; it never panics.
func ParsePeer(s string) (Peer, []ast.Diagnostic) {
	v, p := parsePeerValue(s)
	return v, p.diags
}

func parsePeerValue(s string) (Peer, *parser) {
	p := newParser(s)
	v := Peer{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return v, p
	}
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/peer", "expected a protocol name")
		p.sync()
		p.finish()
		return v, p
	}
	v.Protocol = t.text
	p.advance()
	v.Peer = p.parseRouterPrim()
	v.Options = p.parsePeerOptions()
	p.finish()
	return v, p
}

// parsePeerOptions reads the comma-separated "name(args)" peering options that
// close a peer: value. An option with no parentheses is kept with no arguments.
// An empty item is warned about rather than passed over, as in a prefix list.
func (p *parser) parsePeerOptions() []PeerOption {
	var opts []PeerOption
	pending := false // a ',' was seen and its option has not arrived
	for !p.atEOF() && p.cur().kind != tSemi {
		t := p.cur()
		if t.kind == tComma {
			if pending || len(opts) == 0 {
				p.warnf(t, "policy/peer", "empty item in the peering option list")
			}
			pending = true
			p.advance()
			continue
		}
		if t.kind != tWord {
			p.errf(t, "policy/peer", "expected a peering option")
			return opts
		}
		p.advance()
		opt := PeerOption{Name: normAttr(t.text), Raw: t.text}
		if p.cur().kind == tLParen {
			args, end, ok := p.parenArgs()
			if !ok {
				p.errf(t, "policy/peer", "unterminated '(' in peering option "+quote(t.text))
				return opts
			}
			opt.Args = args
			opt.Raw = strings.TrimSpace(p.src[t.start:end])
		}
		opts = append(opts, opt)
		pending = false
	}
	if pending {
		p.warnf(p.cur(), "policy/peer", "empty item in the peering option list")
	}
	return opts
}

// parenArgs consumes a parenthesized, comma-separated argument list at the
// cursor and returns the arguments plus the source offset just past the ')'.
func (p *parser) parenArgs() (args []string, end int, ok bool) {
	depth, start := 0, p.cur().end
	for !p.atEOF() {
		switch p.cur().kind {
		case tLParen:
			depth++
		case tRParen:
			depth--
			if depth == 0 {
				inner, after := p.cur().start, p.cur().end
				p.advance()
				return splitTrim(p.src[start:inner]), after, true
			}
		}
		p.advance()
	}
	return nil, 0, false
}
