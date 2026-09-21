package object

import (
	"net/netip"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// Inetnum is an inetnum object: an IPv4 address range with registration data
// (RIPE). Lo/Hi bound the range "lo - hi"; Country may repeat.
type Inetnum struct {
	Common
	Lo, Hi  netip.Addr
	Netname string
	Country []string
	Status  string
	raw     *ast.Object
}

func (i Inetnum) Class() string    { return "inetnum" }
func (i Inetnum) Raw() *ast.Object { return i.raw }

func decodeInetnum(d *decoder) Inetnum {
	lo, hi := d.addrRange("inetnum", "object/inetnum-range")
	return Inetnum{
		Common: d.common("inetnum"),
		Lo:     lo, Hi: hi,
		Netname: d.str("netname"),
		Country: d.all("country"),
		Status:  d.str("status"),
		raw:     d.o,
	}
}

// Inet6num is an inet6num object: an IPv6 prefix with registration data (RIPE).
type Inet6num struct {
	Common
	Prefix  netip.Prefix
	Netname string
	Country []string
	Status  string
	raw     *ast.Object
}

func (i Inet6num) Class() string    { return "inet6num" }
func (i Inet6num) Raw() *ast.Object { return i.raw }

func decodeInet6num(d *decoder) Inet6num {
	return Inet6num{
		Common:  d.common("inet6num"),
		Prefix:  d.prefix("inet6num", "object/inet6num-prefix"),
		Netname: d.str("netname"),
		Country: d.all("country"),
		Status:  d.str("status"),
		raw:     d.o,
	}
}

// AsBlock is an as-block object: a delegated range of AS numbers "ASlo - AShi".
type AsBlock struct {
	Common
	Lo, Hi types.ASN
	raw    *ast.Object
}

func (b AsBlock) Class() string    { return "as-block" }
func (b AsBlock) Raw() *ast.Object { return b.raw }

func decodeAsBlock(d *decoder) AsBlock {
	lo, hi := d.asnRange("as-block", "object/as-block-range")
	return AsBlock{Common: d.common("as-block"), Lo: lo, Hi: hi, raw: d.o}
}

// InetRtr is an inet-rtr object: an Internet router with its local AS, interface
// addresses, and peers (RFC 2622 §9, RFC 4012). Peers holds peer: and mp-peer:.
type InetRtr struct {
	Common
	Name      string
	Alias     []string
	LocalAS   types.ASN
	Ifaddr    []string
	Interface []string
	Peers     []string
	MemberOf  []types.SetName
	raw       *ast.Object
}

func (r InetRtr) Class() string    { return "inet-rtr" }
func (r InetRtr) Raw() *ast.Object { return r.raw }

func decodeInetRtr(d *decoder) InetRtr {
	return InetRtr{
		Common:    d.common("inet-rtr"),
		Name:      d.key("inet-rtr"),
		Alias:     d.all("alias"),
		LocalAS:   d.asn("local-as", "object/inet-rtr-local-as"),
		Ifaddr:    d.all("ifaddr"),
		Interface: d.all("interface"),
		Peers:     append(d.all("peer"), d.all("mp-peer")...),
		MemberOf:  d.setNames("member-of", "object/inet-rtr-member-of"),
		raw:       d.o,
	}
}

// Irt is an irt object: a Computer Security Incident Response Team (RIPE), with
// contact and auth data.
type Irt struct {
	Common
	Name    string
	Address []string
	Email   []string
	Auth    []string
	raw     *ast.Object
}

func (i Irt) Class() string    { return "irt" }
func (i Irt) Raw() *ast.Object { return i.raw }

func decodeIrt(d *decoder) Irt {
	return Irt{
		Common:  d.common("irt"),
		Name:    d.key("irt"),
		Address: d.all("address"),
		Email:   d.all("e-mail"),
		Auth:    d.all("auth"),
		raw:     d.o,
	}
}

// Domain is a domain object: a reverse-DNS or forward delegation with
// nameservers and contacts.
type Domain struct {
	Common
	Name    string
	Nserver []string
	ZoneC   []types.NICHandle
	raw     *ast.Object
}

func (d2 Domain) Class() string    { return "domain" }
func (d2 Domain) Raw() *ast.Object { return d2.raw }

func decodeDomain(d *decoder) Domain {
	return Domain{
		Common:  d.common("domain"),
		Name:    d.key("domain"),
		Nserver: d.all("nserver"),
		ZoneC:   d.nicHandles("zone-c", "object/domain-zone-c"),
		raw:     d.o,
	}
}

// Organisation is an organisation object (RIPE extension): the registrant entity
// referenced by other objects' org: attribute.
type Organisation struct {
	Common
	OrgID   string
	OrgName string
	OrgType string
	Address []string
	raw     *ast.Object
}

func (o Organisation) Class() string    { return "organisation" }
func (o Organisation) Raw() *ast.Object { return o.raw }

func decodeOrganisation(d *decoder) Organisation {
	return Organisation{
		Common:  d.common("organisation"),
		OrgID:   d.key("organisation"),
		OrgName: d.str("org-name"),
		OrgType: d.str("org-type"),
		Address: d.all("address"),
		raw:     d.o,
	}
}
