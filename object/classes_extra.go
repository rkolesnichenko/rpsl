package object

import (
	"net/netip"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// Inetnum is an inetnum object: an IPv4 address range with registration data
// (RFC 2622 / RIPE). Lo/Hi bound the range "lo - hi".
type Inetnum struct {
	Lo, Hi  netip.Addr
	Netname string
	Country string
	Status  string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	MntBy   []string
	Source  string
	raw     *ast.Object
}

func (i Inetnum) Class() string    { return "inetnum" }
func (i Inetnum) Raw() *ast.Object { return i.raw }

func decodeInetnum(d *decoder) Inetnum {
	lo, hi := d.addrRange("inetnum", "object/inetnum-range")
	return Inetnum{
		Lo: lo, Hi: hi,
		Netname: d.str("netname"),
		Country: d.str("country"),
		Status:  d.str("status"),
		AdminC:  d.nicHandles("admin-c", "object/inetnum-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/inetnum-tech-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// Inet6num is an inet6num object: an IPv6 prefix with registration data (RFC 4012).
type Inet6num struct {
	Prefix  netip.Prefix
	Netname string
	Country string
	Status  string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	MntBy   []string
	Source  string
	raw     *ast.Object
}

func (i Inet6num) Class() string    { return "inet6num" }
func (i Inet6num) Raw() *ast.Object { return i.raw }

func decodeInet6num(d *decoder) Inet6num {
	return Inet6num{
		Prefix:  d.prefix("inet6num", "object/inet6num-prefix"),
		Netname: d.str("netname"),
		Country: d.str("country"),
		Status:  d.str("status"),
		AdminC:  d.nicHandles("admin-c", "object/inet6num-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/inet6num-tech-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// AsBlock is an as-block object: a delegated range of AS numbers "ASlo - AShi".
type AsBlock struct {
	Lo, Hi types.ASN
	MntBy  []string
	Source string
	raw    *ast.Object
}

func (b AsBlock) Class() string    { return "as-block" }
func (b AsBlock) Raw() *ast.Object { return b.raw }

func decodeAsBlock(d *decoder) AsBlock {
	lo, hi := d.asnRange("as-block", "object/as-block-range")
	return AsBlock{
		Lo: lo, Hi: hi,
		MntBy:  d.all("mnt-by"),
		Source: d.str("source"),
		raw:    d.o,
	}
}

// InetRtr is an inet-rtr object: an Internet router with its local AS, interface
// addresses, and peers (RFC 2622 §9).
type InetRtr struct {
	Name     string
	LocalAS  types.ASN
	Ifaddr   []string
	Peers    []string
	MemberOf []types.SetName
	MntBy    []string
	Source   string
	raw      *ast.Object
}

func (r InetRtr) Class() string    { return "inet-rtr" }
func (r InetRtr) Raw() *ast.Object { return r.raw }

func decodeInetRtr(d *decoder) InetRtr {
	return InetRtr{
		Name:     d.str("inet-rtr"),
		LocalAS:  d.asn("local-as", "object/inet-rtr-local-as"),
		Ifaddr:   d.all("ifaddr"),
		Peers:    append(d.all("peer"), d.all("mp-peer")...),
		MemberOf: d.setNames("member-of", "object/inet-rtr-member-of"),
		MntBy:    d.all("mnt-by"),
		Source:   d.str("source"),
		raw:      d.o,
	}
}

// Irt is an irt object: a Computer Security Incident Response Team (RFC 4012 era
// RIPE extension), with contact and auth data.
type Irt struct {
	Name    string
	Address []string
	Email   []string
	Auth    []string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	MntBy   []string
	Source  string
	raw     *ast.Object
}

func (i Irt) Class() string    { return "irt" }
func (i Irt) Raw() *ast.Object { return i.raw }

func decodeIrt(d *decoder) Irt {
	return Irt{
		Name:    d.str("irt"),
		Address: d.all("address"),
		Email:   d.all("e-mail"),
		Auth:    d.all("auth"),
		AdminC:  d.nicHandles("admin-c", "object/irt-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/irt-tech-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// Domain is a domain object: a reverse-DNS or forward delegation with nameservers
// and contacts (RFC 2622).
type Domain struct {
	Name    string
	Nserver []string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	ZoneC   []types.NICHandle
	MntBy   []string
	Source  string
	raw     *ast.Object
}

func (d2 Domain) Class() string    { return "domain" }
func (d2 Domain) Raw() *ast.Object { return d2.raw }

func decodeDomain(d *decoder) Domain {
	return Domain{
		Name:    d.str("domain"),
		Nserver: d.all("nserver"),
		AdminC:  d.nicHandles("admin-c", "object/domain-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/domain-tech-c"),
		ZoneC:   d.nicHandles("zone-c", "object/domain-zone-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// Organisation is an organisation object (RIPE extension): the registrant entity
// referenced by other objects' org: attribute.
type Organisation struct {
	OrgID   string
	OrgName string
	OrgType string
	Address []string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	MntBy   []string
	Source  string
	raw     *ast.Object
}

func (o Organisation) Class() string    { return "organisation" }
func (o Organisation) Raw() *ast.Object { return o.raw }

func decodeOrganisation(d *decoder) Organisation {
	return Organisation{
		OrgID:   d.str("organisation"),
		OrgName: d.str("org-name"),
		OrgType: d.str("org-type"),
		Address: d.all("address"),
		AdminC:  d.nicHandles("admin-c", "object/organisation-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/organisation-tech-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}
