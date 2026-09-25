package object

import (
	"fmt"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// Inetnum is an inetnum object: an IPv4 address range with registration data
// (RIPE). Lo/Hi bound the range "lo - hi"; Country may repeat.
type Inetnum struct {
	Common
	Registry
	Lo, Hi    netip.Addr
	Netname   string
	Country   []string
	Status    string
	Geofeed   string
	Geoloc    string
	Prefixlen string
	Language  []string
	// AssignmentSize is the prefix length of the assignments an
	// AGGREGATED-BY-LIR range is made of (RIPE), as written.
	AssignmentSize string
	RevSrv         []string // rev-srv: (IRRd): reverse-DNS servers, as written
	raw            *ast.Object
}

// Class returns "inetnum".
func (i Inetnum) Class() string { return "inetnum" }

// Raw returns the object's lossless source, or nil for one built without it.
func (i Inetnum) Raw() *ast.Object { return i.raw }

func decodeInetnum(d *decoder) Inetnum {
	lo, hi := d.addrRange("inetnum", "object/inetnum-range")
	return Inetnum{
		Common:         d.common("inetnum"),
		Registry:       d.registry("inetnum"),
		Lo:             lo,
		Hi:             hi,
		Netname:        d.str("netname"),
		Country:        d.all("country"),
		Status:         d.str("status"),
		Geofeed:        d.str("geofeed"),
		Geoloc:         d.str("geoloc"),
		Prefixlen:      d.str("prefixlen"),
		Language:       d.all("language"),
		AssignmentSize: d.str("assignment-size"),
		RevSrv:         d.all("rev-srv"),
		raw:            d.o,
	}
}

// Inet6num is an inet6num object: an IPv6 prefix with registration data (RIPE).
// An IPv4 prefix is an Error and leaves Prefix zero; one with host bits set is
// a Warning and kept as written, as Route's is.
type Inet6num struct {
	Common
	Registry
	Prefix    netip.Prefix
	Netname   string
	Country   []string
	Status    string
	Geofeed   string
	Geoloc    string
	Prefixlen string
	Language  []string
	// AssignmentSize is the prefix length of the assignments an
	// AGGREGATED-BY-LIR range is made of (RIPE), as written.
	AssignmentSize string
	RevSrv         []string // rev-srv: (IRRd): reverse-DNS servers, as written
	raw            *ast.Object
}

// Class returns "inet6num".
func (i Inet6num) Class() string { return "inet6num" }

// Raw returns the object's lossless source, or nil for one built without it.
func (i Inet6num) Raw() *ast.Object { return i.raw }

func decodeInet6num(d *decoder) Inet6num {
	return Inet6num{
		Common:         d.common("inet6num"),
		Registry:       d.registry("inet6num"),
		Prefix:         d.inet6numPrefix(),
		Netname:        d.str("netname"),
		Country:        d.all("country"),
		Status:         d.str("status"),
		Geofeed:        d.str("geofeed"),
		Geoloc:         d.str("geoloc"),
		Prefixlen:      d.str("prefixlen"),
		Language:       d.all("language"),
		AssignmentSize: d.str("assignment-size"),
		RevSrv:         d.all("rev-srv"),
		raw:            d.o,
	}
}

// inet6numPrefix decodes an inet6num key, which must be an IPv6 prefix.
func (d *decoder) inet6numPrefix() netip.Prefix {
	const rule = "object/inet6num-prefix"
	p := d.prefix("inet6num", rule)
	a, _ := d.o.GetFirst("inet6num")
	switch {
	case !p.IsValid():
	case !p.Addr().Is6():
		d.errf(a, rule, "inet6num prefix "+p.String()+" is not IPv6")
		return netip.Prefix{}
	case p != p.Masked():
		d.warnf(a, "object/inet6num-host-bits",
			fmt.Sprintf("prefix %s has host bits set; the network is %s", p, p.Masked()))
	}
	return p
}

// AsBlock is an as-block object: a delegated range of AS numbers "ASlo - AShi".
type AsBlock struct {
	Common
	Registry
	Lo, Hi types.ASN
	raw    *ast.Object
}

// Class returns "as-block".
func (b AsBlock) Class() string { return "as-block" }

// Raw returns the object's lossless source, or nil for one built without it.
func (b AsBlock) Raw() *ast.Object { return b.raw }

func decodeAsBlock(d *decoder) AsBlock {
	lo, hi := d.asnRange("as-block", "object/as-block-range")
	return AsBlock{Common: d.common("as-block"), Registry: d.registry("as-block"), Lo: lo, Hi: hi, raw: d.o}
}

// InetRtr is an inet-rtr object: an Internet router with its local AS, interface
// addresses, and peers (RFC 2622 §9, RFC 4012). Peers holds peer: and mp-peer:.
type InetRtr struct {
	Common
	Registry
	Name      string
	Alias     []string
	LocalAS   types.ASN
	Ifaddr    []policy.Ifaddr
	Interface []policy.Interface
	Peers     []policy.Peer
	MpPeers   []policy.Peer // RFC 4012 mp-peer: values
	MemberOf  []types.SetName
	RsIn      string // rs-in: (IRRd), as written
	RsOut     string // rs-out: (IRRd), as written
	raw       *ast.Object
}

// Class returns "inet-rtr".
func (r InetRtr) Class() string { return "inet-rtr" }

// Raw returns the object's lossless source, or nil for one built without it.
func (r InetRtr) Raw() *ast.Object { return r.raw }

func decodeInetRtr(d *decoder) InetRtr {
	return InetRtr{
		Common:    d.common("inet-rtr"),
		Registry:  d.registry("inet-rtr"),
		Name:      d.key("inet-rtr"),
		Alias:     d.all("alias"),
		LocalAS:   d.asn("local-as", "object/inet-rtr-local-as"),
		Ifaddr:    d.ifaddrs(),
		Interface: d.interfaces(),
		Peers:     d.peers("peer"),
		MpPeers:   d.peers("mp-peer"),
		MemberOf:  d.memberOf("inet-rtr", types.ClassRtrSet),
		RsIn:      d.str("rs-in"),
		RsOut:     d.str("rs-out"),
		raw:       d.o,
	}
}

// Irt is an irt object: a Computer Security Incident Response Team (RIPE), with
// contact data. Auth holds its authentication schemes, decoded as a mntner's are;
// nothing here verifies one.
type Irt struct {
	Common
	Registry
	Name       string
	Address    []string
	Email      []string
	Auth       []Auth
	Phone      []string
	FaxNo      []string
	Signature  []string
	Encryption []string
	Contact    []string
	IrtNfy     []string
	// AbuseMailbox is IRRd's abuse-mailbox:; RIPE keeps it on role objects.
	AbuseMailbox string
	raw          *ast.Object
}

// Class returns "irt".
func (i Irt) Class() string { return "irt" }

// Raw returns the object's lossless source, or nil for one built without it.
func (i Irt) Raw() *ast.Object { return i.raw }

func decodeIrt(d *decoder) Irt {
	return Irt{
		Common:       d.common("irt"),
		Registry:     d.registry("irt"),
		Name:         d.key("irt"),
		Address:      d.all("address"),
		Email:        d.all("e-mail"),
		Auth:         d.auth("irt"),
		Phone:        d.all("phone"),
		FaxNo:        d.all("fax-no"),
		Signature:    d.list("signature"),
		Encryption:   d.list("encryption"),
		Contact:      d.all("contact"),
		IrtNfy:       d.all("irt-nfy"),
		AbuseMailbox: d.str("abuse-mailbox"),
		raw:          d.o,
	}
}

// Domain is a domain object: a reverse-DNS or forward delegation with
// nameservers and contacts.
type Domain struct {
	Common
	Registry
	Name    string
	Nserver []string
	ZoneC   []types.NICHandle
	DsRdata []string // ds-rdata: DS records, raw (RFC 4034 presentation form)
	SubDom  []string // sub-dom: (IRRd, from RIPE-181), as written
	DomNet  []string // dom-net: (IRRd, from RIPE-181), as written
	Refer   string   // refer: (IRRd, from RIPE-181), as written
	raw     *ast.Object
}

// Class returns "domain".
func (d2 Domain) Class() string { return "domain" }

// Raw returns the object's lossless source, or nil for one built without it.
func (d2 Domain) Raw() *ast.Object { return d2.raw }

func decodeDomain(d *decoder) Domain {
	return Domain{
		Common:   d.common("domain"),
		Registry: d.registry("domain"),
		Name:     d.key("domain"),
		Nserver:  d.all("nserver"),
		ZoneC:    d.nicHandles("zone-c", "object/domain-zone-c"),
		DsRdata:  d.all("ds-rdata"),
		SubDom:   d.all("sub-dom"),
		DomNet:   d.all("dom-net"),
		Refer:    d.str("refer"),
		raw:      d.o,
	}
}

// Organisation is an organisation object (RIPE extension): the registrant entity
// referenced by other objects' org: attribute.
type Organisation struct {
	Common
	Registry
	OrgID    string
	OrgName  string
	OrgType  string
	Address  []string
	Country  string
	Phone    []string
	FaxNo    []string
	Email    []string
	Contact  []string
	Geoloc   string
	Language []string
	RegNr    string
	RefNfy   []string
	raw      *ast.Object
}

// Class returns "organisation".
func (o Organisation) Class() string { return "organisation" }

// Raw returns the object's lossless source, or nil for one built without it.
func (o Organisation) Raw() *ast.Object { return o.raw }

func decodeOrganisation(d *decoder) Organisation {
	return Organisation{
		Common:   d.common("organisation"),
		Registry: d.registry("organisation"),
		OrgID:    d.key("organisation"),
		OrgName:  d.str("org-name"),
		OrgType:  d.str("org-type"),
		Address:  d.all("address"),
		Country:  d.str("country"),
		Phone:    d.all("phone"),
		FaxNo:    d.all("fax-no"),
		Email:    d.all("e-mail"),
		Contact:  d.all("contact"),
		Geoloc:   d.str("geoloc"),
		Language: d.all("language"),
		RegNr:    d.str("reg-nr"),
		RefNfy:   d.all("ref-nfy"),
		raw:      d.o,
	}
}
