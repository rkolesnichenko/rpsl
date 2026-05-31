package object

import "testing"

func TestDecodeInetnum(t *testing.T) {
	o := parse(`inetnum: 192.0.2.0 - 192.0.2.255
netname: EXAMPLE-NET
country: NL
admin-c: EX1-RIPE
status:  ASSIGNED PA
mnt-by:  MAINT-EX
source:  RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	in, ok := obj.(Inetnum)
	if !ok {
		t.Fatalf("Decode = %T, want Inetnum", obj)
	}
	if in.Lo.String() != "192.0.2.0" || in.Hi.String() != "192.0.2.255" {
		t.Errorf("range = %s - %s", in.Lo, in.Hi)
	}
	if in.Netname != "EXAMPLE-NET" || in.Status != "ASSIGNED PA" {
		t.Errorf("netname/status = %q / %q", in.Netname, in.Status)
	}
	if o.String() != obj.Raw().String() {
		t.Error("round-trip mismatch")
	}
}

func TestDecodeInet6num(t *testing.T) {
	o := parse(`inet6num: 2001:db8::/32
netname:  EXAMPLE6
status:   ALLOCATED-BY-RIR
source:   RIPE
`)
	obj, _ := Decode(o)
	in, ok := obj.(Inet6num)
	if !ok {
		t.Fatalf("Decode = %T, want Inet6num", obj)
	}
	if in.Prefix.String() != "2001:db8::/32" {
		t.Errorf("prefix = %s", in.Prefix)
	}
}

func TestDecodeAsBlock(t *testing.T) {
	o := parse(`as-block: AS1 - AS10
mnt-by:   MAINT-EX
source:   RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	b, ok := obj.(AsBlock)
	if !ok {
		t.Fatalf("Decode = %T, want AsBlock", obj)
	}
	if uint32(b.Lo) != 1 || uint32(b.Hi) != 10 {
		t.Errorf("block = AS%d - AS%d", b.Lo, b.Hi)
	}
}

func TestDecodeInetRtr(t *testing.T) {
	o := parse(`inet-rtr:  rtr.example.net
local-as:  AS65000
ifaddr:    192.0.2.1 masklen 30
peer:      BGP4 192.0.2.2 asno(AS65001)
member-of: rtrs-EXAMPLE
mnt-by:    MAINT-EX
source:    RIPE
`)
	obj, _ := Decode(o)
	r, ok := obj.(InetRtr)
	if !ok {
		t.Fatalf("Decode = %T, want InetRtr", obj)
	}
	if r.Name != "rtr.example.net" || uint32(r.LocalAS) != 65000 {
		t.Errorf("name/local-as = %q / AS%d", r.Name, r.LocalAS)
	}
	if len(r.Ifaddr) != 1 || len(r.Peers) != 1 || len(r.MemberOf) != 1 {
		t.Errorf("ifaddr=%v peers=%v memberOf=%v", r.Ifaddr, r.Peers, r.MemberOf)
	}
}

func TestDecodeIrtDomainOrg(t *testing.T) {
	irt, _ := Decode(parse("irt: irt-EXAMPLE\ne-mail: abuse@example.net\nauth: PGPKEY-1\nsource: RIPE\n"))
	if v, ok := irt.(Irt); !ok || v.Name != "irt-EXAMPLE" || len(v.Email) != 1 {
		t.Errorf("irt = %+v", irt)
	}
	dom, _ := Decode(parse("domain: 2.0.192.in-addr.arpa\nnserver: ns1.example.net\nzone-c: EX1-RIPE\nsource: RIPE\n"))
	if v, ok := dom.(Domain); !ok || v.Name != "2.0.192.in-addr.arpa" || len(v.Nserver) != 1 || len(v.ZoneC) != 1 {
		t.Errorf("domain = %+v", dom)
	}
	org, _ := Decode(parse("organisation: ORG-EX1-RIPE\norg-name: Example Org\norg-type: LIR\nsource: RIPE\n"))
	if v, ok := org.(Organisation); !ok || v.OrgID != "ORG-EX1-RIPE" || v.OrgType != "LIR" {
		t.Errorf("organisation = %+v", org)
	}
}
