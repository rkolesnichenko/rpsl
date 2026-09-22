package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
)

func TestDecodePeeringSet(t *testing.T) {
	o := parse(`peering-set: prng-EXAMPLE
peering:     AS1 at 192.0.2.1
mp-peering:  AS2
mnt-by:      MAINT-EX
source:      RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	ps, ok := obj.(PeeringSet)
	if !ok {
		t.Fatalf("Decode = %T, want PeeringSet", obj)
	}
	if ps.Name.String() != "PRNG-EXAMPLE" {
		t.Errorf("Name = %q", ps.Name.String())
	}
	if len(ps.Peerings) != 1 || len(ps.MpPeerings) != 1 {
		t.Fatalf("Peerings = %+v, MpPeerings = %+v; want one each", ps.Peerings, ps.MpPeerings)
	}
	if _, ok := ps.Peerings[0].(policy.PeeringAS); !ok {
		t.Errorf("peering[0] = %T, want PeeringAS", ps.Peerings[0])
	}
	if o.String() != obj.Raw().String() {
		t.Error("round-trip mismatch")
	}
}

func TestDecodeFilterSet(t *testing.T) {
	o := parse(`filter-set: fltr-EXAMPLE
filter:     {192.0.2.0/24^+} AND NOT AS65000
mnt-by:     MAINT-EX
source:     RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	fs, ok := obj.(FilterSet)
	if !ok {
		t.Fatalf("Decode = %T, want FilterSet", obj)
	}
	if fs.Name.String() != "FLTR-EXAMPLE" {
		t.Errorf("Name = %q", fs.Name.String())
	}
	if _, ok := fs.Filter.(policy.FilterAnd); !ok {
		t.Errorf("Filter = %T, want FilterAnd", fs.Filter)
	}
}

func TestDecodeRtrSet(t *testing.T) {
	o := parse(`rtr-set:     rtrs-EXAMPLE
members:     rtr1.example.net, rtr2.example.net
mp-members:  rtrs-OTHER
mbrs-by-ref: MAINT-EX
mnt-by:      MAINT-EX
source:      RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	rs, ok := obj.(RtrSet)
	if !ok {
		t.Fatalf("Decode = %T, want RtrSet", obj)
	}
	if rs.Name.String() != "RTRS-EXAMPLE" {
		t.Errorf("Name = %q", rs.Name.String())
	}
	// members: is a comma-separated list (RFC 2622 §2): two routers, not one.
	if len(rs.Members) != 2 || len(rs.MpMembers) != 1 {
		t.Fatalf("Members=%q MpMembers=%q", rs.Members, rs.MpMembers)
	}
	for i, want := range []string{"rtr1.example.net", "rtr2.example.net"} {
		m := rs.Members[i]
		if m.Kind != RtrMemberRouter || m.Router.Name() != want || m.Raw != want {
			t.Errorf("Members[%d] = %+v, want the router %q", i, m, want)
		}
	}
	// A nested rtr-set is recognised as a set, not as the DNS name it resembles.
	if m := rs.MpMembers[0]; m.Kind != RtrMemberSet || m.Set.String() != "RTRS-OTHER" || m.Raw != "rtrs-OTHER" {
		t.Errorf("MpMembers[0] = %+v, want the rtr-set RTRS-OTHER", m)
	}
	if len(rs.MbrsByRef) != 1 || rs.MbrsByRef[0] != "MAINT-EX" {
		t.Errorf("MbrsByRef = %v", rs.MbrsByRef)
	}
}
