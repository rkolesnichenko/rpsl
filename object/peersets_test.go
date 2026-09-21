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
	if ps.Name.Canonical() != "PRNG-EXAMPLE" {
		t.Errorf("Name = %q", ps.Name.Canonical())
	}
	if len(ps.Peerings) != 2 {
		t.Fatalf("Peerings = %+v, want 2", ps.Peerings)
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
	if fs.Name.Canonical() != "FLTR-EXAMPLE" {
		t.Errorf("Name = %q", fs.Name.Canonical())
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
	if rs.Name.Canonical() != "RTRS-EXAMPLE" {
		t.Errorf("Name = %q", rs.Name.Canonical())
	}
	// members: is a comma-separated list (RFC 2622 §2): two routers, not one.
	if len(rs.Members) != 2 || rs.Members[0] != "rtr1.example.net" || rs.Members[1] != "rtr2.example.net" ||
		len(rs.MpMembers) != 1 || rs.MpMembers[0] != "rtrs-OTHER" {
		t.Errorf("Members=%q MpMembers=%q", rs.Members, rs.MpMembers)
	}
	if len(rs.MbrsByRef) != 1 || rs.MbrsByRef[0] != "MAINT-EX" {
		t.Errorf("MbrsByRef = %v", rs.MbrsByRef)
	}
}
