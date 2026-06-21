package object

import "testing"

func TestAutNumMpDefault(t *testing.T) {
	o := parse("aut-num: AS65001\n" +
		"default:    to AS64512\n" +
		"mp-default: afi ipv6.unicast to AS64513\n" +
		"source:     RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	a, ok := obj.(AutNum)
	if !ok {
		t.Fatalf("obj = %T, want AutNum", obj)
	}
	if len(a.Defaults) != 2 {
		t.Fatalf("Defaults = %d, want 2 (default + mp-default)", len(a.Defaults))
	}
	if !a.Defaults[0].Unscoped() {
		t.Errorf("Defaults[0] should be the unscoped legacy default")
	}
	if len(a.Defaults[1].AFIs) != 1 || a.Defaults[1].AFIs[0].String() != "ipv6.unicast" {
		t.Errorf("mp-default AFIs = %v, want [ipv6.unicast]", a.Defaults[1].AFIs)
	}
}

func TestRouteSetMpMembersSeparate(t *testing.T) {
	o := parse("route-set: RS-X\n" +
		"members:    192.0.2.0/24\n" +
		"mp-members: 2001:db8::/32\n" +
		"source:     TEST\n")
	obj, _ := Decode(o)
	rs, ok := obj.(RouteSet)
	if !ok {
		t.Fatalf("obj = %T, want RouteSet", obj)
	}
	if len(rs.Members) != 1 || len(rs.MpMembers) != 1 {
		t.Fatalf("Members=%d MpMembers=%d, want 1/1", len(rs.Members), len(rs.MpMembers))
	}
	if len(rs.SetMembers()) != 2 {
		t.Errorf("SetMembers() union = %d, want 2", len(rs.SetMembers()))
	}
}

// As-set objects can carry mp-members in RIPE/IRRd reality (the profile admits
// it). Both lists must populate, and SetMembers() must union them so the engine
// does not silently drop ASNs that live only in mp-members.
func TestAsSetMpMembersSeparate(t *testing.T) {
	o := parse("as-set:     AS-X\n" +
		"members:    AS1\n" +
		"mp-members: AS2\n" +
		"source:     TEST\n")
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	as, ok := obj.(AsSet)
	if !ok {
		t.Fatalf("obj = %T, want AsSet", obj)
	}
	if len(as.Members) != 1 || len(as.MpMembers) != 1 {
		t.Fatalf("Members=%d MpMembers=%d, want 1/1", len(as.Members), len(as.MpMembers))
	}
	union := as.SetMembers()
	if len(union) != 2 {
		t.Fatalf("SetMembers() union = %d, want 2", len(union))
	}
	if union[0].AS != 1 || union[1].AS != 2 {
		t.Errorf("union ASNs = [%v %v], want [AS1 AS2]", union[0].AS, union[1].AS)
	}
}
