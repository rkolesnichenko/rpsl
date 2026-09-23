package object

import "testing"

// Handles in the shapes other registries issue decode without a diagnostic:
// ARIN's handles that start with a digit, and handles with an underscore (RFC
// 2622 object-name syntax, used in RADB). A person's name where a handle
// belongs is not a handle and stays an Error.
func TestRegistryNICHandles(t *testing.T) {
	obj, diags := Decode(parse("route:   65.38.96.0/22\norigin:  AS1\nadmin-c: 1NO-ARIN\ntech-c:  VAGNER_BRASILEIRO\nsource:  ARIN\n"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v, want none", diags)
	}
	r := obj.(Route)
	if len(r.AdminC) != 1 || r.AdminC[0] != "1NO-ARIN" || len(r.TechC) != 1 || r.TechC[0] != "VAGNER_BRASILEIRO" {
		t.Errorf("admin-c %q, tech-c %q", r.AdminC, r.TechC)
	}
	p, diags := Decode(parse("person:  Vagner Brasileiro\nnic-hdl: VAGNER_BRASILEIRO\nsource:  RADB\n"))
	if len(diags) != 0 || p.(Person).NicHdl != "VAGNER_BRASILEIRO" {
		t.Errorf("person nic-hdl %q, diagnostics %+v", p.(Person).NicHdl, diags)
	}
	obj, diags = Decode(parse("route:   192.0.2.0/24\norigin:  AS1\nadmin-c: Eric Cluett\nsource:  RADB\n"))
	if len(diags) != 1 || diags[0].Rule != "object/route-admin-c" || diags[0].Severity.String() != "error" || len(obj.(Route).AdminC) != 0 {
		t.Errorf("admin-c with a name: diagnostics %+v, AdminC %q; want one Error and the value dropped", diags, obj.(Route).AdminC)
	}
}
