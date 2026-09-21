package policy

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

var (
	v4u = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	v6u = types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
)

func TestParseMpDefault(t *testing.T) {
	d, diags := ParseDefault("afi ipv6.unicast to AS1")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if len(d.AFIs) != 1 || d.AFIs[0].String() != "ipv6.unicast" {
		t.Fatalf("AFIs = %v, want [ipv6.unicast]", d.AFIs)
	}
	if _, ok := d.Peering.(PeeringAS); !ok {
		t.Errorf("Peering = %T, want PeeringAS", d.Peering)
	}
}

func TestParseDefaultUnscoped(t *testing.T) {
	d, diags := ParseDefault("to AS1")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	if !d.Unscoped() {
		t.Errorf("plain default should be unscoped, AFIs = %v", d.AFIs)
	}
}

func TestParseExceptAFI(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept ANY except afi ipv6.unicast {from AS2 accept AS2}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	ex, ok := imp.Expr.(Except)
	if !ok {
		t.Fatalf("Expr = %T, want Except", imp.Expr)
	}
	if len(ex.AFIs) != 1 || ex.AFIs[0].String() != "ipv6.unicast" {
		t.Errorf("Except.AFIs = %v, want [ipv6.unicast]", ex.AFIs)
	}
}

func TestParseRefineAFI(t *testing.T) {
	imp, diags := ParseImport("from AS1 accept ANY refine afi ipv4.unicast {from AS2 accept AS2}")
	if len(diags) != 0 {
		t.Fatalf("diags = %+v", diags)
	}
	rf, ok := imp.Expr.(Refine)
	if !ok {
		t.Fatalf("Expr = %T, want Refine", imp.Expr)
	}
	if len(rf.AFIs) != 1 || rf.AFIs[0].String() != "ipv4.unicast" {
		t.Errorf("Refine.AFIs = %v, want [ipv4.unicast]", rf.AFIs)
	}
}

func TestImportAppliesTo(t *testing.T) {
	scoped, _ := ParseImport("afi ipv6.unicast from AS1 accept ANY")
	if scoped.Unscoped() {
		t.Errorf("scoped import reported unscoped")
	}
	if !scoped.AppliesTo(v6u) {
		t.Errorf("ipv6 import should apply to ipv6.unicast")
	}
	if scoped.AppliesTo(v4u) {
		t.Errorf("ipv6 import should not apply to ipv4.unicast")
	}

	legacy, _ := ParseImport("from AS1 accept ANY")
	if !legacy.Unscoped() {
		t.Errorf("legacy import should be unscoped")
	}
	if !legacy.AppliesTo(v4u) {
		t.Errorf("legacy import should apply to ipv4.unicast (RFC 4012 §3)")
	}
	if legacy.AppliesTo(v6u) {
		t.Errorf("legacy import should not apply to ipv6.unicast")
	}
}

func TestExportAppliesTo(t *testing.T) {
	scoped, _ := ParseExport("afi ipv6.unicast to AS1 announce ANY")
	if !scoped.AppliesTo(v6u) || scoped.AppliesTo(v4u) {
		t.Errorf("ipv6 export AppliesTo mismatch")
	}
	legacy, _ := ParseExport("to AS1 announce ANY")
	if !legacy.AppliesTo(v4u) || legacy.AppliesTo(v6u) {
		t.Errorf("legacy export AppliesTo mismatch")
	}
}

func TestDefaultAppliesToWildcard(t *testing.T) {
	any, _ := ParseDefault("afi any to AS1")
	if !any.AppliesTo(v4u) || !any.AppliesTo(v6u) {
		t.Errorf("afi any default should apply to both families, AFIs = %v", any.AFIs)
	}
}

// RFC 4012 §2.5: an mp-* value with no afi clause applies to every family,
// while a legacy import:/export:/default: means ipv4.unicast only.
func TestMPWithoutAFIAppliesToAll(t *testing.T) {
	v4m := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIMulticast}
	imp, _ := ParseMPImport("from AS1 accept ANY")
	exp, _ := ParseMPExport("to AS1 announce ANY")
	def, _ := ParseMPDefault("to AS1")
	for name, applies := range map[string]func(types.AddrFamily) bool{
		"mp-import": imp.AppliesTo, "mp-export": exp.AppliesTo, "mp-default": def.AppliesTo,
	} {
		if !applies(v4u) || !applies(v6u) || !applies(v4m) {
			t.Errorf("%s without afi: v4u=%v v6u=%v v4m=%v, want all true", name, applies(v4u), applies(v6u), applies(v4m))
		}
	}
	if !imp.MP || !imp.Unscoped() {
		t.Errorf("mp-import: MP=%v Unscoped=%v, want both true", imp.MP, imp.Unscoped())
	}
	legacy, _ := ParseImport("from AS1 accept ANY")
	if legacy.MP || legacy.AppliesTo(v6u) || legacy.AppliesTo(v4m) || !legacy.AppliesTo(v4u) {
		t.Errorf("legacy import must be ipv4.unicast only (MP=%v)", legacy.MP)
	}
	scoped, _ := ParseMPImport("afi ipv6.unicast from AS1 accept ANY")
	if scoped.AppliesTo(v4u) || !scoped.AppliesTo(v6u) {
		t.Errorf("mp-import afi ipv6.unicast must apply to ipv6.unicast only")
	}
}
