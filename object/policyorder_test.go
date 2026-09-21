package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// Policy order is precedence (design §4), so import: and mp-import: (and the
// export/default pairs) must stay interleaved exactly as written, and the mp-
// forms must be parsed as RFC 4012 (no afi clause = every family).
func TestAutNumPoliciesKeepDocumentOrder(t *testing.T) {
	an := mustDecode(t, `aut-num:    AS1
as-name:    X
import:     from AS2 accept ANY
mp-import:  from AS3 accept ANY
import:     from AS4 accept ANY
export:     to AS2 announce AS1
mp-export:  afi ipv6.unicast to AS3 announce AS1
export:     to AS4 announce AS1
mp-default: to AS3
default:    to AS2
`).(AutNum)

	peer := func(e policy.Expr) uint32 {
		return uint32(e.(policy.Factor).Peers[0].Peering.(policy.PeeringAS).AS.(policy.ASNum).AS)
	}
	var imports, exports []uint32
	var importMP, exportMP, defaultMP []bool
	for _, i := range an.Imports {
		imports, importMP = append(imports, peer(i.Expr)), append(importMP, i.MP)
	}
	for _, e := range an.Exports {
		exports, exportMP = append(exports, peer(e.Expr)), append(exportMP, e.MP)
	}
	var defaults []uint32
	for _, d := range an.Defaults {
		defaults = append(defaults, uint32(d.Peering.(policy.PeeringAS).AS.(policy.ASNum).AS))
		defaultMP = append(defaultMP, d.MP)
	}
	if !reflect.DeepEqual(imports, []uint32{2, 3, 4}) || !reflect.DeepEqual(importMP, []bool{false, true, false}) {
		t.Errorf("imports = %v MP %v, want [2 3 4] MP [false true false]", imports, importMP)
	}
	if !reflect.DeepEqual(exports, []uint32{2, 3, 4}) || !reflect.DeepEqual(exportMP, []bool{false, true, false}) {
		t.Errorf("exports = %v MP %v, want [2 3 4] MP [false true false]", exports, exportMP)
	}
	if !reflect.DeepEqual(defaults, []uint32{3, 2}) || !reflect.DeepEqual(defaultMP, []bool{true, false}) {
		t.Errorf("defaults = %v MP %v, want [3 2] MP [true false]", defaults, defaultMP)
	}

	v6u := types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
	if !an.Imports[1].AppliesTo(v6u) || an.Imports[0].AppliesTo(v6u) {
		t.Errorf("mp-import without afi must apply to IPv6; legacy import must not")
	}
}
