package policy

import "github.com/rkolesnichenko/rpsl/types"

// ipv4Unicast is the implicit family of a legacy import:/export:/default:
// value: RFC 4012 §2 keeps those attributes as IPv4 unicast policy.
var ipv4Unicast = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}

// afisApply reports whether a policy scoped to afis is in effect for af. With no
// afi clause, a legacy policy applies only to ipv4.unicast and an mp- policy to
// every family (RFC 4012 §2.5: "the equivalent of 'afi any'"). Otherwise the
// policy applies when any entry covers af (honoring "any"/SAFI wildcards).
func afisApply(afis []types.AddrFamily, mp bool, af types.AddrFamily) bool {
	if len(afis) == 0 {
		return mp || ipv4Unicast.Covers(af)
	}
	for _, a := range afis {
		if a.Covers(af) {
			return true
		}
	}
	return false
}

// Unscoped reports whether the import carries no afi clause.
func (i Import) Unscoped() bool { return len(i.AFIs) == 0 }

// AppliesTo reports whether the import is in effect for address family af.
func (i Import) AppliesTo(af types.AddrFamily) bool { return afisApply(i.AFIs, i.MP, af) }

// Unscoped reports whether the export carries no afi clause.
func (e Export) Unscoped() bool { return len(e.AFIs) == 0 }

// AppliesTo reports whether the export is in effect for address family af.
func (e Export) AppliesTo(af types.AddrFamily) bool { return afisApply(e.AFIs, e.MP, af) }

// Unscoped reports whether the default carries no afi clause.
func (d Default) Unscoped() bool { return len(d.AFIs) == 0 }

// AppliesTo reports whether the default is in effect for address family af.
func (d Default) AppliesTo(af types.AddrFamily) bool { return afisApply(d.AFIs, d.MP, af) }

// Unscoped reports whether the exception carries no afi clause of its own.
func (e Except) Unscoped() bool { return len(e.AFIs) == 0 }

// AppliesTo reports whether the exception's right-hand policy is in effect for
// af. An except/refine with no afi clause of its own inherits the enclosing
// policy's scope, so it applies wherever that one does.
func (e Except) AppliesTo(af types.AddrFamily) bool { return afisApply(e.AFIs, e.MP, af) }

// Unscoped reports whether the refinement carries no afi clause of its own.
func (r Refine) Unscoped() bool { return len(r.AFIs) == 0 }

// AppliesTo reports whether the refinement's right-hand policy is in effect for af.
func (r Refine) AppliesTo(af types.AddrFamily) bool { return afisApply(r.AFIs, r.MP, af) }
