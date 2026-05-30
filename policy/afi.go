package policy

import "github.com/rkolesnichenko/rpsl/types"

// ipv4Unicast is the implicit family of a legacy (unscoped) import:/export:/
// default: value. RFC 4012 §3 equates such a value to the mp- form scoped to
// "afi ipv4.unicast".
var ipv4Unicast = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}

// afisApply reports whether a policy scoped to afis is in effect for af. An
// empty afis (unscoped, legacy) applies only to ipv4.unicast; otherwise the
// policy applies when any entry covers af (honoring "any"/SAFI wildcards).
func afisApply(afis []types.AddrFamily, af types.AddrFamily) bool {
	if len(afis) == 0 {
		return ipv4Unicast.Covers(af)
	}
	for _, a := range afis {
		if a.Covers(af) {
			return true
		}
	}
	return false
}

// Unscoped reports whether the import carries no afi clause (a legacy import:).
func (i Import) Unscoped() bool { return len(i.AFIs) == 0 }

// AppliesTo reports whether the import is in effect for address family af.
func (i Import) AppliesTo(af types.AddrFamily) bool { return afisApply(i.AFIs, af) }

// Unscoped reports whether the export carries no afi clause (a legacy export:).
func (e Export) Unscoped() bool { return len(e.AFIs) == 0 }

// AppliesTo reports whether the export is in effect for address family af.
func (e Export) AppliesTo(af types.AddrFamily) bool { return afisApply(e.AFIs, af) }

// Unscoped reports whether the default carries no afi clause (a legacy default:).
func (d Default) Unscoped() bool { return len(d.AFIs) == 0 }

// AppliesTo reports whether the default is in effect for address family af.
func (d Default) AppliesTo(af types.AddrFamily) bool { return afisApply(d.AFIs, af) }
