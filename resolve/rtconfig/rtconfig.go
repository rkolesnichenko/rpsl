// Package rtconfig writes router configuration from evaluated RPSL policy —
// the clauses resolve/peval computes for a BGP session — as Cisco IOS, Junos,
// Cisco IOS-XR or BIRD 2 configuration: what IRRToolSet's RtConfig does, on the
// rpsl engine. It is pure: it writes to an io.Writer and opens nothing.
//
// AS-path regexps are translated into each vendor's syntax and never evaluated
// (design §13). A construct a vendor cannot express is refused with an
// *UnsupportedError wrapping ErrUnsupported, naming the vendor, the cause and
// the term; nothing is approximated, and a Write method that fails writes
// nothing.
package rtconfig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Vendor is a router configuration dialect.
type Vendor uint8

// The vendors rtconfig writes for.
const (
	IOS   Vendor = iota + 1 // Cisco IOS / IOS-XE ("cisco")
	Junos                   // Juniper Junos ("junos")
	IOSXR                   // Cisco IOS-XR ("ciscoxr")
	BIRD2                   // BIRD 2 ("bird")
)

var vendorNames = [...]string{IOS: "cisco", Junos: "junos", IOSXR: "ciscoxr", BIRD2: "bird"}

// String returns the vendor's name as rtconfig's -config option spells it.
func (v Vendor) String() string {
	if v >= IOS && v <= BIRD2 {
		return vendorNames[v]
	}
	return "Vendor(" + strconv.Itoa(int(v)) + ")"
}

// ParseVendor reads a vendor name: rtconfig's -config names (cisco, junos,
// ciscoxr) and bird, without regard to case.
func ParseVendor(s string) (Vendor, error) {
	for _, v := range Vendors() {
		if strings.EqualFold(strings.TrimSpace(s), vendorNames[v]) {
			return v, nil
		}
	}
	return 0, fmt.Errorf("rtconfig: unknown vendor %q (want cisco, junos, ciscoxr or bird)", s)
}

// Vendors returns every vendor, in a fixed order.
func Vendors() []Vendor { return []Vendor{IOS, Junos, IOSXR, BIRD2} }

// Naming holds rtconfig's naming and numbering knobs (its "@RtConfig set"
// commands). A name pattern's first %d is replaced by the peer AS, its second
// by a count of the maps written so far (1, 2, …), as rtconfig does. A zero
// field takes DefaultNaming's.
type Naming struct {
	MapName         string // cisco_map_name: route-maps and route-policies, "MyMap_%d_%d"
	MapFirstNo      int    // cisco_map_first_no: the first route-map entry's sequence number, 1
	MapIncrementBy  int    // cisco_map_increment_by: the step between route-map entries, 1
	PrefixACLNo     int    // prefix_acl_no: the first prefix list number, 100
	ASPathACLNo     int    // aspath_acl_no: the first AS-path list number, 100
	CommunityACLNo  int    // community_acl_no: the first community list number, 100
	AccessListNo    int    // cisco_access_list_no: the first number access_list uses, 100
	JunosPolicyName string // junos_policy_name: Junos policy-statements, "policy_%d_%d"
}

// DefaultNaming returns rtconfig's defaults.
func DefaultNaming() Naming {
	return Naming{MapName: "MyMap_%d_%d", MapFirstNo: 1, MapIncrementBy: 1, PrefixACLNo: 100,
		ASPathACLNo: 100, CommunityACLNo: 100, AccessListNo: 100, JunosPolicyName: "policy_%d_%d"}
}

// Generator writes configuration for one vendor. It numbers maps and lists
// across calls, as rtconfig does across one template, so it is not safe for
// concurrent use. Set Vendor before use.
type Generator struct {
	Vendor Vendor
	// MaxPreference maps RPSL's pref N to local-preference MaxPreference−N,
	// as rtconfig's cisco_max_preference does (default 1000): RPSL prefers a
	// smaller pref, BGP a larger local-preference. A pref above it is refused.
	MaxPreference int
	Names         Naming

	maps, prefixLists, pathLists, commLists, accessLists int // how many of each written so far

	birdSessions []*birdSession // BIRD: the neighbours attached so far, for WriteSessions
}

func (g *Generator) maxPref() int {
	if g.MaxPreference <= 0 {
		return 1000
	}
	return g.MaxPreference
}

// names returns g.Names with each zero field taken from DefaultNaming.
func (g *Generator) names() Naming {
	n, d := g.Names, DefaultNaming()
	if n.MapName == "" {
		n.MapName = d.MapName
	}
	if n.MapFirstNo == 0 {
		n.MapFirstNo = d.MapFirstNo
	}
	if n.MapIncrementBy == 0 {
		n.MapIncrementBy = d.MapIncrementBy
	}
	if n.PrefixACLNo == 0 {
		n.PrefixACLNo = d.PrefixACLNo
	}
	if n.ASPathACLNo == 0 {
		n.ASPathACLNo = d.ASPathACLNo
	}
	if n.CommunityACLNo == 0 {
		n.CommunityACLNo = d.CommunityACLNo
	}
	if n.AccessListNo == 0 {
		n.AccessListNo = d.AccessListNo
	}
	if n.JunosPolicyName == "" {
		n.JunosPolicyName = d.JunosPolicyName
	}
	return n
}

// expand replaces the successive %d of pattern with nums, and %% with %.
func expand(pattern string, nums ...int) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '%' && i+1 < len(pattern) {
			switch pattern[i+1] {
			case 'd':
				if len(nums) > 0 {
					b.WriteString(strconv.Itoa(nums[0]))
					nums = nums[1:]
				}
				i++
				continue
			case '%':
				b.WriteByte('%')
				i++
				continue
			}
		}
		b.WriteByte(pattern[i])
	}
	return b.String()
}

// ErrUnsupported is wrapped by every *UnsupportedError.
var ErrUnsupported = errors.New("rtconfig: not expressible for this vendor")

// UnsupportedError reports something a vendor's configuration cannot express.
// Cause is one of the Cause constants; Term is the policy text concerned.
type UnsupportedError struct {
	Vendor Vendor
	Cause  string
	Term   string
}

func (e *UnsupportedError) Error() string {
	return "rtconfig: " + e.Vendor.String() + " cannot express " + e.Term + ": " + e.Cause
}

// Unwrap returns ErrUnsupported.
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

func unsupported(v Vendor, cause, term string) error {
	return &UnsupportedError{Vendor: v, Cause: cause, Term: term}
}

// The causes an *UnsupportedError names. They are stable: docs/rpslconf.md
// lists each, and a test holds the list to these constants.
const (
	CauseVia             = "a via clause (import-via:, export-via:)"
	CauseSAFI            = "a SAFI other than unicast"
	CauseTwoPaths        = "two AS-path regexps that must both match"
	CauseNegatedClass    = "a negated AS-path class [^…]"
	CauseSameAS          = "same-AS repetition (~*, ~+, ~{m,n}) over more than one AS"
	CausePathShape       = "an AS-path regexp shape the vendor's path syntax lacks"
	CauseCommunityForm   = "a community that is neither a:b nor a well-known one"
	CauseCommunityEquals = "an exact community match (community == {…})"
	CauseAction          = "an action other than pref, med, community, aspath.prepend and next-hop"
	CauseActionValue     = "an action value the vendor cannot set"
	CausePref            = "a pref above MaxPreference"
	CauseDefault         = "a default: the vendor has no configuration for"
	CauseNetworks        = "networks the vendor has no configuration for"
	CauseListShape       = "a filter that is not a single list of that kind"
)

// Causes returns every Cause constant, for the documentation contract.
func Causes() []string {
	return []string{CauseVia, CauseSAFI, CauseTwoPaths, CauseNegatedClass, CauseSameAS, CausePathShape,
		CauseCommunityForm, CauseCommunityEquals, CauseAction, CauseActionValue, CausePref,
		CauseDefault, CauseNetworks, CauseListShape}
}
