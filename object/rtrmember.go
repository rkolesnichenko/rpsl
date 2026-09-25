package object

import (
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// RtrMemberKind tags what one members:/mp-members: item of an rtr-set is.
type RtrMemberKind uint8

// The kinds of rtr-set member (RFC 2622 §5.5, RFC 4012).
const (
	RtrMemberInvalid RtrMemberKind = iota // unparsable; kept so nothing is dropped
	RtrMemberRouter                       // a router address or inet-rtr name
	RtrMemberSet                          // a nested rtr-set name
)

// String names the kind.
func (k RtrMemberKind) String() string {
	switch k {
	case RtrMemberRouter:
		return "router"
	case RtrMemberSet:
		return "rtr-set"
	}
	return "invalid"
}

// RtrSetMember is one member of an rtr-set: a router — an address or an
// inet-rtr name — or a nested rtr-set. Raw keeps the item as written, so an
// unparsable member round-trips instead of vanishing.
type RtrSetMember struct {
	Kind   RtrMemberKind
	Router types.RouterID // set when Kind is RtrMemberRouter
	Set    types.SetName  // set when Kind is RtrMemberSet
	Raw    string
}

// String returns the member as written.
func (m RtrSetMember) String() string { return m.Raw }

// ParseRtrSetMember parses one members: item of an rtr-set. A nested rtr-set is
// recognised first: "RTRS-FOO" is a set name, not the DNS name it also looks
// like. A name of another set class is an error, so class confusion in a messy
// registry is reported rather than silently followed.
func ParseRtrSetMember(item string) (RtrSetMember, error) {
	raw := strings.TrimSpace(item)
	m := RtrSetMember{Raw: raw}
	if raw == "" {
		return m, fmt.Errorf("rpsl/object: empty rtr-set member")
	}
	if n, err := types.ParseSetName(raw); err == nil {
		if n.Class() != types.ClassRtrSet {
			return m, fmt.Errorf("rpsl/object: %q is a %s, not a router or rtr-set", raw, n.Class())
		}
		m.Kind, m.Set = RtrMemberSet, n
		return m, nil
	}
	r, err := types.ParseRouterID(raw)
	if err != nil {
		return m, fmt.Errorf("rpsl/object: invalid rtr-set member: %w", err)
	}
	m.Kind, m.Router = RtrMemberRouter, r
	return m, nil
}
