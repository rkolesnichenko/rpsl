package policy

import (
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// SetNameTemplate is a hierarchical set name in which one or more components
// are the PeerAS keyword ("AS8821:AS-CUSTOMERS:PeerAS", "PeerAS:AS-TO-X"): a
// different set for every peer. RFC 2622 defines PeerAS in filters and AS-path
// regexps; using it inside a set name is an IRR convention common in RIPE data.
// It is comparable.
type SetNameTemplate struct {
	text  string         // trimmed original spelling
	class types.SetClass // class of the set components
}

// ParseSetNameTemplate parses a set name containing at least one PeerAS
// component. It must form a valid types.SetName once PeerAS is replaced by an
// AS number, so Instantiate cannot fail.
func ParseSetNameTemplate(s string) (SetNameTemplate, error) {
	t := strings.TrimSpace(s)
	n, ok := substitutePeerAS(t, 1)
	if !ok {
		return SetNameTemplate{}, fmt.Errorf("rpsl/policy: %q has no PeerAS component", s)
	}
	name, err := types.ParseSetName(n)
	if err != nil {
		return SetNameTemplate{}, fmt.Errorf("rpsl/policy: invalid set name template %q: %w", s, err)
	}
	return SetNameTemplate{text: t, class: name.Class()}, nil
}

// String returns the template in its original spelling.
func (t SetNameTemplate) String() string { return t.text }

// Class reports the set class of the template's set components.
func (t SetNameTemplate) Class() types.SetClass { return t.class }

// Instantiate returns the concrete set name for the given peer, replacing every
// PeerAS component with the peer's AS number.
func (t SetNameTemplate) Instantiate(peer types.ASN) types.SetName {
	s, _ := substitutePeerAS(t.text, peer)
	n, _ := types.ParseSetName(s) // validated by ParseSetNameTemplate
	return n
}

// substitutePeerAS replaces each ':'-separated PeerAS component of s with as,
// reporting whether there was at least one.
func substitutePeerAS(s string, as types.ASN) (string, bool) {
	comps := strings.Split(s, ":")
	found := false
	for i, c := range comps {
		if strings.EqualFold(c, "peeras") {
			comps[i] = as.String()
			found = true
		}
	}
	return strings.Join(comps, ":"), found
}
