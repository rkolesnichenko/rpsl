package types

import (
	"fmt"
	"strings"
)

// SetClass identifies which RPSL set class a SetName denotes, inferred from the
// set component's prefix.
type SetClass uint8

const (
	SetClassUnknown SetClass = iota
	AsSet                     // as-
	RouteSet                  // rs-
	RtrSet                    // rtrs-
	FilterSet                 // fltr-
	PeeringSet                // prng-
)

func (c SetClass) String() string {
	switch c {
	case AsSet:
		return "as-set"
	case RouteSet:
		return "route-set"
	case RtrSet:
		return "rtr-set"
	case FilterSet:
		return "filter-set"
	case PeeringSet:
		return "peering-set"
	default:
		return "unknown"
	}
}

// SetName is a possibly hierarchical set reference such as
// "AS3333:AS-CUSTOMERS:RS-FOO". Components preserve their original case; Class is
// inferred from the last set-prefixed component.
type SetName struct {
	Components []string
	Class      SetClass
}

// componentClass reports the set class implied by a single component's prefix,
// and whether the component is a set token at all.
func componentClass(c string) (SetClass, bool) {
	lc := strings.ToLower(c)
	switch {
	case strings.HasPrefix(lc, "as-"):
		return AsSet, true
	case strings.HasPrefix(lc, "rs-"):
		return RouteSet, true
	case strings.HasPrefix(lc, "rtrs-"):
		return RtrSet, true
	case strings.HasPrefix(lc, "fltr-"):
		return FilterSet, true
	case strings.HasPrefix(lc, "prng-"):
		return PeeringSet, true
	}
	return SetClassUnknown, false
}

// ParseSetName parses a set name. Each component must be an ASN or a set token,
// and at least one component must be a set token.
func ParseSetName(s string) (SetName, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name: empty")
	}
	parts := strings.Split(t, ":")
	sn := SetName{Components: make([]string, 0, len(parts))}
	hasSet := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: empty component", s)
		}
		if cls, ok := componentClass(p); ok {
			hasSet = true
			sn.Class = cls
		} else if _, err := ParseASN(p); err != nil {
			return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: bad component %q", s, p)
		}
		sn.Components = append(sn.Components, p)
	}
	if !hasSet {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: no set component", s)
	}
	return sn, nil
}

// String joins the components with ':' in their original case.
func (n SetName) String() string {
	return strings.Join(n.Components, ":")
}

// Canonical returns the uppercased form for case-insensitive comparison.
func (n SetName) Canonical() string {
	return strings.ToUpper(n.String())
}
