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
	AsSet                    // as-
	RouteSet                 // rs-
	RtrSet                   // rtrs-
	FilterSet                // fltr-
	PeeringSet               // prng-
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

// SetName is a validated, possibly hierarchical RPSL set name such as
// "AS3333:AS-CUSTOMERS" (RFC 2622 §5). Only ParseSetName produces a non-zero
// value, so a SetName never carries whitespace, commas, '^', or control bytes
// and is safe to interpolate into an IRRd or whois query. It is comparable, but
// == is spelling-exact: use Canonical as the RPSL identity and map key.
type SetName struct {
	name  string   // trimmed original spelling
	canon string   // precomputed Canonical form
	class SetClass // class shared by every set component
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

// validSetComponent applies the RFC 2622 §2 name rule to a set component that
// already carries a class prefix: letters, digits, '_' and '-' only, ending in a
// letter or digit (which also rejects a bare "AS-").
func validSetComponent(c string) bool {
	for i := 0; i < len(c); i++ {
		if !isAlnum(c[i]) && c[i] != '_' && c[i] != '-' {
			return false
		}
	}
	return isAlnum(c[len(c)-1])
}

// validASNComponent restricts an ASN component to its plain or asdot spelling
// before ParseASN (which would otherwise tolerate surrounding whitespace).
func validASNComponent(c string) bool {
	for i := 0; i < len(c); i++ {
		if !isAlnum(c[i]) && c[i] != '.' {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// ParseSetName parses a set name. Components are separated by ':'; each must be
// an ASN or a set name, at least one must be a set name, and all set names must
// be of the same class (RFC 2622 §5). Only surrounding whitespace is trimmed.
func ParseSetName(s string) (SetName, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name: empty")
	}
	parts := strings.Split(t, ":")
	canon := make([]string, len(parts))
	class := SetClassUnknown
	for i, p := range parts {
		if p == "" {
			return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: empty component", s)
		}
		if cls, ok := componentClass(p); ok {
			if !validSetComponent(p) {
				return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: bad component %q", s, p)
			}
			if class != SetClassUnknown && cls != class {
				return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: mixes %s and %s components", s, class, cls)
			}
			class = cls
			canon[i] = strings.ToUpper(p)
			continue
		}
		as, err := ParseASN(p)
		if err != nil || !validASNComponent(p) {
			return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: bad component %q", s, p)
		}
		canon[i] = as.String()
	}
	if class == SetClassUnknown {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: no set component", s)
	}
	return SetName{name: t, canon: strings.Join(canon, ":"), class: class}, nil
}

// Class reports the set class of the name's set components.
func (n SetName) Class() SetClass { return n.class }

// String returns the name in its original spelling.
func (n SetName) String() string { return n.name }

// Canonical returns the RPSL identity of the name: set components upper-cased,
// ASN components normalized ("as007:as-x" and "AS7:AS-X" share one form).
func (n SetName) Canonical() string { return n.canon }

// IsZero reports whether n is the zero SetName (never produced by ParseSetName).
func (n SetName) IsZero() bool { return n.name == "" }

// Components returns the ':'-separated components in their original spelling,
// as a fresh slice.
func (n SetName) Components() []string {
	if n.name == "" {
		return nil
	}
	return strings.Split(n.name, ":")
}
