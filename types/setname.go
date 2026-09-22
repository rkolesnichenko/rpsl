package types

import (
	"fmt"
	"strings"
)

// SetClass identifies which RPSL set class a SetName denotes, inferred from the
// set component's prefix.
type SetClass uint8

// The set classes, named by their prefix.
const (
	ClassUnknown    SetClass = iota
	ClassAsSet               // as-
	ClassRouteSet            // rs-
	ClassRtrSet              // rtrs-
	ClassFilterSet           // fltr-
	ClassPeeringSet          // prng-
)

// String returns the class name, e.g. "as-set".
func (c SetClass) String() string {
	switch c {
	case ClassAsSet:
		return "as-set"
	case ClassRouteSet:
		return "route-set"
	case ClassRtrSet:
		return "rtr-set"
	case ClassFilterSet:
		return "filter-set"
	case ClassPeeringSet:
		return "peering-set"
	default:
		return "unknown"
	}
}

// SetName is a validated, possibly hierarchical RPSL set name such as
// "AS3333:AS-CUSTOMERS" (RFC 2622 §5). Only ParseSetName produces a non-zero
// value, so a SetName never carries whitespace, commas, '^', or control bytes
// and is safe to interpolate into an IRRd or whois query.
//
// RPSL names are case-insensitive, so a SetName holds only the canonical form —
// set components upper-cased, ASN components in asplain ("as007:as-x" is
// "AS7:AS-X") — and every spelling of one name is == and one map key. The
// original spelling is kept in the lossless ast layer.
type SetName struct {
	canon string   // canonical form
	class SetClass // class shared by every set component
}

// componentClass reports the set class implied by a single component's prefix,
// and whether the component is a set token at all.
func componentClass(c string) (SetClass, bool) {
	lc := strings.ToLower(c)
	switch {
	case strings.HasPrefix(lc, "as-"):
		return ClassAsSet, true
	case strings.HasPrefix(lc, "rs-"):
		return ClassRouteSet, true
	case strings.HasPrefix(lc, "rtrs-"):
		return ClassRtrSet, true
	case strings.HasPrefix(lc, "fltr-"):
		return ClassFilterSet, true
	case strings.HasPrefix(lc, "prng-"):
		return ClassPeeringSet, true
	}
	return ClassUnknown, false
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

// MaxSetNameLen is the longest set name ParseSetName accepts, in bytes. Real
// names are a few dozen bytes; the cap keeps hostile ones off query lines.
const MaxSetNameLen = 1024

// ParseSetName parses a set name. Components are separated by ':'; each must be
// an ASN or a set name, at least one must be a set name, and all set names must
// be of the same class (RFC 2622 §5). Only surrounding whitespace is trimmed.
func ParseSetName(s string) (SetName, error) {
	t := strings.Trim(s, " \t")
	if t == "" {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name: empty")
	}
	if len(t) > MaxSetNameLen {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name: longer than %d bytes", MaxSetNameLen)
	}
	parts := strings.Split(t, ":")
	canon := make([]string, len(parts))
	class := ClassUnknown
	for i, p := range parts {
		if p == "" {
			return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: empty component", s)
		}
		if cls, ok := componentClass(p); ok {
			if !validSetComponent(p) {
				return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: bad component %q", s, p)
			}
			if class != ClassUnknown && cls != class {
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
	if class == ClassUnknown {
		return SetName{}, fmt.Errorf("rpsl/types: invalid set name %q: no set component", s)
	}
	return SetName{canon: strings.Join(canon, ":"), class: class}, nil
}

// Class reports the set class of the name's set components.
func (n SetName) Class() SetClass { return n.class }

// String returns the name in canonical form.
func (n SetName) String() string { return n.canon }

// IsZero reports whether n is the zero SetName (never produced by ParseSetName).
func (n SetName) IsZero() bool { return n.canon == "" }

// Components returns the ':'-separated components, in canonical form, as a
// fresh slice.
func (n SetName) Components() []string {
	if n.canon == "" {
		return nil
	}
	return strings.Split(n.canon, ":")
}
