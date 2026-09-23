package types

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxRouterNameLen is the longest router name ParseRouterID accepts, the DNS
// limit on a presentation-format name.
const MaxRouterNameLen = 253

// RouterID identifies one router, the way an rtr-set lists its members and an
// inet-rtr names itself (RFC 2622 §5.5, §9): either an IP address or the DNS
// name of an inet-rtr object.
//
// It is an opaque, canonical, comparable value, so it works as a map key and
// every spelling of one router is ==. Names are held lower-case without a
// trailing dot, and addresses are unmapped and zone-less. The original spelling
// stays in the ast layer. The zero RouterID is no router.
type RouterID struct {
	addr netip.Addr // set when the member was written as an address
	name string     // canonical DNS name otherwise
}

// ParseRouterID parses an IP address or a DNS name. Surrounding spaces and tabs
// are trimmed, as is one trailing dot. A name is a dot-separated sequence of
// labels of letters, digits and interior hyphens; a single-label name is
// accepted here and left for the policy layer to warn about.
//
// The address form is tried first, after the trailing dot is removed, so a
// spelling like "192.0.2.1." is the address and not a name that would parse
// back as one.
func ParseRouterID(s string) (RouterID, error) {
	t := strings.TrimSuffix(strings.Trim(s, " \t"), ".")
	if t == "" {
		return RouterID{}, fmt.Errorf("rpsl/types: invalid router: empty")
	}
	if a, err := ParseAddr(t); err == nil {
		return RouterID{addr: a.Unmap().WithZone("")}, nil
	}
	if err := validRouterName(t, s); err != nil {
		return RouterID{}, err
	}
	return RouterID{name: strings.ToLower(t)}, nil
}

// validRouterName checks a DNS presentation name. orig is the caller's text,
// used only in messages.
func validRouterName(name, orig string) error {
	switch {
	case name == "":
		return fmt.Errorf("rpsl/types: invalid router %q: empty name", orig)
	case len(name) > MaxRouterNameLen:
		return fmt.Errorf("rpsl/types: invalid router %q: longer than %d characters", orig, MaxRouterNameLen)
	}
	for _, label := range strings.Split(name, ".") {
		switch {
		case label == "":
			return fmt.Errorf("rpsl/types: invalid router %q: empty label", orig)
		case len(label) > 63:
			return fmt.Errorf("rpsl/types: invalid router %q: label longer than 63 characters", orig)
		case label[0] == '-' || label[len(label)-1] == '-':
			return fmt.Errorf("rpsl/types: invalid router %q: label starts or ends with a hyphen", orig)
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !isLetter(c) && !isDigit(c) && c != '-' {
				return fmt.Errorf("rpsl/types: invalid router %q: bad character %q", orig, c)
			}
		}
	}
	return nil
}

// Addr returns the router's address; ok is false when it is named instead.
func (r RouterID) Addr() (netip.Addr, bool) { return r.addr, r.addr.IsValid() }

// Name returns the router's DNS name, lower-case, or "" when it is an address.
func (r RouterID) Name() string { return r.name }

// IsZero reports whether r is the zero RouterID.
func (r RouterID) IsZero() bool { return !r.addr.IsValid() && r.name == "" }

// String renders the router in canonical text form ("" for the zero RouterID).
func (r RouterID) String() string {
	if r.addr.IsValid() {
		return r.addr.String()
	}
	return r.name
}
