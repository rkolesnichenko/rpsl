package types

import (
	"fmt"
	"strings"
)

// MaxSourceNameLen is the longest IRR source name ParseSourceName accepts, in
// bytes. Real names ("RIPE-NONAUTH", "LEVEL3") are a dozen bytes.
const MaxSourceNameLen = 64

// ParseSourceName validates and canonicalizes an IRR source name — the value of
// a source: attribute, or the registry of a scoped reference: ASCII letters,
// digits, '-' and '_', upper-cased. Such a name cannot carry another command or
// argument, so it is safe in an IRRd "!s" or a whois "-s" query.
func ParseSourceName(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("rpsl/types: invalid source name: empty")
	}
	if len(s) > MaxSourceNameLen {
		return "", fmt.Errorf("rpsl/types: invalid source name: longer than %d bytes", MaxSourceNameLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '-' && c != '_' {
			return "", fmt.Errorf("rpsl/types: invalid source name %q", s)
		}
	}
	return strings.ToUpper(s), nil // ASCII only, so no byte offsets move
}

// SetRef is a reference to a set, optionally scoped to one registry
// (draft-ietf-grow-rpsl-registry-scoped-members: "RIPE::AS-FOO"). It is opaque
// and canonical, as SetName is: the source is upper-cased, so every spelling of
// a reference is == and one map key. An unscoped ref leaves the choice of
// registry to the Source's precedence.
type SetRef struct {
	source string // "" or a canonical source name
	name   SetName
}

// Ref returns the unscoped reference to name.
func Ref(name SetName) SetRef { return SetRef{name: name} }

// NewSetRef returns name scoped to source, which ParseSourceName validates. An
// empty source gives the unscoped reference.
func NewSetRef(source string, name SetName) (SetRef, error) {
	if name.IsZero() {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference: no set name")
	}
	if source == "" {
		return Ref(name), nil
	}
	s, err := ParseSourceName(source)
	if err != nil {
		return SetRef{}, err
	}
	return SetRef{source: s, name: name}, nil
}

// ParseSetRef parses "AS-FOO" or "RIPE::AS-FOO". Surrounding whitespace is
// trimmed; whitespace around "::" is an error.
func ParseSetRef(s string) (SetRef, error) {
	t := strings.Trim(s, " \t")
	src, rest, scoped := strings.Cut(t, "::")
	if !scoped {
		n, err := ParseSetName(t)
		if err != nil {
			return SetRef{}, err
		}
		return Ref(n), nil
	}
	if rest == "" || rest[0] == ' ' || rest[0] == '\t' {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference %q", s)
	}
	n, err := ParseSetName(rest)
	if err != nil {
		return SetRef{}, err
	}
	if src == "" {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference %q: empty source", s)
	}
	return NewSetRef(src, n)
}

// Source returns the registry the reference is scoped to, "" when unscoped.
func (r SetRef) Source() string { return r.source }

// Name returns the set name.
func (r SetRef) Name() SetName { return r.name }

// IsScoped reports whether the reference names a registry.
func (r SetRef) IsScoped() bool { return r.source != "" }

// IsZero reports whether r is the zero SetRef.
func (r SetRef) IsZero() bool { return r.name.IsZero() }

// String returns "RIPE::AS-FOO", or "AS-FOO" when unscoped.
func (r SetRef) String() string {
	if r.source == "" {
		return r.name.String()
	}
	return r.source + "::" + r.name.String()
}
