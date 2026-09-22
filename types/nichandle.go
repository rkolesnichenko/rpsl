package types

import (
	"fmt"
	"strings"
)

// NICHandle is a registry contact handle such as "EX1-RIPE" or the placeholder
// "AUTO-1". Handles are case-insensitive, so a NICHandle holds the upper-case
// form and == compares handles as RPSL does. It is string-backed (comparable).
type NICHandle string

// MaxNICHandleLen is the longest NIC handle ParseNICHandle accepts.
const MaxNICHandleLen = 30

// ParseNICHandle validates a NIC handle: letters, digits and single hyphens, at
// most 30 of them, starting with a letter and ending with a letter or digit
// ("JD123-ARIN", "APPLEC-1-Z"). Surrounding spaces and tabs are trimmed; the
// handle is returned upper-case.
func ParseNICHandle(s string) (NICHandle, error) {
	t := strings.Trim(s, " \t")
	switch {
	case t == "":
		return "", fmt.Errorf("rpsl/types: invalid NIC handle: empty")
	case len(t) > MaxNICHandleLen:
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: longer than %d characters", s, MaxNICHandleLen)
	case !isLetter(t[0]):
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: must start with a letter", s)
	case t[len(t)-1] == '-':
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: must end with a letter or digit", s)
	case strings.Contains(t, "--"):
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: empty part between hyphens", s)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !isLetter(c) && !isDigit(c) && c != '-' {
			return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: bad character %q", s, c)
		}
	}
	return NICHandle(strings.ToUpper(t)), nil
}

// String returns the handle, upper-case.
func (h NICHandle) String() string { return string(h) }

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
