package types

import (
	"fmt"
	"strings"
)

// NICHandle is a registry contact handle such as "EX1-RIPE" or the placeholder
// "AUTO-1". Handles are case-insensitive, so a NICHandle holds the upper-case
// form and == compares handles as RPSL does. It is string-backed (comparable).
type NICHandle string

// MaxNICHandleLen is the longest NIC handle ParseNICHandle accepts. RPSL sets
// no limit; this one only bounds input, and no registry's handles come close.
const MaxNICHandleLen = 64

// ParseNICHandle validates a NIC handle. A handle is an RPSL object name (RFC
// 2622 §2): letters, digits, '_' and single hyphens, ending with a letter or
// digit ("JD123-ARIN", "APPLEC-1-Z", "VAGNER_BRASILEIRO"). It may start with a
// digit as well as a letter, since ARIN issues handles such as "1NO-ARIN".
// Anything else — a person's name with spaces, as some RADB objects hold — is
// not a handle and is rejected, so a NICHandle is always a single safe word.
// Surrounding spaces and tabs are trimmed; the handle is returned upper-case.
func ParseNICHandle(s string) (NICHandle, error) {
	t := strings.Trim(s, " \t")
	switch {
	case t == "":
		return "", fmt.Errorf("rpsl/types: invalid NIC handle: empty")
	case len(t) > MaxNICHandleLen:
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: longer than %d characters", s, MaxNICHandleLen)
	case !isLetter(t[0]) && !isDigit(t[0]):
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: must start with a letter or digit", s)
	case !isLetter(t[len(t)-1]) && !isDigit(t[len(t)-1]):
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: must end with a letter or digit", s)
	case strings.Contains(t, "--"):
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: empty part between hyphens", s)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !isLetter(c) && !isDigit(c) && c != '-' && c != '_' {
			return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: bad character %q", s, c)
		}
	}
	return NICHandle(strings.ToUpper(t)), nil
}

// String returns the handle, upper-case.
func (h NICHandle) String() string { return string(h) }

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
