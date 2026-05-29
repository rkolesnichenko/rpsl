package types

import (
	"fmt"
	"strings"
)

// NICHandle is a registry contact handle such as "EX1-RIPE" or the placeholder
// "AUTO-1". It is string-backed (comparable) and preserves its original case.
type NICHandle string

// ParseNICHandle validates and returns a NIC handle. It accepts letters, digits,
// and hyphens, and must start with a letter.
func ParseNICHandle(s string) (NICHandle, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", fmt.Errorf("rpsl/types: invalid NIC handle: empty")
	}
	if !isLetter(t[0]) {
		return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: must start with a letter", s)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !isLetter(c) && !isDigit(c) && c != '-' {
			return "", fmt.Errorf("rpsl/types: invalid NIC handle %q: bad character %q", s, c)
		}
	}
	return NICHandle(t), nil
}

func (h NICHandle) String() string { return string(h) }

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
