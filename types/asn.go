// Package types holds the leaf value types every higher RPSL layer is built
// from: ASN, SetName, PrefixRange, NICHandle. They are built on net/netip and
// are comparable where possible so they work as map keys and in tests.
package types

import (
	"fmt"
	"strconv"
	"strings"
)

// ASN is a 32-bit autonomous system number.
type ASN uint32

// ParseASN parses "AS65001", dotted "AS1.10" (asdot), and is case-insensitive.
// Surrounding spaces and tabs are trimmed; any other whitespace is an error.
func ParseASN(s string) (ASN, error) {
	t := strings.Trim(s, " \t")
	if len(t) < 3 || !strings.EqualFold(t[:2], "as") {
		return 0, fmt.Errorf("rpsl/types: invalid ASN %q: missing AS prefix", s)
	}
	num := t[2:]
	if dot := strings.IndexByte(num, '.'); dot >= 0 {
		hi, err := strconv.ParseUint(num[:dot], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("rpsl/types: invalid ASN %q: %w", s, err)
		}
		lo, err := strconv.ParseUint(num[dot+1:], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("rpsl/types: invalid ASN %q: %w", s, err)
		}
		return ASN(hi<<16 | lo), nil
	}
	v, err := strconv.ParseUint(num, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("rpsl/types: invalid ASN %q: %w", s, err)
	}
	return ASN(v), nil
}

// String renders the ASN in plain "AS65001" form.
func (a ASN) String() string {
	return "AS" + strconv.FormatUint(uint64(a), 10)
}
