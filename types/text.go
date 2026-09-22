package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Text forms (encoding.TextMarshaler / TextUnmarshaler) for every value type:
// MarshalText writes the same form String does and the parser reads, so values
// round-trip through encoding/json, flags and map keys. For the types whose zero
// value is "none" (SetName, PrefixRange, RangeOperator, AddrFamily, NICHandle,
// RouterID), the zero value marshals as "" and "" unmarshals to it.

// MarshalText returns "AS<n>".
func (a ASN) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText parses a as ParseASN does.
func (a *ASN) UnmarshalText(b []byte) error {
	v, err := ParseASN(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// UnmarshalJSON accepts a JSON string ("AS65001") or a JSON number (65001), the
// form RDAP and many APIs use. JSON null leaves a unchanged.
func (a *ASN) UnmarshalJSON(b []byte) error {
	switch {
	case string(b) == "null":
		return nil
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		return a.UnmarshalText([]byte(s))
	}
	n, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		return fmt.Errorf("rpsl/types: invalid ASN %s", b)
	}
	*a = ASN(n)
	return nil
}

// MarshalText returns the canonical name ("" for the zero SetName).
func (n SetName) MarshalText() ([]byte, error) { return []byte(n.String()), nil }

// UnmarshalText parses n as ParseSetName does; "" is the zero SetName.
func (n *SetName) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*n = SetName{}
		return nil
	}
	v, err := ParseSetName(string(b))
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// MarshalText returns the canonical range ("" for the zero PrefixRange).
func (r PrefixRange) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText parses r as ParsePrefixRange does; "" is the zero PrefixRange.
func (r *PrefixRange) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*r = PrefixRange{}
		return nil
	}
	v, err := ParsePrefixRange(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// MarshalText returns the operator with its '^' ("" for no operator).
func (o RangeOperator) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText parses "^+", "^-", "^n" or "^n-m" (the '^' is optional); ""
// is no operator.
func (o *RangeOperator) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*o = RangeOperator{}
		return nil
	}
	v, err := ParseRangeOperator(strings.TrimPrefix(string(b), "^"))
	if err != nil {
		return err
	}
	*o = v
	return nil
}

// MarshalText returns the afi form ("" for the zero AddrFamily).
func (a AddrFamily) MarshalText() ([]byte, error) {
	if a == (AddrFamily{}) {
		return nil, nil
	}
	return []byte(a.String()), nil
}

// UnmarshalText parses a as ParseAddrFamily does; "" is the zero AddrFamily.
func (a *AddrFamily) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*a = AddrFamily{}
		return nil
	}
	v, err := ParseAddrFamily(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// MarshalText returns the handle (upper-case).
func (h NICHandle) MarshalText() ([]byte, error) { return []byte(h), nil }

// UnmarshalText parses h as ParseNICHandle does; "" is the zero NICHandle.
func (h *NICHandle) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*h = ""
		return nil
	}
	v, err := ParseNICHandle(string(b))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

// MarshalText returns the router's canonical form; the zero RouterID is "".
func (r RouterID) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText parses r as ParseRouterID does; "" is the zero RouterID.
func (r *RouterID) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*r = RouterID{}
		return nil
	}
	v, err := ParseRouterID(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}
