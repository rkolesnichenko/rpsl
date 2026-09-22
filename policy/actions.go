package policy

import (
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Typed accessors over the common rp-attributes (design §7). They interpret the
// raw Action/FilterCommunity values on demand; the underlying Attr/Op/Value
// triple is never mutated, so round-trip and the open-ended RP-attribute set are
// both preserved. Uncommon attributes simply lack an accessor and round-trip raw.

// Int returns the integer right-hand side of an assignment action such as
// "pref = 100", "med = 10", or "dpa = 5". ok is false when the action is not a
// plain assignment or the value is not an integer.
func (a Action) Int() (int, bool) {
	if a.Op != ActionAssign {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(a.Value))
	if err != nil {
		return 0, false
	}
	return n, true
}

// Prepends returns the ASNs of an "aspath.prepend(AS…, …)" method action, in
// order. ok is false for any other action, or if an argument is not an ASN.
func (a Action) Prepends() ([]types.ASN, bool) {
	if a.Op != ActionMethod || a.Attr != "aspath" || a.Method != "prepend" {
		return nil, false
	}
	out := make([]types.ASN, 0, len(a.Args))
	for _, w := range a.Args {
		as, err := types.ParseASN(w)
		if err != nil {
			return nil, false
		}
		out = append(out, as)
	}
	return out, true
}

// Communities returns the communities an action sets or adds, written as
// "community = {…}", "community .= {…}" or "community.append(…)". ok is false
// for any other action — community.delete(…) included, whose Args are the
// communities it removes.
func (a Action) Communities() ([]string, bool) {
	if a.Attr != "community" {
		return nil, false
	}
	switch {
	case a.Op == ActionAssign || a.Op == ActionAppend:
		return braceList(a.Value), true
	case a.Op == ActionMethod && a.Method == "append":
		return a.Args, true
	}
	return nil, false
}

// delimited returns the comma-separated items inside the first open..last close
// pair of s, trimmed and with empties dropped. Returns nil if the pair is absent.
func delimited(s string, open, clo byte) []string {
	i := strings.IndexByte(s, open)
	if i < 0 {
		return nil
	}
	j := strings.LastIndexByte(s, clo)
	if j <= i {
		return nil
	}
	return splitTrim(s[i+1 : j])
}

// braceList returns the items inside {…}, or the bare comma-separated list when
// no braces are present.
func braceList(s string) []string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "{") {
		return delimited(t, '{', '}')
	}
	return splitTrim(s)
}

func splitTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
