package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// FuzzParseFilter asserts the standalone filter parser never panics.
func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{
		"ANY", "PeerAS", "{192.0.2.0/24^+}", "AS65000",
		"AS-FOO AND NOT AS65001", "(AS1 OR AS2)", "community(65000:1)", "AS1 (AS2)",
		"<^AS1+$>", "", "{", "()", "fltr-EXAMPLE",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, p := parseFilterValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, flt, p.diags, func(v string) (any, []ast.Diagnostic) { return ParseFilter(v) })
		walkFilter(flt, func(f Filter) {
			if c, ok := f.(FilterCommunity); ok && !strings.HasPrefix(strings.ToLower(c.Raw), "community") {
				t.Fatalf("ParseFilter(%q) made a FilterCommunity of %q", s, c.Raw)
			}
		})
	})
}

// walkFilter calls fn for f and every filter nested in it.
func walkFilter(f Filter, fn func(Filter)) {
	fn(f)
	switch x := f.(type) {
	case FilterAnd:
		for _, t := range x.Terms {
			walkFilter(t, fn)
		}
	case FilterOr:
		for _, t := range x.Terms {
			walkFilter(t, fn)
		}
	case FilterNot:
		walkFilter(x.Inner, fn)
	}
}

// FuzzParsePeering asserts the standalone peering parser never panics.
func FuzzParsePeering(f *testing.F) {
	for _, s := range []string{
		"AS65000", "AS65000 at 192.0.2.1", "prng-EXAMPLE",
		"AS-FOO 192.0.2.1", "<^AS1$>", "", "at", "192.0.2.1 at",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		pe, p := parsePeeringValue(s)
		assertNothingDropped(t, s, p)
		checkParse(t, s, pe, p.diags, func(v string) (any, []ast.Diagnostic) { return ParsePeering(v) })
	})
}
