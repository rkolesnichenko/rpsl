package policy

import "testing"

// FuzzParseFilter asserts the standalone filter parser never panics.
func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{
		"ANY", "PeerAS", "{192.0.2.0/24^+}", "AS65000",
		"AS-FOO AND NOT AS65001", "(AS1 OR AS2)", "community(65000:1)",
		"<^AS1+$>", "", "{", "()", "fltr-EXAMPLE",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseFilter(s) })
}

// FuzzParsePeering asserts the standalone peering parser never panics.
func FuzzParsePeering(f *testing.F) {
	for _, s := range []string{
		"AS65000", "AS65000 at 192.0.2.1", "prng-EXAMPLE",
		"AS-FOO 192.0.2.1", "<^AS1$>", "", "at", "192.0.2.1 at",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParsePeering(s) })
}
