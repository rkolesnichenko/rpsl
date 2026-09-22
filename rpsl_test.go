package rpsl

import "testing"

// Names that only look valid after Unicode folding are reported.
func TestNonASCIIAttributeNamesAreInvalid(t *testing.T) {
	for _, src := range []string{"route : 192.0.2.0/24\n", "Key: x\n", "rou\u0000te: x\n"} {
		_, diags := ParseObject(src)
		found := false
		for _, d := range diags {
			found = found || d.Rule == "lexer/invalid-attribute-name"
		}
		if !found {
			t.Errorf("ParseObject(%q) diagnostics %+v, want lexer/invalid-attribute-name", src, diags)
		}
	}
}
