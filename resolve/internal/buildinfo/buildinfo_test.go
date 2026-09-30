package buildinfo

import "testing"

func TestVersionInTests(t *testing.T) {
	if v := Version(); v != "(devel)" {
		t.Errorf("Version() = %q in a test binary, want (devel)", v)
	}
}
