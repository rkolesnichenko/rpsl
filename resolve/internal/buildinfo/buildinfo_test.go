package buildinfo

import (
	"regexp"
	"testing"
)

// semver matches Version()'s tagged-release shape: v1.2.3, with an optional
// pre-release/pseudo-version suffix (v1.2.3-rc.1, v1.2.3-0.20260930120000-abcdef123456).
var semver = regexp.MustCompile(`^v\d+\.\d+\.\d+`)

// TestVersion holds Version() to its two documented shapes: "(devel)" for an
// untagged build (an ordinary local go test in this checkout), or a semver
// tag when the binary — or, as release.sh's step 6 exercises, the test
// binary itself — was built from resolve at a published version. It must
// pass unchanged whether run here or against the published module's zip.
func TestVersion(t *testing.T) {
	v := Version()
	if v != "(devel)" && !semver.MatchString(v) {
		t.Errorf(`Version() = %q, want "(devel)" or a semver version`, v)
	}
}
