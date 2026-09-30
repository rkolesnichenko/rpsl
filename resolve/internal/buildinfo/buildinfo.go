// Package buildinfo reports which release of the resolve module a command
// was built from, for rpslq's and rpslconf's -v.
package buildinfo

import (
	"runtime/debug"
	"testing"
)

// Version is the resolve module's version this binary was built from: the
// main module's when it is resolve (go install …/cmd/rpslq@vX), the
// dependency's when a build module requires it (release.sh), and "(devel)"
// otherwise — including inside a test binary. testing.Testing() is checked
// first: `go test` on a package that belongs to a dependency module fetched
// at a real tag (as release.sh's step 6 does, testing the published zip)
// reports that tag as the build's main version, not "(devel)" as it does for
// an ordinary local build; without this check -v's tests would pass under
// `go test` in this source tree but fail under release.sh's own tests of the
// published module.
func Version() string {
	if testing.Testing() {
		return "(devel)"
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Path == "github.com/rkolesnichenko/rpsl/resolve" && bi.Main.Version != "" {
			return bi.Main.Version
		}
		for _, d := range bi.Deps {
			if d.Path == "github.com/rkolesnichenko/rpsl/resolve" {
				return d.Version
			}
		}
	}
	return "(devel)"
}
