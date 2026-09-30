// Package buildinfo reports which release of the resolve module a command
// was built from, for rpslq's and rpslconf's -v.
package buildinfo

import "runtime/debug"

// Version is the resolve module's version this binary was built from: the
// main module's when it is resolve (go install …/cmd/rpslq@vX), the
// dependency's when a build module requires it (release.sh), and "(devel)"
// otherwise.
func Version() string {
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
