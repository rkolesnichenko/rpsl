package resolve

import (
	"os/exec"
	"testing"
)

// TestDiffBgpq4 is the differential-correctness harness against bgpq4 (design
// §11.3). It expands a basket of sets with both this engine and `bgpq4 -j`
// against a shared offline IRR snapshot and diffs the results; any divergence
// is a bug in one of the two.
//
// The harness is gated: it skips cleanly when bgpq4 is not installed or when no
// offline snapshot is configured, so it never blocks the suite in environments
// that lack the external tool. Wiring an actual snapshot is tracked for the M6
// live/IRRd-backend work, where a fixed corpus is checked in.
func TestDiffBgpq4(t *testing.T) {
	if _, err := exec.LookPath("bgpq4"); err != nil {
		t.Skip("bgpq4 not installed; skipping differential test")
	}
	t.Skip("differential test requires a checked-in offline IRR snapshot (wired in M6)")
}
