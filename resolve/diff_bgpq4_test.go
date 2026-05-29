package resolve_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
)

// TestDiffBgpq4Live is the live differential-correctness harness against bgpq4
// (design §11.3). It expands a set with both this engine and `bgpq4 -j` against
// the SAME IRRd server and diffs the resulting ASNs; any divergence is a bug in
// one of the two.
//
// It is opt-in: it skips unless bgpq4 is installed AND both RPSL_BGPQ4_SERVER
// (host:port) and RPSL_BGPQ4_SET (the as-set to expand) are set, so it never
// blocks CI. The always-on golden snapshot test (TestGoldenExpansion) provides
// differential coverage without external tooling.
func TestDiffBgpq4Live(t *testing.T) {
	if _, err := exec.LookPath("bgpq4"); err != nil {
		t.Skip("bgpq4 not installed")
	}
	server := os.Getenv("RPSL_BGPQ4_SERVER")
	setName := os.Getenv("RPSL_BGPQ4_SET")
	if server == "" || setName == "" {
		t.Skip("set RPSL_BGPQ4_SERVER=host:port and RPSL_BGPQ4_SET=AS-… to run")
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		t.Fatalf("RPSL_BGPQ4_SERVER %q: %v", server, err)
	}

	out, err := exec.Command("bgpq4", "-h", host, "-p", port, "-j", "-l", "res", "-t", setName).Output()
	if err != nil {
		t.Fatalf("bgpq4: %v", err)
	}
	var parsed any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("parse bgpq4 json: %v", err)
	}
	bgpq4 := map[uint32]bool{}
	collectASNs(parsed, bgpq4)

	src := &irrd.Source{Addr: server}
	got, err := (&resolve.Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, setName))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	ours := map[uint32]bool{}
	for _, a := range got.List() {
		ours[uint32(a)] = true
	}

	for as := range bgpq4 {
		if !ours[as] {
			t.Errorf("AS%d in bgpq4 but missing from our expansion", as)
		}
	}
	for as := range ours {
		if !bgpq4[as] {
			t.Errorf("AS%d in our expansion but missing from bgpq4", as)
		}
	}
}

// collectASNs walks decoded bgpq4 JSON and records every integer (its -t output
// is a flat list of origin ASNs).
func collectASNs(v any, out map[uint32]bool) {
	switch t := v.(type) {
	case float64:
		if t >= 0 && t <= 4294967295 {
			out[uint32(t)] = true
		}
	case []any:
		for _, e := range t {
			collectASNs(e, out)
		}
	case map[string]any:
		for _, e := range t {
			collectASNs(e, out)
		}
	}
}
