package rpslcheck

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/types"
)

// Important #2 (fix round 1): the sweep's one-line text format (w.only >
// ast.Info) must still show a conditional finding's Given, or a finding that
// only holds for routes passing an AS-path or community test reads as if it
// held unconditionally.
func TestDirectionShowsGivenInSweepFormat(t *testing.T) {
	var out bytes.Buffer
	w := &writer{out: &out, only: ast.Warning}
	d := consist.Direction{
		From: 65001,
		To:   65002,
		Findings: []consist.Finding{{
			Kind:     consist.NotImported,
			Severity: ast.Warning,
			Given:    []string{"<^ AS1+ $>", "NOT community(1:2)"},
		}},
	}
	af := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	src := resolve.NewMemSource(nil)
	if !w.direction(context.Background(), src, d, af) {
		t.Fatal("direction reported no Warning")
	}
	got := out.String()
	if !strings.Contains(got, "[given: <^ AS1+ $> AND NOT community(1:2)]") {
		t.Errorf("sweep line missing given: %q", got)
	}
}
