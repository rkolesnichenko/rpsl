package resolve_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslq"
	"github.com/rkolesnichenko/rpsl/types"
)

// rpslqFormats are the output flag sets rpslq and bgpq4 share; each is run for
// prefix lists of both families, and as an AS list where the format has one.
var rpslqFormats = [][]string{nil, {"-j"}, {"-b"}, {"-J"}}

// rpslq writes what bgpq4 writes: the same flags against the same server give
// the same text, byte for byte, over the random IRRs the engine's own
// differential uses (in bgpq4-compatible mode), with bgpq4's special AS
// numbers dropped and kept (-p).
func TestRpslqMatchesBgpq4(t *testing.T) {
	needBgpq4(t)
	for seed := uint64(0); seed < 20; seed++ {
		r := rand.New(rand.NewPCG(seed, 11))
		m := randomModel(r, true)
		addr := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB").IRRd(t)
		var tops []string
		for name := range newOracle(m).sets {
			tops = append(tops, name)
		}
		sort.Strings(tops)
		for _, top := range tops {
			for _, special := range [][]string{nil, {"-p"}} {
				for _, format := range rpslqFormats {
					var runs [][]string
					for _, fam := range []string{"-4", "-6"} {
						runs = append(runs, append(append(append([]string{fam}, special...), format...), top))
					}
					if setClass(top) == types.ClassAsSet && (len(format) == 1 && (format[0] == "-j" || format[0] == "-b")) {
						runs = append(runs, append(append(append([]string{"-t"}, special...), format...), top))
					}
					for _, args := range runs {
						base := []string{"-h", addr, "-S", modelSources, "-L", "64"}
						want := runBgpq4Text(t, append(append([]string(nil), base...), args...))
						var got, errs bytes.Buffer
						if code := rpslq.Run(context.Background(), append(append([]string(nil), base...), args...), &got, &errs); code != 0 {
							t.Fatalf("seed %d: rpslq %v: exit %d: %s", seed, args, code, errs.String())
						}
						if got.String() != want {
							t.Fatalf("seed %d: rpslq %v differs from bgpq4:\nrpslq:\n%s\nbgpq4:\n%s", seed, args, got.String(), want)
						}
					}
				}
			}
		}
	}
}

// runBgpq4Text runs bgpq4 and returns what it writes to stdout.
func runBgpq4Text(t *testing.T, args []string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bgpq4", args...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bgpq4 %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}
