package rpki

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
)

// rpkiAwareExports are the registries whose dumps an RPKI-aware IRRd exports,
// leaving the invalid routes out as it does from its answers: RADB's own, and
// NTT's (rr.ntt.net lists the source RPKI). The other mirrors on RADB's FTP
// server are the registries' own dumps, passed on unfiltered: 79% of BELL's
// routes are invalid, and RADB serves none of them (TestLiveRPKIAgreesWithRADB).
var rpkiAwareExports = []string{"radb", "nttcom"}

// TestRealDataRPKI (opt-in: RPSL_REALDATA, filled by scripts/fetch-irr-dumps.sh
// with the dumps and rpki/vrps.json) reads NTT's VRP export as IRRd does,
// writes its pseudo objects and loads them back, and validates every route of
// every registry. The dumps an RPKI-aware IRRd exported hold almost no route
// Validate finds invalid — only those that ROAs issued since the export made
// so, at most 1% — which holds it to IRRd's validator on real data; the other
// registries are logged.
func TestRealDataRPKI(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	f, err := os.Open(filepath.Join(dir, "rpki", "vrps.json"))
	if err != nil {
		t.Skipf("no VRPs (scripts/fetch-irr-dumps.sh rpki): %v", err)
	}
	start := time.Now()
	v, err := ReadJSON(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read %d VRPs in %s", v.Len(), time.Since(start).Round(time.Millisecond))
	if v.Len() < 100_000 {
		t.Fatalf("only %d VRPs", v.Len())
	}

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(v.WriteRPSL(pw)) }()
	l := &resolve.DumpLoader{}
	if err := l.Read(pr); err != nil {
		t.Fatal(err)
	}
	if l.Stats.Diagnosed != 0 || l.Stats.Kept == 0 || l.Stats.Kept > v.Len() {
		t.Errorf("pseudo objects loaded as %+v from %d VRPs", l.Stats, v.Len())
	}

	regs, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range regs {
		if !reg.IsDir() || reg.Name() == "rpki" {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, reg.Name(), "*.gz"))
		var routes, invalid, notFound int
		for _, file := range files {
			base := filepath.Base(file)
			if strings.Count(base, ".") > 2 && !strings.Contains(base, ".route") { // a split dump of another class
				continue
			}
			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			for o := range rpsl.Parse(zr) {
				if c := o.Class(); c != "route" && c != "route6" {
					continue
				}
				obj, _ := object.Decode(o)
				p, origin, ok := route(obj)
				if !ok || !p.IsValid() {
					continue
				}
				routes++
				switch v.Validate(p, origin) {
				case Invalid:
					invalid++
				case NotFound:
					notFound++
				}
			}
			f.Close()
		}
		if routes == 0 {
			continue
		}
		share := float64(invalid) / float64(routes)
		t.Logf("%-8s %9d routes: %7d invalid (%.2f%%), %9d not found", reg.Name(), routes, invalid, 100*share, notFound)
		if slices.Contains(rpkiAwareExports, reg.Name()) && share > 0.01 {
			t.Errorf("%s: %.2f%% of the routes its IRRd exported are invalid; it leaves the invalid ones out", reg.Name(), 100*share)
		}
	}
}
