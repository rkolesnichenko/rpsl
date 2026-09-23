package bulk

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
)

// TestRealData is the opt-in real-data regression. Point RPSL_REALDATA at a
// directory of RIPE split dumps (ripe.db.<class>.gz; scripts/fetch-ripe-dumps.sh
// downloads them). For every dump present it checks that streaming is lossless
// and raises no stream-level diagnostics, that every route and route6 decodes
// to a valid prefix, and that decode, policy and RIPE validation errors stay
// rare. With the set, route and aut-num dumps present it also expands the
// largest sets, twice, in opposite input orders, and requires identical results.
func TestRealData(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to a directory of RIPE split dumps (see scripts/fetch-ripe-dumps.sh)")
	}
	dumps, _ := filepath.Glob(filepath.Join(dir, "ripe.db.*.gz"))
	if len(dumps) == 0 {
		t.Fatalf("no ripe.db.*.gz dumps in %s (a relative path is read from the package directory; use an absolute one)", dir)
	}
	sort.Strings(dumps)
	for _, path := range dumps {
		t.Run(filepath.Base(path), func(t *testing.T) { checkDump(t, path) })
	}
	engine := []string{"as-set", "route-set", "route", "route6", "aut-num"}
	var inputs []string
	for _, class := range engine {
		p := filepath.Join(dir, "ripe.db."+class+".gz")
		if _, err := os.Stat(p); err != nil {
			t.Logf("skipping expansion check: %s not present", filepath.Base(p))
			return
		}
		inputs = append(inputs, p)
	}
	t.Run("expansion", func(t *testing.T) { checkExpansion(t, inputs) })
}

// Real registry data holds a few genuinely malformed objects, but a parser or
// profile regression shows up in many. So each diagnostic family (lexer/,
// object/, policy/, dict/, ...) may put Errors on at most maxErrorRate of a
// dump's objects, and never fewer than minTolerated (small dumps).
const (
	maxErrorRate = 0.001
	minTolerated = 3
)

func checkDump(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	in, out := sha256.New(), sha256.New()
	var objects, policies int
	var badRoutes, badVia []string
	failing := map[string]int{} // family -> objects with an Error in it
	start := time.Now()
	for obj, diags := range rpsl.Parse(io.TeeReader(gz, in)) {
		objects++
		io.WriteString(out, obj.String())
		for _, d := range diags {
			t.Errorf("stream diagnostic %s at line %d: %s", d.Rule, d.Span.StartLine, d.Message)
		}
		typed, decodeDiags := object.Decode(obj)
		switch r := typed.(type) {
		case object.Route:
			if !r.Prefix.IsValid() {
				badRoutes = append(badRoutes, obj.Key())
			}
		case object.Route6:
			if !r.Prefix.IsValid() {
				badRoutes = append(badRoutes, obj.Key())
			}
		}
		families := map[string]bool{}
		for _, d := range append(decodeDiags, rpsl.Validate(obj, rpsl.RIPE)...) {
			if d.Severity == rpsl.Error {
				families[strings.SplitN(d.Rule, "/", 2)[0]] = true
			}
		}
		for f := range families {
			failing[f]++
		}
		for _, a := range obj.Attributes() {
			switch strings.TrimPrefix(a.Name, "mp-") {
			case "import", "export", "default", "filter", "peering":
				policies++
			case "import-via", "export-via":
				// RIPE data has no malformed via policy, so any Error is a
				// parser regression, not bad data.
				policies++
				parse := func(v string) []rpsl.Diagnostic { _, d := policy.ParseImportVia(v); return d }
				if a.Name == "export-via" {
					parse = func(v string) []rpsl.Diagnostic { _, d := policy.ParseExportVia(v); return d }
				}
				for _, d := range parse(a.Value) {
					if d.Severity == rpsl.Error {
						badVia = append(badVia, fmt.Sprintf("%s %s: %s: %s", obj.Key(), a.Name, d.Rule, d.Message))
					}
				}
			}
		}
	}
	if len(badRoutes) > 0 {
		// An undecodable route prefix is dropped from every expansion.
		t.Errorf("%d route objects have no valid prefix, e.g. %q", len(badRoutes), badRoutes[:min(5, len(badRoutes))])
	}
	if len(badVia) > 0 {
		t.Errorf("%d via policies have errors, e.g. %q", len(badVia), badVia[:min(5, len(badVia))])
	}
	if !reflect.DeepEqual(in.Sum(nil), out.Sum(nil)) {
		t.Error("the stream is not lossless: concatenated objects differ from the input")
	}
	allowed := max(int(maxErrorRate*float64(objects)), minTolerated)
	for family, n := range failing {
		if n > allowed {
			t.Errorf("%d of %d objects have %s/* errors; at most %d (%.1f%%) are tolerated",
				n, objects, family, allowed, 100*maxErrorRate)
		}
	}
	t.Logf("%d objects, %d policy values, objects with errors by family %v, %v",
		objects, policies, failing, time.Since(start).Round(time.Millisecond))
}

// checkExpansion streams the dumps into the bulk harness's resolve pass twice,
// in opposite orders, and requires the same expansion of the 20 largest as-sets
// and route-sets, with only documented error outcomes.
func checkExpansion(t *testing.T, inputs []string) {
	run := func(paths []string) []ResolveSample {
		var readers []io.Reader
		for _, p := range paths {
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			gz, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			readers = append(readers, gz, strings.NewReader("\n"))
		}
		report, err := Run(context.Background(), io.MultiReader(readers...), Options{
			Validate: ValidateOff, Expand: true, ExpandSample: 20, ExpandTimeout: 2 * time.Minute,
			MaxRetainAutNums: 1 << 22, MaxRetainAsSets: 1 << 22, MaxRetainRouteSets: 1 << 22, MaxRetainRoutes: 1 << 23,
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for i := range report.ResolveSamples {
			report.ResolveSamples[i].ElapsedNS = 0
		}
		return report.ResolveSamples
	}
	forward := run(inputs)
	reversed := append([]string(nil), inputs...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if backward := run(reversed); !reflect.DeepEqual(forward, backward) {
		t.Errorf("expansion depends on input order:\nforward  %+v\nreversed %+v", forward, backward)
	}
	for _, s := range forward {
		if s.Err != "" && !strings.Contains(s.Err, "closes a cycle") && !strings.Contains(s.Err, "cannot be expanded") {
			t.Errorf("%s %s: unexpected error %s", s.Class, s.Set, s.Err)
		}
		t.Logf("%-10s %-32s asns=%-6d prefixes=%-8d truncated=%v %s", s.Class, s.Set, s.ASNs, s.Prefixes, s.Truncated, s.Err)
	}
}
