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
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
)

// TestRealData is the opt-in real-data regression. Point RPSL_REALDATA at the
// directory scripts/fetch-irr-dumps.sh fills: one subdirectory of dumps per
// registry (ripe, apnic, arin, afrinic, lacnic, radb). A directory holding
// ripe.db.*.gz files itself is read as RIPE, the layout this test once used.
//
// For every dump present it checks that streaming is lossless and raises no
// stream-level diagnostics, that every route and route6 decodes to a valid
// prefix, and that decode and policy errors stay rare; RIPE's dumps are also
// validated against the RIPE profile. For RIPE and APNIC, whose dumps come one
// class per file, it also expands the largest sets twice, in opposite input
// orders, and requires identical results.
func TestRealData(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	ran := false
	for _, reg := range registries {
		regDir := filepath.Join(dir, reg.name)
		if reg.name == "ripe" && hasDumps(dir, "ripe.db.*.gz") {
			regDir = dir // the older layout: RPSL_REALDATA is the RIPE directory itself
		}
		if !hasDumps(regDir, "*.gz") {
			continue
		}
		ran = true
		t.Run(reg.name, func(t *testing.T) { checkRegistry(t, reg, regDir) })
	}
	if !ran {
		t.Fatalf("no dumps under %s (a relative path is read from the package directory; use an absolute one)", dir)
	}
}

// registry describes what one registry's dumps need from the test.
type registry struct {
	name string
	// validate: check objects against the RIPE profile. The profiles describe
	// RIPE's templates (and the RFCs'); other registries have templates of
	// their own, so validating their data against RIPE's would only measure
	// how the templates differ.
	validate bool
	// artefact reports a diagnostic caused by how the registry publishes its
	// dumps rather than by the data or this library. Each is listed with its
	// reason; everything else still counts.
	artefact func(obj *ast.Object, d rpsl.Diagnostic) bool
	// expandPrefix names the split dumps the expansion check reads
	// (<prefix>.db.<class>.gz); "" for a registry published as one file.
	expandPrefix string
	// strictVia: the registry's import-via: and export-via: values are all
	// well-formed, so any Error in one is a parser regression. Elsewhere a via
	// error counts like any other policy error.
	strictVia bool
}

var registries = []registry{
	{name: "ripe", validate: true, expandPrefix: "ripe", strictVia: true, artefact: func(obj *ast.Object, d rpsl.Diagnostic) bool {
		// RIPE's dumps remove the auth: lines of some mntners and irts.
		return d.Rule == "dict/missing-required" && (obj.Class() == "mntner" || obj.Class() == "irt") &&
			strings.Contains(d.Message, `"auth"`)
	}},
	{name: "apnic", expandPrefix: "apnic"},
	{name: "arin", artefact: func(obj *ast.Object, d rpsl.Diagnostic) bool {
		// ARIN's dump ends with a line reading EOF.
		return d.Rule == "lexer/malformed-line" && strings.HasSuffix(strings.TrimRight(obj.String(), "\r\n"), "\nEOF")
	}},
	{name: "afrinic"},
	{name: "lacnic"},
	{name: "radb"},
}

// knownGap names the library gap a failure is due to, or "" for any other
// cause. They are the gaps the real data of other registries found, each to be
// fixed in its own change; when one is, its case goes and the test holds the
// data to it.
func knownGap(d rpsl.Diagnostic) string {
	if d.Severity != rpsl.Error || !strings.HasPrefix(d.Rule, "object/") {
		return ""
	}
	m := nicHandleError.FindStringSubmatch(d.Message)
	switch {
	case m == nil:
		return ""
	case m[1] != "" && m[1][0] >= '0' && m[1][0] <= '9':
		return "NIC handles starting with a digit (ARIN)"
	case strings.Contains(m[1], " "):
		return "names where a NIC handle belongs (RADB)"
	}
	return ""
}

var nicHandleError = regexp.MustCompile(`invalid NIC handle "([^"]*)"`)

func hasDumps(dir, pattern string) bool {
	m, _ := filepath.Glob(filepath.Join(dir, pattern))
	return len(m) > 0
}

func checkRegistry(t *testing.T, reg registry, dir string) {
	dumps, _ := filepath.Glob(filepath.Join(dir, "*.gz"))
	sort.Strings(dumps)
	for _, path := range dumps {
		t.Run(filepath.Base(path), func(t *testing.T) { checkDump(t, reg, path) })
	}
	if reg.expandPrefix == "" {
		return
	}
	var inputs []string
	for _, class := range []string{"as-set", "route-set", "route", "route6", "aut-num"} {
		p := filepath.Join(dir, reg.expandPrefix+".db."+class+".gz")
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

func checkDump(t *testing.T, reg registry, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	artefact := func(obj *ast.Object, d rpsl.Diagnostic) bool { return reg.artefact != nil && reg.artefact(obj, d) }
	in, out := sha256.New(), sha256.New()
	var objects, policies, artefacts int
	var badRoutes, badVia []string
	gaps := map[string]int{}    // known gap -> diagnostics or routes
	failing := map[string]int{} // family -> objects with an Error in it
	start := time.Now()
	for obj, diags := range rpsl.Parse(io.TeeReader(gz, in)) {
		objects++
		io.WriteString(out, obj.String())
		for _, d := range diags {
			if artefact(obj, d) {
				artefacts++
				continue
			}
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
		checked := decodeDiags
		if reg.validate {
			checked = append(checked, rpsl.Validate(obj, rpsl.RIPE)...)
		}
		families := map[string]bool{}
		for _, d := range checked {
			if d.Severity != rpsl.Error {
				continue
			}
			if artefact(obj, d) {
				artefacts++
				continue
			}
			if g := knownGap(d); g != "" {
				gaps[g]++
				continue
			}
			families[strings.SplitN(d.Rule, "/", 2)[0]] = true
		}
		for f := range families {
			failing[f]++
		}
		for _, a := range obj.Attributes() {
			switch strings.TrimPrefix(a.Name, "mp-") {
			case "import", "export", "default", "filter", "peering":
				policies++
			case "import-via", "export-via":
				policies++
				if !reg.strictVia {
					continue
				}
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
	for g, n := range gaps {
		t.Logf("known library gap, not counted: %d × %s", n, g)
	}
	t.Logf("%d objects, %d policy values, %d dump artefacts, objects with errors by family %v, %v",
		objects, policies, artefacts, failing, time.Since(start).Round(time.Millisecond))
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
