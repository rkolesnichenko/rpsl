package bulk

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate testdata golden files")

// TestRunTinyDump exercises the full pipeline (stream + decode + validate +
// resolve) against testdata/tiny-dump.txt and compares the resulting Report to
// the golden JSON. Time-varying fields are zeroed before comparison so the
// golden stays stable. Run with -update to regenerate.
func TestRunTinyDump(t *testing.T) {
	got := runOn(t, "testdata/tiny-dump.txt")
	goldenPath := filepath.Join("testdata", "expected-report.json")
	check := func(t *testing.T, gotJSON []byte) {
		if *update {
			if err := os.WriteFile(goldenPath, gotJSON, 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			t.Logf("regenerated %s", goldenPath)
			return
		}
		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden (run with -update to create): %v", err)
		}
		if !bytes.Equal(gotJSON, want) {
			t.Errorf("report does not match golden.\n--- got ---\n%s\n--- want ---\n%s", gotJSON, want)
		}
	}
	check(t, marshalForGolden(t, got))
}

// TestRunTinyDumpGzip verifies the gzip magic-byte sniff path produces an
// identical Report to the plaintext run. This is the single hardest-to-spot
// regression — a gzip-handling change that silently truncates objects.
func TestRunTinyDumpGzip(t *testing.T) {
	plain, err := os.ReadFile("testdata/tiny-dump.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	gotPlain := runOnReader(t, bytes.NewReader(plain))
	gotGz := runOnReader(t, &buf)

	// Bytes counts the compressed on-disk size by design (what the user paid for
	// at the IO layer); ParsedBytes counts what the parser consumed, which is
	// the same for both.
	if gotGz.Bytes == int64(len(plain)) {
		t.Errorf("gzip Bytes = %d, want the compressed size, not the plaintext size", gotGz.Bytes)
	}
	if gotPlain.ParsedBytes != int64(len(plain)) || gotGz.ParsedBytes != int64(len(plain)) {
		t.Errorf("ParsedBytes plain=%d gzip=%d, want %d (the decompressed dump)", gotPlain.ParsedBytes, gotGz.ParsedBytes, len(plain))
	}
	gotPlain.Bytes, gotGz.Bytes = 0, 0
	jp := marshalForGolden(t, gotPlain)
	jg := marshalForGolden(t, gotGz)
	if !bytes.Equal(jp, jg) {
		t.Errorf("gzip and plaintext Reports diverge.\n--- plain ---\n%s\n--- gzip ---\n%s", jp, jg)
	}
}

// TestPartialOnCancel asserts Run returns a non-nil partial Report when the
// context is already canceled — the harness must never lose data on Ctrl-C.
func TestPartialOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Run(ctx, bytes.NewReader([]byte("aut-num: AS1\n")), Options{})
	if err != nil {
		t.Fatalf("unexpected error from canceled Run: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil partial Report on cancellation")
	}
	if r.SchemaVersion != SchemaVersion {
		t.Errorf("partial Report missing SchemaVersion")
	}
}

func runOn(t *testing.T, path string) *Report {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	return runOnReader(t, f)
}

func runOnReader(t *testing.T, r io.Reader) *Report {
	t.Helper()
	report, err := Run(context.Background(), r, Options{
		Validate:     ValidateRIPE,
		Expand:       true,
		ExpandSample: 3, // pick top-3 per class — covers our 2 as-sets and 1 route-set
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report == nil {
		t.Fatal("Run returned nil Report with nil error")
	}
	return report
}

// marshalForGolden produces stable JSON: zero Elapsed (wall-clock) and per-
// sample ElapsedNS, indent for readability, sort map keys (encoding/json
// already does that), trailing newline.
func marshalForGolden(t *testing.T, r *Report) []byte {
	t.Helper()
	clone := *r
	clone.Elapsed = 0
	if len(clone.ResolveSamples) > 0 {
		samples := make([]ResolveSample, len(clone.ResolveSamples))
		copy(samples, clone.ResolveSamples)
		for i := range samples {
			samples[i].ElapsedNS = 0
		}
		clone.ResolveSamples = samples
	}
	buf, err := json.MarshalIndent(&clone, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(buf, '\n')
}

// An --expand-set name that does not parse is still reported (upper-cased, as
// class "unknown", with its parse error) rather than silently dropped.
func TestExpandSetBadNameReported(t *testing.T) {
	r, err := Run(context.Background(), bytes.NewReader([]byte("as-set: AS-X\nmembers: AS1\n")), Options{
		Expand:     true,
		ExpandSets: []string{"as-x", "not a set"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var bad, good *ResolveSample
	for i := range r.ResolveSamples {
		switch r.ResolveSamples[i].Set {
		case "NOT A SET":
			bad = &r.ResolveSamples[i]
		case "AS-X":
			good = &r.ResolveSamples[i]
		}
	}
	if bad == nil || bad.Class != "unknown" || bad.Err == "" {
		t.Errorf("bad name sample = %+v, want Set=NOT A SET Class=unknown with an error", bad)
	}
	if good == nil || good.Class != "as-set" || good.Err != "" || good.ASNs != 1 {
		t.Errorf("good name sample = %+v, want Set=AS-X Class=as-set ASNs=1", good)
	}
}
