package resolve_test

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// loadSnapshot decodes every object under testdata/snapshot into a MemSource.
func loadSnapshot(t *testing.T) *resolve.MemSource {
	t.Helper()
	dir := filepath.Join("testdata", "snapshot")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot dir: %v", err)
	}
	var objs []object.Object
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for raw := range rpsl.Parse(strings.NewReader(string(data))) {
			o, _ := object.Decode(raw)
			objs = append(objs, o)
		}
	}
	return resolve.NewMemSource(objs)
}

// readGolden returns the non-comment, non-blank lines of a golden file.
func readGolden(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("open golden %s: %v", name, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		lines = append(lines, s)
	}
	return lines
}

func mustSet(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatalf("ParseSetName(%q): %v", s, err)
	}
	return n
}

// TestGoldenExpansion is the always-on differential-correctness guard: it
// expands a basket of sets against the offline snapshot and compares to golden
// files (captured to match bgpq4's expansion of the same data). No external
// tooling required.
func TestGoldenExpansion(t *testing.T) {
	src := loadSnapshot(t)
	ctx := context.Background()

	t.Run("ExpandAS/AS-EXAMPLE", func(t *testing.T) {
		e := &resolve.Expander{Src: src}
		got, err := e.ExpandAS(ctx, mustSet(t, "AS-EXAMPLE"))
		if err != nil {
			t.Fatalf("ExpandAS: %v", err)
		}
		var lines []string
		for _, a := range got.List() {
			lines = append(lines, a.String())
		}
		assertEqual(t, lines, readGolden(t, "as-example.asn"))
	})

	// The same set written as RFC 2622 comma-separated, folded lists must
	// expand identically to its one-member-per-line twin.
	t.Run("ExpandAS/AS-EXAMPLE-LIST", func(t *testing.T) {
		e := &resolve.Expander{Src: src}
		got, err := e.ExpandAS(ctx, mustSet(t, "AS-EXAMPLE-LIST"))
		if err != nil {
			t.Fatalf("ExpandAS: %v", err)
		}
		var lines []string
		for _, a := range got.List() {
			lines = append(lines, a.String())
		}
		assertEqual(t, lines, readGolden(t, "as-example.asn"))
	})

	prefixCase := func(name, set, golden string) {
		t.Run(name, func(t *testing.T) {
			e := &resolve.Expander{Src: src, AFI: types.AFIv4}
			got, err := e.ExpandPrefixes(ctx, mustSet(t, set))
			if err != nil {
				t.Fatalf("ExpandPrefixes: %v", err)
			}
			var lines []string
			for _, p := range got.List() {
				lines = append(lines, p.String())
			}
			assertEqual(t, lines, readGolden(t, golden))
		})
	}
	prefixCase("ExpandPrefixes/AS-EXAMPLE/v4", "AS-EXAMPLE", "as-example.v4")
	prefixCase("ExpandPrefixes/RS-EXAMPLE/v4", "RS-EXAMPLE", "rs-example.v4")
}

func assertEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lines %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}
