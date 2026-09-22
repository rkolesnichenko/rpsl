package resolve_test

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from bgpq4's output (needs bgpq4)")

// snapshotSources is the source priority the snapshot is expanded under, by
// the engine and by bgpq4 alike.
const snapshotSources = "TEST,RADB"

// snapshotTexts returns the objects under testdata/snapshot, one text each.
func snapshotTexts(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("testdata", "snapshot")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot dir: %v", err)
	}
	var texts []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for raw := range rpsl.Parse(strings.NewReader(string(data))) {
			if raw.Class() != "" {
				texts = append(texts, raw.String())
			}
		}
	}
	return texts
}

// loadSnapshot decodes every object under testdata/snapshot into a MemSource.
func loadSnapshot(t *testing.T) *resolve.MemSource {
	t.Helper()
	var objs []object.Object
	for _, text := range snapshotTexts(t) {
		raw, _ := rpsl.ParseObject(text)
		o, _ := object.Decode(raw)
		objs = append(objs, o)
	}
	return resolve.NewMemSource(objs, strings.Split(snapshotSources, ",")...)
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

// golden is one expansion of the basket: a set, what is expanded ("asn", "v4"
// or "v6"), and the golden file holding bgpq4's answer.
type golden struct{ set, kind, file string }

func basket() []golden {
	var out []golden
	for _, c := range []struct {
		set   string
		kinds []string
	}{
		{"AS-EXAMPLE", []string{"asn", "v4", "v6"}},
		{"AS-CLAIMED", []string{"asn", "v4", "v6"}},
		{"AS-ANYREF", []string{"asn", "v6"}},
		{"AS-PRECEDENCE", []string{"asn"}},
		{"AS-WITH-MISSING", []string{"asn"}},
		{"RS-EXAMPLE", []string{"v4"}},
		{"RS-RANGES", []string{"v4", "v6"}},
		{"RS-NESTED", []string{"v4", "v6"}},
		{"RS-CLAIMED", []string{"v4", "v6"}},
	} {
		for _, k := range c.kinds {
			out = append(out, golden{c.set, k, strings.ToLower(c.set) + "." + k})
		}
	}
	// The same set as a comma-separated, folded list expands identically.
	return append(out, golden{"AS-EXAMPLE-LIST", "asn", "as-example.asn"})
}

// TestGoldenExpansion is the always-on differential guard: every set of the
// basket expands, against the offline snapshot, to exactly what bgpq4 printed
// for it (TestGoldensAreBgpq4Output keeps the goldens honest).
func TestGoldenExpansion(t *testing.T) {
	src := loadSnapshot(t)
	for _, g := range basket() {
		t.Run(g.file+"/"+g.set, func(t *testing.T) {
			asns, v4, v6 := engineResults(t, src, g.set)
			got := map[string][]string{"asn": asns, "v4": v4, "v6": v6}[g.kind]
			assertEqual(t, got, readGolden(t, g.file))
		})
	}
}

// TestGoldensAreBgpq4Output checks each golden against bgpq4 run on the
// snapshot, served by irrtest; -update rewrites them from bgpq4's output.
func TestGoldensAreBgpq4Output(t *testing.T) {
	needBgpq4(t)
	addr := irrtest.New(snapshotTexts(t)...).IRRd(t)
	for _, g := range basket() {
		var got []string
		flagFor := map[string]string{"asn": "-t", "v4": "-4", "v6": "-6"}[g.kind]
		switch g.kind {
		case "asn":
			got = bgpq4ASNs(t, addr, snapshotSources, g.set)
		default:
			got = bgpq4Prefixes(t, addr, snapshotSources, g.set, g.kind == "v6")
		}
		if *update && g.file == strings.ToLower(g.set)+"."+g.kind { // an alias shares its set's file
			header := fmt.Sprintf("# bgpq4 %s -S %s %s %s, against testdata/snapshot served by\n"+
				"# internal/irrtest. Regenerate: go test -run TestGoldensAreBgpq4Output -update .\n",
				strings.Join(bgpq4Args, " "), snapshotSources, flagFor, g.set)
			body := strings.Join(got, "\n")
			if body != "" {
				body += "\n"
			}
			if err := os.WriteFile(filepath.Join("testdata", "golden", g.file), []byte(header+body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if *update {
			continue
		}
		if want := readGolden(t, g.file); !slices.Equal(got, want) {
			t.Errorf("%s: bgpq4 prints %v, the golden holds %v", g.file, got, want)
		}
	}
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
