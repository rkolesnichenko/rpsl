package resolve_test

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestRealDataCorpus (opt-in: RPSL_REALDATA) holds a Corpus to NewMemSource on
// real data: RIPE's and ARIN's dumps, every object decoded, and the 20 largest
// as-sets and route-sets of each expanded over both — ASNs and prefixes of
// both families alike. (APNIC's 1.9 million routes, decoded whole for the
// reference, would take about 9 GB.)
func TestRealDataCorpus(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	for _, reg := range []string{"ripe", "arin"} {
		files, _ := filepath.Glob(filepath.Join(dir, reg, "*.gz"))
		var objs []object.Object
		for _, f := range files {
			base := filepath.Base(f)
			if strings.Count(base, ".") > 2 && !strings.Contains(base, ".route") && !strings.Contains(base, "-set") && !strings.Contains(base, ".aut-num") {
				continue
			}
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			for o := range rpsl.Parse(zr) {
				if obj, _ := object.Decode(o); resolve.Expandable(obj) {
					objs = append(objs, obj)
				}
			}
			fh.Close()
		}
		if len(objs) == 0 {
			continue
		}
		objs = latest(objs)
		c := corpusOf(objs)
		want, got := resolve.NewMemSource(objs), c.Source()
		var sets []object.Set
		for _, o := range objs {
			if s, ok := o.(object.Set); ok {
				sets = append(sets, s)
			}
		}
		sort.SliceStable(sets, func(i, j int) bool { return len(sets[i].SetMembers()) > len(sets[j].SetMembers()) })
		checked := 0
		for _, s := range sets {
			if checked == 20 {
				break
			}
			checked++
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			wp, werr := (&resolve.Expander{Src: want}).ExpandPrefixes(ctx, types.Ref(s.SetName()))
			gp, gerr := (&resolve.Expander{Src: got}).ExpandPrefixes(ctx, types.Ref(s.SetName()))
			cancel()
			if (werr == nil) != (gerr == nil) || werr == nil && !slices.Equal(wp.List(), gp.List()) {
				t.Errorf("%s %s: corpus %d prefixes (%v), all objects %d (%v)", reg, s.SetName(), gp.Len(), gerr, wp.Len(), werr)
			}
			t.Logf("%s %-30s %d prefixes", reg, s.SetName(), wp.Len())
		}
		t.Logf("%s: %d objects, a corpus of %d", reg, len(objs), c.Len())
	}
}
