package resolve_test

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
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

// TestRealDataKeepPolicy: RIPE's dumps with KeepPolicy cost at most 150 MB
// more heap than without (95 MB of aut-num text measured, plus index), and
// every aut-num decoded on demand is the one decoded at load.
func TestRealDataKeepPolicy(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ripe", "*.gz"))
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	load := func(keep bool) (*resolve.DumpLoader, uint64) {
		before := heap()
		l := &resolve.DumpLoader{KeepPolicy: keep, Sources: []string{"RIPE"}}
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Read(zr); err != nil {
				t.Fatal(err)
			}
			fh.Close()
		}
		return l, heap() - before
	}
	_, without := load(false)
	l, with := load(true)
	if extra := int64(with) - int64(without); extra > 150<<20 {
		t.Errorf("KeepPolicy costs %d MB, over the 150 MB bound", extra>>20)
	}
	src := l.Source()
	fh, err := os.Open(filepath.Join(dir, "ripe", "ripe.db.aut-num.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for raw := range rpsl.Parse(zr) {
		o, _ := object.Decode(raw)
		want, ok := o.(object.AutNum)
		if !ok {
			continue
		}
		// Compared attribute by attribute, name and value as decoded: the
		// corpus keeps an aut-num's text without the dump's header and the
		// blank lines the stream attached around it (a member-of claimant
		// whole, as streamed), and decodes it again on demand, which must
		// give the same attributes the stream did.
		got, err := src.AutNum(context.Background(), want.AS, "RIPE")
		if err != nil {
			t.Fatalf("%s: %v", want.AS, err)
		}
		g, w := attrList(got.Raw()), attrList(want.Raw())
		if !slices.Equal(g, w) {
			i := 0
			for i < len(g) && i < len(w) && g[i] == w[i] {
				i++
			}
			t.Fatalf("%s: on-demand decode differs at attribute %d of %d (want %d): got %q, want %q",
				want.AS, i, len(g), len(w), at(g, i), at(w, i))
		}
		n++
	}
	t.Logf("%d aut-nums, KeepPolicy +%d MB", n, (int64(with)-int64(without))>>20)
}

// attrList is o's attributes as (name, value) pairs, in order.
func attrList(o *ast.Object) []string {
	var out []string
	for _, a := range o.Attributes() {
		out = append(out, a.Name+": "+a.Value)
	}
	return out
}

// at is l[i], or "" past its end.
func at(l []string, i int) string {
	if i < len(l) {
		return l[i]
	}
	return ""
}
