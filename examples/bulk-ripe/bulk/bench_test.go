package bulk

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// The real-data benchmarks measure the library on the RIPE split dumps, which
// the generated inputs of the other benchmarks only imitate. Like the
// real-data tests they are opt-in: set RPSL_REALDATA to the directory
// scripts/fetch-irr-dumps.sh fills (its ripe/ subdirectory is read, or the
// directory itself when it holds the RIPE dumps).

// realDump returns the named dump decompressed, so a benchmark measures
// parsing rather than gzip.
func realDump(b *testing.B, class string) []byte {
	b.Helper()
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		b.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	path := filepath.Join(dir, "ripe", "ripe.db."+class+".gz")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(dir, "ripe.db."+class+".gz")
	}
	f, err := os.Open(path)
	if err != nil {
		b.Skipf("%v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		b.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

// BenchmarkRealDataStream parses and decodes the RIPE aut-num dump, the one
// with the most policy text.
func BenchmarkRealDataStream(b *testing.B) {
	data := realDump(b, "aut-num")
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for o := range rpsl.Parse(bytes.NewReader(data)) {
			rpsl.Decode(o)
			n++
		}
		if n == 0 {
			b.Fatal("no objects")
		}
	}
}

// realExpansion is the source and set BenchmarkRealDataExpand measures: the
// RIPE as-set, route and route6 dumps loaded into a MemSource, and the as-set
// with the most direct members that expands within the default limits.
var realExpansion struct {
	once sync.Once
	src  *resolve.MemSource
	set  types.SetName
	err  error
}

func BenchmarkRealDataExpand(b *testing.B) {
	var dumps [][]byte
	for _, class := range []string{"as-set", "route", "route6"} {
		dumps = append(dumps, realDump(b, class))
	}
	ctx := context.Background()
	realExpansion.once.Do(func() {
		var objs []object.Object
		var sets []object.AsSet
		for _, data := range dumps {
			for o := range rpsl.Parse(bytes.NewReader(data)) {
				d, _ := rpsl.Decode(o)
				objs = append(objs, d)
				if s, ok := d.(object.AsSet); ok {
					sets = append(sets, s)
				}
			}
		}
		realExpansion.src = resolve.NewMemSource(objs, "RIPE")
		sort.Slice(sets, func(i, j int) bool { return len(sets[i].Members) > len(sets[j].Members) })
		e := &resolve.Expander{Src: realExpansion.src}
		for _, s := range sets {
			if _, err := e.ExpandPrefixes(ctx, s.Name); err == nil {
				realExpansion.set = s.Name
				return
			}
		}
		realExpansion.err = errNoExpandableSet
	})
	if realExpansion.err != nil {
		b.Fatal(realExpansion.err)
	}
	e := &resolve.Expander{Src: realExpansion.src}
	b.ReportAllocs()
	b.ResetTimer()
	var prefixes int
	for i := 0; i < b.N; i++ {
		got, err := e.ExpandPrefixes(ctx, realExpansion.set)
		if err != nil {
			b.Fatal(err)
		}
		prefixes = got.Len()
	}
	b.ReportMetric(float64(prefixes), "prefixes")
}

var errNoExpandableSet = errors.New("no as-set in the dumps expands within the default limits")
