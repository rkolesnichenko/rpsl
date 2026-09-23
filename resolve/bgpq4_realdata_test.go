package resolve_test

import (
	"compress/gzip"
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestBgpq4RealData (opt-in: RPSL_REALDATA=<absolute dir with the RIPE split
// dumps> and bgpq4 installed) serves the RIPE as-set, route-set, aut-num,
// route and route6 dumps to bgpq4 through irrtest, and compares its expansion
// of the largest sets and a random sample with the engine's. A difference is
// allowed only where the set's closure holds one of the known divergences
// (testdata/bgpq4/divergences.md); the counts are logged.
func TestBgpq4RealData(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	if st, err := os.Stat(filepath.Join(dir, "ripe")); err == nil && st.IsDir() {
		dir = filepath.Join(dir, "ripe") // the RIPE dumps; RPSL_REALDATA may also name them directly
	}
	needBgpq4(t)
	db := irrtest.New()
	var objs []object.Object
	var asSets, routeSets []object.Set
	for _, class := range []string{"as-set", "route-set", "aut-num", "route", "route6"} {
		f, err := os.Open(filepath.Join(dir, "ripe.db."+class+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		for raw := range rpsl.Parse(gz) {
			if raw.Class() == "" {
				continue
			}
			db.Add(raw, "")
			o, _ := rpsl.Decode(raw)
			objs = append(objs, o)
			switch s := o.(type) {
			case object.AsSet:
				asSets = append(asSets, s)
			case object.RouteSet:
				routeSets = append(routeSets, s)
			}
		}
		f.Close()
	}
	src := resolve.NewMemSource(objs, "RIPE")
	addr := db.IRRd(t)

	// The largest sets by direct member count, and a fixed random sample.
	pick := func(sets []object.Set, largest, sample int) []string {
		sort.Slice(sets, func(i, j int) bool { return len(sets[i].SetMembers()) > len(sets[j].SetMembers()) })
		var out []string
		for _, s := range sets[:min(largest, len(sets))] {
			out = append(out, s.SetName().String())
		}
		r := rand.New(rand.NewPCG(1, 2))
		for k := 0; k < sample; k++ {
			out = append(out, sets[r.IntN(len(sets))].SetName().String())
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	var agree, differ, refused, tooLarge int
	for _, name := range append(pick(asSets, 10, 150), pick(routeSets, 10, 150)...) {
		reasons := divergentFeatures(db, name)
		n := mustSet(t, name)
		var tl *resolve.SetTooLargeError
		_, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), n)
		switch {
		case errors.As(err, &tl) && tl.Limit == resolve.LimitPrefixes:
			tooLarge++ // more prefixes than the default cap; bgpq4 would print them all
			t.Logf("%s: over MaxPrefixes, not compared", name)
			continue
		case err != nil && len(reasons) > 0:
			refused++
			t.Logf("%s: the engine refuses it (%v), as expected: %s", name, err, strings.Join(reasons, ", "))
			continue
		case err != nil:
			t.Errorf("%s: the engine fails (%v) with no known divergence in its closure", name, err)
			continue
		}
		asns, v4, v6 := engineResults(t, src, name)
		same := slices.Equal(v4, bgpq4Prefixes(t, addr, "RIPE", name, false)) &&
			slices.Equal(v6, bgpq4Prefixes(t, addr, "RIPE", name, true))
		if n.Class() == types.ClassAsSet {
			same = same && slices.Equal(asns, bgpq4ASNs(t, addr, "RIPE", name))
		}
		switch {
		case same:
			agree++
		case len(reasons) > 0:
			differ++
			t.Logf("%s differs, as expected: %s", name, strings.Join(reasons, ", "))
		default:
			t.Errorf("%s: the engine and bgpq4 differ, with no known divergence in its closure", name)
		}
	}
	t.Logf("%d sets agree with bgpq4; %d differ and %d are refused by the engine where a known divergence "+
		"explains it; %d are over MaxPrefixes", agree, differ, refused, tooLarge)
}

// divergentFeatures walks everything a set can reach, following every set name
// as bgpq4 and IRRd would, and names the known divergences it meets.
func divergentFeatures(db *irrtest.DB, name string) []string {
	found := map[string]bool{}
	seen := map[string]bool{}
	var walk func(set string, class types.SetClass)
	walk = func(set string, class types.SetClass) {
		if seen[strings.ToUpper(set)] {
			return
		}
		seen[strings.ToUpper(set)] = true
		members, ok := db.Members([]string{"RIPE"}, set)
		if !ok {
			return
		}
		for _, m := range members {
			base, op, hasOp := strings.Cut(m, "^")
			n, err := types.ParseSetName(base)
			switch {
			case hasOp && !strings.Contains(base, "/"):
				found["operator-on-set-or-as-member"] = true
			case hasOp && !strings.Contains(op, "-") && op != "+":
				found["single-length-range"] = true
			case err == nil && (n.String() == "AS-ANY" || n.String() == "RS-ANY"):
				found["as-any"] = true
			case err == nil && class == types.ClassAsSet && n.Class() == types.ClassRouteSet:
				found["route-set-in-as-set"] = true
			}
			if err == nil && !hasOp {
				walk(base, n.Class())
			}
		}
	}
	n, _ := types.ParseSetName(name)
	walk(name, n.Class())
	var out []string
	for f := range found {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
