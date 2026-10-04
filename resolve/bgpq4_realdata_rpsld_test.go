package resolve_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/resolve/internal/filtergen"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestRpsldMatchesRpslqRealData (opt-in: RPSL_REALDATA=<the directory
// scripts/fetch-irr-dumps.sh fills, or its ripe/ directory> and bgpq4 1.16
// installed) serves RIPE's as-set, route-set, aut-num, route and route6 dumps
// with rpsld — one registry, RIPE, as rpsld's dump loader builds it — and holds
// bgpq4's lists against it to what rpslq --dump -S RIPE writes over the same
// dumps (spec §7), for the largest sets and a seeded sample of each class: an
// as-set's AS numbers and both families' prefixes, a route-set's prefixes, as
// bgpq4 -j writes them, byte for byte. A difference, or an rpslq refusal, is
// allowed only where the set's closure holds a known divergence
// (testdata/bgpq4/divergences.md: rpsld answers as IRRd does, and rpslq is the
// engine); a set with more prefixes than the engine's MaxPrefixes is counted
// and not compared, as TestBgpq4RealData does. rpslq runs first, and bgpq4
// only on a list rpslq wrote within that cap: bgpq4 has no cap, and lists a
// range's every prefix (RIPE's RS-MOUATS-V6-ROUTES, 2607:f150:ffff::/48^48-128,
// held it for ten minutes and gigabytes). The counts are logged.
//
// The process holds only rpsld's registry and the dump backend rpslq reads:
// each dump is read and each object decoded once, into both. rpslq runs in
// this process (rpslq.RunWith), and one bgpq4 at a time. RPSL_REALDATA_LARGEST
// and RPSL_REALDATA_SAMPLE (default 10 and 150, per class) size the pick, for a
// trial on fewer sets. rpslq's lists of one set share a five-minute deadline
// (a set past it is counted, not compared); at the defaults the run takes
// several minutes, so run it with -timeout 30m.
func TestRpsldMatchesRpslqRealData(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	if st, err := os.Stat(filepath.Join(dir, "ripe")); err == nil && st.IsDir() {
		dir = filepath.Join(dir, "ripe")
	}
	needBgpq4Output(t) // the lists are compared as text
	largest, sample := envCount(t, "RPSL_REALDATA_LARGEST", 10), envCount(t, "RPSL_REALDATA_SAMPLE", 150)

	begin := time.Now()
	// rpsld's registry: the objects whose source: is RIPE, in a Corpus that
	// keeps policy (internal/rpsld's loadDump). rpslq's backend: what
	// backend.Open builds for --dump … -S RIPE — a DumpLoader puts every
	// decoded object into its Corpus, served as SourceOf("RIPE").
	served := &resolve.Corpus{KeepPolicy: true}
	dump := &resolve.Corpus{}
	type sized struct {
		name string
		n    int
	}
	var asSets, routeSets []sized
	objects, others := 0, 0
	for _, class := range []string{"as-set", "route-set", "aut-num", "route", "route6"} {
		err := backend.ReadInput(filepath.Join(dir, "ripe.db."+class+".gz"), func(r io.Reader) error {
			for o, ds := range rpsl.Parse(r) {
				for _, d := range ds {
					if d.Rule == "rpsl/read-error" {
						return errors.New(d.Message)
					}
				}
				if o == nil || o.Class() == "" {
					continue
				}
				objects++
				obj, _ := object.Decode(o)
				dump.Put(obj)
				if a, ok := o.GetFirst("source"); ok && strings.ToUpper(strings.TrimSpace(a.Value)) == "RIPE" {
					served.Put(obj)
				} else {
					others++
				}
				switch s := obj.(type) {
				case object.AsSet:
					asSets = append(asSets, sized{s.Name.String(), len(s.SetMembers())})
				case object.RouteSet:
					routeSets = append(routeSets, sized{s.Name.String(), len(s.SetMembers())})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	reg, err := irrdq.NewRegistry("RIPE", 0, served)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := irrdq.NewSnapshot([]*irrdq.Registry{reg}, irrdq.SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	addr := rpsldtest.Serve(t, snap)
	be := &backend.Backend{
		Src:      dump.SourceOf("RIPE"),
		Restrict: func(registry string) resolve.PolicySource { return dump.SourceOf(registry) },
		Close:    func() {},
	}
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("RIPE: %d objects read (%d as-sets, %d route-sets; %d of another source left out of rpsld's registry) in %v; heap %d MB",
		objects, len(asSets), len(routeSets), others, time.Since(begin).Round(time.Second), m.HeapAlloc>>20)

	// The largest sets by direct member count, then a seeded sample.
	pick := func(sets []sized) []string {
		sort.Slice(sets, func(i, j int) bool {
			return sets[i].n > sets[j].n || sets[i].n == sets[j].n && sets[i].name < sets[j].name
		})
		var out []string
		for _, s := range sets[:min(largest, len(sets))] {
			out = append(out, s.name)
		}
		r := rand.New(rand.NewPCG(1, 2))
		for k := 0; k < sample && len(sets) > 0; k++ {
			if name := sets[r.IntN(len(sets))].name; !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
		return out
	}
	picked := append(pick(asSets), pick(routeSets)...)

	session := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
	session.Do(context.Background(), "!!")
	members := func(set string) ([]string, bool) {
		r, _ := session.Do(context.Background(), "!i"+set)
		var b strings.Builder
		r.WriteTo(&b)
		head, rest, _ := strings.Cut(b.String(), "\n")
		if !strings.HasPrefix(head, "A") {
			return nil, false
		}
		n, err := strconv.Atoi(head[1:])
		if err != nil || n > len(rest) {
			t.Fatalf("!i%s: not an IRRd answer: %.200q", set, b.String())
		}
		return strings.Fields(rest[:n]), true
	}

	var same, differ, refused, tooLarge, operator, timedOut int
	why := map[string]int{}
	for _, name := range picked {
		setBegin := time.Now()
		// rpslq's lists of one set share a deadline, so that one set cannot
		// hold the run past go test's timeout; a set past it is counted.
		setCtx, cancel := context.WithTimeout(context.Background(), setDeadline)
		reasons := closureDivergences(members, name)
		lists := [][]string{{"-4"}, {"-6"}}
		if mustSet(t, name).Class() == types.ClassAsSet {
			lists = append([][]string{{"-t"}}, lists...)
		}
		outcome := "same"
	lists:
		for _, list := range lists {
			q := append(append(append([]string(nil), bgpq4Args...), list...), name)
			// rpslq first: bgpq4 lists every prefix a range holds, without
			// end (a /48^48-128 is 2^80 of them), so it runs only on a list
			// rpslq built under the cap TestBgpq4RealData compares under.
			var out, errs bytes.Buffer
			code := rpslq.RunWith(setCtx, q, &out, &errs, be)
			switch {
			case setCtx.Err() != nil:
				outcome = "timeout"
				t.Logf("%s %v: rpslq still running after %v, not compared", name, list, setDeadline)
				break lists
			case code != 0 && (strings.Contains(errs.String(), "exceeds "+resolve.LimitPrefixes.String()) ||
				strings.Contains(errs.String(), filtergen.ErrTooManyPrefixes.Error())):
				outcome = "too large"
				t.Logf("%s %v: over a prefix limit, not compared: %s", name, list, strings.TrimSpace(errs.String()))
				break lists
			case code != 0 && len(reasons) > 0:
				outcome = "refused"
				t.Logf("%s %v: rpslq refuses it, as expected (%s): %s", name, list, strings.Join(reasons, ", "),
					strings.TrimSpace(errs.String()))
				break lists
			case code != 0:
				outcome = "failed"
				t.Errorf("%s %v: rpslq exits %d with no known divergence in its closure: %s", name, list, code,
					strings.TrimSpace(errs.String()))
				break lists
			case strings.Count(out.String(), "\n") > maxComparedEntries:
				outcome = "too large"
				t.Logf("%s %v: rpslq lists %d entries, over %d: not compared", name, list,
					strings.Count(out.String(), "\n"), maxComparedEntries)
				break lists
			}
			if slices.Contains(reasons, "operator-on-set-or-as-member") {
				// rpslq applies the operator, which may narrow a range;
				// bgpq4 drops it and may list far more than rpslq did.
				outcome = "operator"
				t.Logf("%s %v: a range operator on a set or AS member in its closure; bgpq4 is not run on it", name, list)
				break lists
			}
			want, err := bgpq4Text(append([]string{"-h", addr, "-S", "RIPE"}, q...))
			switch {
			case err != nil:
				outcome = "failed"
				t.Errorf("%s: %v", name, err)
				break lists
			case out.String() != want && len(reasons) > 0:
				outcome = "differ"
				t.Logf("%s %v differs, as expected: %s", name, list, strings.Join(reasons, ", "))
				break lists
			case out.String() != want:
				outcome = "failed"
				t.Errorf("%s %v: rpslq --dump and bgpq4 against rpsld differ, with no known divergence in its closure: %s",
					name, list, firstDifference(out.String(), want))
				break lists
			}
		}
		switch outcome {
		case "same":
			same++
		case "differ", "refused":
			if outcome == "differ" {
				differ++
			} else {
				refused++
			}
			for _, r := range reasons {
				why[r]++
			}
		case "too large":
			tooLarge++
		case "operator":
			operator++
		case "timeout":
			timedOut++
		}
		cancel()
		if took := time.Since(setBegin); took > 30*time.Second {
			t.Logf("%s: %v", name, took.Round(time.Second))
		}
	}
	var byReason []string
	for r, n := range why {
		byReason = append(byReason, fmt.Sprintf("%s %d", r, n))
	}
	sort.Strings(byReason)
	runtime.ReadMemStats(&m)
	t.Logf("rpslq --dump vs bgpq4 against rpsld: %d sets picked; %d the same; %d differ and %d are refused by rpslq where "+
		"a known divergence explains it (sets by divergence in the closure: %s); %d over a prefix limit, not compared; "+
		"%d with a range operator on a set or AS member in the closure, not compared; %d past rpslq's %v deadline, not compared; "+
		"%v in all, heap %d MB",
		len(picked), same, differ, refused, strings.Join(byReason, ", "), tooLarge, operator, timedOut, setDeadline,
		time.Since(begin).Round(time.Second), m.HeapAlloc>>20)
}

// setDeadline bounds rpslq's lists of one set in TestRpsldMatchesRpslqRealData.
const setDeadline = 5 * time.Minute

// envCount reads a non-negative count from the environment, def when unset.
func envCount(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		t.Fatalf("%s=%q: want a count", name, v)
	}
	return n
}

// maxComparedEntries is the longest list TestRpsldMatchesRpslqRealData hands bgpq4,
// the engine's default MaxPrefixes, which TestBgpq4RealData compares under:
// bgpq4's memory grows with the list, and it holds no cap of its own.
const maxComparedEntries = 1 << 20

// bgpq4Text runs bgpq4 with a five-minute bound and returns what it writes to
// stdout.
func bgpq4Text(args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bgpq4", args...).Output()
	if err != nil {
		return "", fmt.Errorf("bgpq4 %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// firstDifference describes where two texts first differ, without printing
// lists of megabytes.
func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < max(len(g), len(w)); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("rpslq %d lines, bgpq4 %d; line %d: rpslq %q, bgpq4 %q", len(g), len(w), i+1, gl, wl)
		}
	}
	return "no difference"
}

// closureDivergences walks everything a set can reach through members — a
// set's members as IRRd's "!i" lists them: rpsld's own here, irrtest's for
// TestBgpq4RealData — following every set name as bgpq4 and IRRd would, and
// names the known divergences it meets.
func closureDivergences(members func(set string) ([]string, bool), name string) []string {
	found := map[string]bool{}
	seen := map[string]bool{}
	var walk func(set string, class types.SetClass)
	walk = func(set string, class types.SetClass) {
		if seen[strings.ToUpper(set)] {
			return
		}
		seen[strings.ToUpper(set)] = true
		ms, ok := members(set)
		if !ok {
			return
		}
		for _, m := range ms {
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
