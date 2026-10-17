package resolve_test

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestRealDataPeval (opt-in: RPSL_REALDATA) evaluates RIPE's policies: for a
// sample of aut-nums, import and export toward each AS their policies name,
// in both families, over RIPE's dumps loaded with KeepPolicy. It also renders
// each evaluated policy for all four rtconfig vendors and counts refusals by
// cause. Nothing may panic or fail except by a limit, a timeout, a filter
// that cannot be normalized, or a construct a vendor cannot express
// (*rtconfig.UnsupportedError); a rendered configuration cfgsim cannot parse
// is a failure. A *resolve.AnySetError (a set reaching AS-ANY in filter
// position) is counted as "any set". RPSL_PEVAL_AS (comma-separated AS
// numbers) adds those aut-nums to the sample with every peer their
// policies name, and logs each of their sessions. The report counts
// clauses, Undecided terms by cause, failures by kind, renders/refusals by
// vendor and cause, and the AS-path regexps naming a set that reaches
// AS-ANY (a PathMatch with an ASNSet whose Any() is true).
func TestRealDataPeval(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ripe", "*.gz"))
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	type target struct {
		as    types.ASN
		peers []types.ASN
	}
	var targets []target
	forced := map[types.ASN]bool{}
	for _, f := range strings.Split(os.Getenv("RPSL_PEVAL_AS"), ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		as, err := types.ParseASN(f)
		if err != nil {
			if as, err = types.ParseASN("AS" + f); err != nil {
				t.Fatalf("RPSL_PEVAL_AS: %q: %v", f, err)
			}
		}
		forced[as] = true
	}
	for _, f := range files {
		base := filepath.Base(f)
		wanted := strings.Contains(base, ".route") || strings.Contains(base, "-set") ||
			strings.Contains(base, ".aut-num") || strings.Contains(base, ".inet-rtr")
		if strings.Count(base, ".") > 2 && !wanted {
			continue
		}
		read := func(fn func(o *object.AutNum)) {
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if fn == nil {
				if err := l.Read(zr); err != nil {
					t.Fatal(err)
				}
				return
			}
			for o := range rpsl.Parse(zr) {
				if obj, _ := rpsl.Decode(o); obj != nil {
					if an, ok := obj.(*object.AutNum); ok {
						fn(an)
					}
				}
			}
		}
		read(nil)
		if strings.Contains(base, ".aut-num") {
			read(func(an *object.AutNum) {
				n := 5
				if forced[an.AS] {
					n = 0 // every peer it names
				}
				if peers := namedPeers(an, n); len(peers) > 0 {
					targets = append(targets, target{an.AS, peers})
				}
			})
		}
	}
	if len(targets) == 0 {
		t.Skip("no RIPE aut-num dump under RPSL_REALDATA")
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].as < targets[j].as })
	step := max(1, len(targets)/300)
	v := &peval.Evaluator{Src: resolve.NewCache(l.Source(), 0)}
	gens := map[rtconfig.Vendor]*rtconfig.Generator{}
	for _, vendor := range rtconfig.Vendors() {
		gens[vendor] = &rtconfig.Generator{Vendor: vendor}
	}
	stats := map[string]int{}
	anyUses := map[string]bool{} // "ASn import|export #index" with a regexp naming a set reaching AS-ANY
	start := time.Now()
	// The forced aut-nums first, then the sample less them: each once.
	var order []target
	found := map[types.ASN]bool{}
	for _, tg := range targets {
		if forced[tg.as] {
			order = append(order, tg)
			found[tg.as] = true
		}
	}
	for as := range forced {
		if !found[as] {
			t.Errorf("RPSL_PEVAL_AS: AS%d is not a RIPE aut-num naming a peer", as)
		}
	}
	sampled := 0
	for i := 0; i < len(targets); i += step {
		if !forced[targets[i].as] {
			order = append(order, targets[i])
			sampled++
		}
	}
	for _, tg := range order {
		for _, peer := range tg.peers {
			for _, af := range families {
				for _, export := range []bool{false, true} {
					s := peval.Session{Local: tg.as, Peer: peer, AF: af}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					var p peval.Policy
					var err error
					if export {
						p, err = v.Export(ctx, s)
					} else {
						p, err = v.Import(ctx, s)
					}
					cancel()
					var tl *resolve.SetTooLargeError
					var ne *resolve.NotEnumerableError
					var ae *resolve.AnySetError
					if forced[tg.as] {
						dir := "import from"
						if export {
							dir = "export to"
						}
						if err != nil {
							t.Logf("forced AS%d %s AS%d %v: %v", tg.as, dir, peer, af, err)
						} else {
							t.Logf("forced AS%d %s AS%d %v: %d clauses, %d undecided, %d regexps naming a set reaching AS-ANY",
								tg.as, dir, peer, af, len(p.Clauses), len(p.Undecided), anySetPaths(p, nil))
						}
					}
					switch {
					case err == nil:
						stats["evaluated"]++
						stats["clauses"] += len(p.Clauses)
						kind := "import"
						if export {
							kind = "export"
						}
						stats["regexps naming a set reaching AS-ANY"] += anySetPaths(p, func(index int) {
							anyUses[fmt.Sprintf("AS%d %s #%d", tg.as, kind, index)] = true
						})
						for _, u := range p.Undecided {
							stats["undecided: "+u.Why]++
						}
						for _, vendor := range rtconfig.Vendors() {
							g := gens[vendor]
							write := g.WriteImport
							if export {
								write = g.WriteExport
							}
							var b strings.Builder
							err := write(&b, s, p)
							var ue *rtconfig.UnsupportedError
							switch {
							case errors.As(err, &ue):
								stats["refused: "+vendor.String()+": "+ue.Cause]++
							case err != nil:
								t.Errorf("AS%d toward AS%d %v export=%v, %v: %v", tg.as, peer, af, export, vendor, err)
							default:
								stats["rendered: "+vendor.String()]++
								if _, err := cfgsim.Parse(vendor.String(), b.String()); err != nil {
									t.Errorf("AS%d toward AS%d %v export=%v: our %v configuration does not parse: %v", tg.as, peer, af, export, vendor, err)
								}
							}
						}
					case errors.As(err, &tl):
						stats["limit: "+tl.Limit.String()]++
					case errors.As(err, &ne):
						stats["not enumerable: "+ne.Why]++
					case errors.As(err, &ae):
						stats["any set"]++
					case errors.Is(err, context.DeadlineExceeded):
						stats["timeout"]++
					case errors.Is(err, policy.ErrFlattenTooLarge):
						stats["flatten too large"]++
					default:
						t.Errorf("AS%d toward AS%d %v export=%v: %v", tg.as, peer, af, export, err)
					}
				}
			}
		}
	}
	stats["any set"] += 0 // reported even when none
	stats["regexps naming a set reaching AS-ANY"] += 0
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-60s %d\n", k, stats[k])
	}
	t.Logf("%d aut-nums sampled of %d (and %d forced), in %s:\n%s", sampled, len(targets), len(order)-sampled, time.Since(start).Round(time.Second), b.String())
	uses := make([]string, 0, len(anyUses))
	for u := range anyUses {
		uses = append(uses, u)
	}
	sort.Strings(uses)
	t.Logf("attributes with a regexp naming a set reaching AS-ANY (%d): %s", len(uses), strings.Join(uses, ", "))
}

// anySetPaths counts the AS-path tests in p's clauses that name a set
// reaching AS-ANY (an ASNSet whose Any() is true), calling at, when not
// nil, with each such clause's attribute index.
func anySetPaths(p peval.Policy, at func(index int)) int {
	n := 0
	for _, cl := range p.Clauses {
		for _, cj := range cl.Filter.Conjuncts {
			for _, pm := range cj.Paths {
				for _, set := range pm.Sets {
					if set.Any() {
						n++
						if at != nil {
							at(cl.Index)
						}
						break
					}
				}
			}
		}
	}
	return n
}

// namedPeers returns up to n AS numbers (all of them when n is 0) the
// aut-num's import: and export: peerings name directly, in order.
func namedPeers(an *object.AutNum, n int) []types.ASN {
	seen := map[types.ASN]bool{}
	var out []types.ASN
	var walk func(e policy.Expr)
	walk = func(e policy.Expr) {
		switch x := e.(type) {
		case policy.Factor:
			for _, pa := range x.Peers {
				if p, ok := pa.Peering.(policy.PeeringAS); ok {
					if a, ok := p.AS.(policy.ASNum); ok && !seen[a.AS] && (n == 0 || len(out) < n) {
						seen[a.AS] = true
						out = append(out, a.AS)
					}
				}
			}
		case policy.ExprList:
			for _, sub := range x.Exprs {
				walk(sub)
			}
		case policy.Except:
			walk(x.Left)
			walk(x.Right)
		case policy.Refine:
			walk(x.Left)
			walk(x.Right)
		}
	}
	for _, imp := range an.Imports {
		walk(imp.Expr)
	}
	for _, exp := range an.Exports {
		walk(exp.Expr)
	}
	return out
}
