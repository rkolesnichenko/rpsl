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
// is a failure. The report counts clauses, Undecided terms by cause,
// failures by kind, and renders/refusals by vendor and cause.
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
				if peers := namedPeers(an, 5); len(peers) > 0 {
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
	start := time.Now()
	for i := 0; i < len(targets); i += step {
		tg := targets[i]
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
					switch {
					case err == nil:
						stats["evaluated"]++
						stats["clauses"] += len(p.Clauses)
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
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-60s %d\n", k, stats[k])
	}
	t.Logf("%d aut-nums sampled of %d, in %s:\n%s", (len(targets)+step-1)/step, len(targets), time.Since(start).Round(time.Second), b.String())
}

// namedPeers returns up to n AS numbers the aut-num's import: and export:
// peerings name directly, in order.
func namedPeers(an *object.AutNum, n int) []types.ASN {
	seen := map[types.ASN]bool{}
	var out []types.ASN
	var walk func(e policy.Expr)
	walk = func(e policy.Expr) {
		switch x := e.(type) {
		case policy.Factor:
			for _, pa := range x.Peers {
				if p, ok := pa.Peering.(policy.PeeringAS); ok {
					if a, ok := p.AS.(policy.ASNum); ok && !seen[a.AS] && len(out) < n {
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
