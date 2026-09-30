package resolve_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/types"
)

// NormalizeFilter against IRRToolSet's peval, on the filters peval gets
// right (spec §3): prefix lists, bare AS numbers, AND, OR, and NOT over prefix
// lists — IPv4 only, since peval reads a filter without an afi clause as
// ipv4.unicast. Both query the same irrtest server; peval's answer is its
// enumerated prefixes, ours the one pure conjunct's ranges, materialized. The
// IRRs are compat ones: no range operators on set members, and no AS-ANY.
// peval runs from PATH with its server in the environment, because the
// Homebrew arm64 build ignores its command-line options.
//
// as-set/route-set *names* are not compared here (see pevalSafe's "set"
// case): this generator's sets routinely carry a missing, wrong-class, or
// junk member (by design — other tests hold the engine's own handling of
// those to the model), and peval substitutes 0.0.0.0/0 for whatever it
// cannot resolve inside a set's membership (D2), the same bug the compat
// model's disabled member-level range operators were meant to dodge. Applying
// an outer range operator to that substituted 0.0.0.0/0 then enumerates the
// entire address space at the operator's window — hundreds of megabytes of
// output that never finishes in test time (see divergences.md). A bare AS
// number never triggers this: it resolves straight to "-K -r -i origin ASn",
// with no "!i" membership walk to corrupt.
func TestPevalMatchesIRRToolSet(t *testing.T) {
	bin, err := exec.LookPath("peval")
	if err != nil {
		t.Skip("IRRToolSet's peval is not installed")
	}
	ctx := context.Background()
	for seed := uint64(0); seed < 40; seed++ {
		r := rand.New(rand.NewPCG(seed, 19))
		m := randomModel(r, true)
		g := newFilterGen(r, newOracle(m))
		g.v4only = true
		texts := m.texts(r)
		db := irrtest.New(texts...).WithSources("RIPE", "RADB")
		addr := db.IRRd(t)
		host, port, _ := net.SplitHostPort(addr)
		ir := &irrd.Source{Addr: addr, Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		e := &resolve.Expander{Src: ir, AFI: types.AFIv4}
		for i := 0; i < 10; i++ {
			f := pevalFilter(g, 2)
			text := f.text()
			nf, err := e.NormalizeFilter(ctx, mustParseFilter(t, text, text))
			if err != nil {
				t.Fatalf("seed %d: %s: %v", seed, text, err)
			}
			// NormalizeFilter treats NOT as symbolic unconditionally (design
			// §4.2), even over a plain prefix list, so it is never folded
			// into a single literal alongside a positive term the way two
			// positive enumerable terms are: "NOT {p} OR (ANY AND AS1)" comes
			// back as two conjuncts. Both sides are still pevalSafe-approved
			// literals, so the filter as a whole is exactly their union.
			seen := map[string]bool{}
			var ours []string
			for _, c := range nf.Conjuncts {
				for _, p := range materialize(c.Prefixes.List(), c.NotPrefixes.List()) {
					if !seen[p] {
						seen[p] = true
						ours = append(ours, p)
					}
				}
			}
			slices.Sort(ours)
			// A per-invocation deadline guards against a peval shape we have
			// not seen: peval's default (non-compressed; the Homebrew build
			// ignores -compressed) mode enumerates every concrete prefix, and
			// a shape that reads as a wide or unbounded range can run for a
			// very long time rather than erroring (see D2 above). 10s is
			// generous next to peval's usual 7-40ms (spec §3).
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			cmd := exec.CommandContext(cctx, bin)
			cmd.Env = append(os.Environ(), "IRR_HOST="+host, "IRR_PORT="+port, "IRR_SOURCES=RIPE,RADB")
			cmd.Stdin = strings.NewReader(text + "\n")
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err = cmd.Run()
			cancel()
			if err != nil {
				raw := out.String()
				if len(raw) > 2000 {
					raw = raw[:2000] + "…"
				}
				t.Fatalf("seed %d: peval %s: %v\n%s", seed, text, err, raw)
			}
			theirs := pevalPrefixes(out.String())
			if !slices.Equal(ours, theirs) {
				t.Errorf("seed %d: %s:\n  ours  %v\n  peval %v\n  raw   %s", seed, text, ours, theirs, strings.TrimSpace(out.String()))
			}
		}
		ir.Close()
	}
}

// pevalFilter draws a filter from what peval evaluates correctly.
func pevalFilter(g *filterGen, depth int) *mFilter {
	for {
		f := g.filter(depth)
		if pevalSafe(f, false) {
			return f
		}
	}
}

func pevalSafe(f *mFilter, underNot bool) bool {
	switch f.kind {
	case "pfx":
		return true
	case "any":
		return !underNot
	case "as":
		return !underNot // D1: peval's NOT over AS-derived terms is wrong
	case "set":
		// D2: peval substitutes 0.0.0.0/0 for a route-set/as-set member it
		// cannot resolve (missing, wrong-class, or junk — not only one
		// carrying a range operator, as originally pinned), and an outer
		// range operator on the set then enumerates that substituted
		// 0.0.0.0/0 without bound. This compat model still draws such
		// members regardless of range-operator suppression (only member-
		// level operators are disabled), so no set name is safe to compare.
		return false
	case "not":
		return pevalSafe(f.subs[0], true)
	case "and", "or":
		return pevalSafe(f.subs[0], underNot) && pevalSafe(f.subs[1], underNot)
	}
	return false // regexps, communities, PeerAS, filter-sets: not compared here
}

var pevalRange = regexp.MustCompile(`[0-9a-fA-F:.]+/\d+(\^[-+]|\^\d+(-\d+)?)?`)

// everyPrefix is 0.0.0.0/0 and ::/0, the two ranges "ANY" and an empty
// "NOT{...}" denote.
func everyPrefix() []types.PrefixRange {
	var all []types.PrefixRange
	for _, s := range []string{"0.0.0.0/0^0-32", "::/0^0-128"} {
		pr, _ := types.ParsePrefixRange(s)
		all = append(all, pr)
	}
	return all
}

// pevalPrefixes reads peval's output — "({p/l^n-m, …})", "ANY", "NOT ANY",
// and "(NOT{p/l^n-m, …})" for a co-finite answer (peval cannot enumerate an
// unbounded complement, so it prints the excluded ranges instead; RFC 2622
// gives NOT no finite denotation on its own, and this is the correct value,
// not a divergence) — as the sorted prefixes of the model's universes it
// denotes.
func pevalPrefixes(out string) []string {
	out = strings.TrimSpace(out)
	if strings.Contains(out, "NOT ANY") || out == "" {
		return nil
	}
	negated := strings.Contains(out, "NOT{")
	var ranges []types.PrefixRange
	if strings.Contains(out, "ANY") {
		ranges = append(ranges, everyPrefix()...)
	}
	for _, s := range pevalRange.FindAllString(out, -1) {
		if pr, err := types.ParsePrefixRange(s); err == nil {
			ranges = append(ranges, pr)
		}
	}
	if negated {
		return materialize(everyPrefix(), ranges)
	}
	return materialize(ranges, nil)
}

// materialize lists the IPv4 prefixes of the model's universe that lie in
// one of in and none of out, sorted: what two answers must agree on.
func materialize(in, out []types.PrefixRange) []string {
	var got []string
	for _, p := range samplePrefixes {
		if !p.Addr().Is4() {
			continue
		}
		inside := slices.ContainsFunc(in, func(r types.PrefixRange) bool { return r.Contains(p) })
		excluded := slices.ContainsFunc(out, func(r types.PrefixRange) bool { return r.Contains(p) })
		if inside && !excluded {
			got = append(got, p.String())
		}
	}
	slices.Sort(got)
	return got
}
