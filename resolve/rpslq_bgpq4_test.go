package resolve_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslq"
	"github.com/rkolesnichenko/rpsl/types"
)

// rpslqFormats are the output flag sets rpslq and bgpq4 share; each is run for
// prefix lists of both families, and as an AS list where the format has one.
var rpslqFormats = [][]string{nil, {"-j"}, {"-b"}, {"-J"}}

// rpslq writes what bgpq4 writes: the same flags against the same server give
// the same text, byte for byte, over the random IRRs the engine's own
// differential uses (in bgpq4-compatible mode), with bgpq4's special AS
// numbers dropped and kept (-p).
func TestRpslqMatchesBgpq4(t *testing.T) {
	needBgpq4Output(t)
	for seed := uint64(0); seed < 20; seed++ {
		r := rand.New(rand.NewPCG(seed, 11))
		m := randomModel(r, true)
		addr := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB").IRRd(t)
		var tops []string
		for name := range newOracle(m).sets {
			tops = append(tops, name)
		}
		sort.Strings(tops)
		for _, top := range tops {
			for _, special := range [][]string{nil, {"-p"}} {
				for _, format := range rpslqFormats {
					var runs [][]string
					for _, fam := range []string{"-4", "-6"} {
						runs = append(runs, append(append(append([]string{fam}, special...), format...), top))
					}
					if setClass(top) == types.ClassAsSet && (len(format) == 1 && (format[0] == "-j" || format[0] == "-b")) {
						runs = append(runs, append(append(append([]string{"-t"}, special...), format...), top))
					}
					for _, args := range runs {
						base := []string{"-h", addr, "-S", modelSources, "-L", "64"}
						want := runBgpq4Text(t, append(append([]string(nil), base...), args...))
						var got, errs bytes.Buffer
						if code := rpslq.Run(context.Background(), append(append([]string(nil), base...), args...), &got, &errs); code != 0 {
							t.Fatalf("seed %d: rpslq %v: exit %d: %s", seed, args, code, errs.String())
						}
						if got.String() != want {
							t.Fatalf("seed %d: rpslq %v differs from bgpq4:\nrpslq:\n%s\nbgpq4:\n%s", seed, args, got.String(), want)
						}
					}
				}
			}
		}
	}
}

// rpslq --server-expand writes what plain bgpq4 writes: without -L, bgpq4 asks the server
// to expand an as-set ("!a"), and so does rpslq --server-expand, so the two agree on the
// server's answer — its recursion, special AS numbers kept — byte for byte.
func TestRpslqServerSideMatchesBgpq4(t *testing.T) {
	needBgpq4Output(t)
	for seed := uint64(0); seed < 20; seed++ {
		r := rand.New(rand.NewPCG(seed, 13))
		m := randomModel(r, true)
		db := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB")
		addr := db.IRRd(t)
		var tops []string
		for name := range newOracle(m).sets {
			tops = append(tops, name)
		}
		sort.Strings(tops)
		for _, top := range tops {
			for _, format := range rpslqFormats {
				for _, fam := range []string{"-4", "-6"} {
					args := append(append([]string{fam}, format...), top)
					base := []string{"-h", addr, "-S", modelSources}
					want := runBgpq4Text(t, append(append([]string(nil), base...), args...))
					var got, errs bytes.Buffer
					if code := rpslq.Run(context.Background(), append(append(append([]string(nil), base...), "--server-expand"), args...), &got, &errs); code != 0 {
						t.Fatalf("seed %d: rpslq --server-expand %v: exit %d: %s", seed, args, code, errs.String())
					}
					if got.String() != want {
						t.Fatalf("seed %d: rpslq --server-expand %v differs from bgpq4:\nrpslq:\n%s\nbgpq4:\n%s", seed, args, got.String(), want)
					}
				}
			}
		}
		// bgpq4 took the "!a" path for the as-sets, as rpslq --server-expand did.
		used := false
		for _, cmd := range db.Commands() {
			used = used || strings.HasPrefix(cmd, "!a4") || strings.HasPrefix(cmd, "!a6")
		}
		if !used {
			t.Fatalf("seed %d: no \"!a\" query was sent", seed)
		}
	}
}

// runBgpq4Text runs bgpq4 and returns what it writes to stdout.
func runBgpq4Text(t *testing.T, args []string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bgpq4", args...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bgpq4 %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// Every vendor, kind and shape bgpq4 has, as flag sets.
var (
	bgpq4Vendors = [][]string{nil, {"-X"}, {"-j"}, {"-b"}, {"-J"}, {"-B"}, {"-e"}, {"-N"}, {"-n"}, {"-n2"},
		{"-K"}, {"-K7"}, {"-U"}, {"-u"}, {"-F", `%n/%l %a %A\n`}, {"-F", `%N %r %m %i %%`}}
	bgpq4Kinds  = [][]string{nil, {"-E"}, {"-z"}, {"-t"}, {"-f", "65002"}, {"-G", "65001"}, {"-H", "65003"}, {"-f", "7"}}
	bgpq4Shapes = [][]string{nil, {"-A"}, {"-R", "30"}, {"-r", "30"}, {"-A", "-R", "31"}, {"-s"}, {"-m", "30"},
		{"-l", "MY/TERM"}, {"-W", "2"}, {"-W", "0"}, {"-w"}, {"-a", "65009"}, {"-M", "community x"}}
)

// isASKind reports whether a kind is written from AS numbers.
func isASKind(kind []string) bool {
	return len(kind) > 0 && (kind[0] == "-t" || kind[0] == "-f" || kind[0] == "-G" || kind[0] == "-H")
}

// compareRpslq runs rpslq and bgpq4 with the same arguments: both must refuse
// them, or both write the same text, which it reports.
func compareRpslq(t *testing.T, label string, args []string) (wrote bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, bgpErr := exec.CommandContext(ctx, "bgpq4", args...).Output()
	var got, errs bytes.Buffer
	code := rpslq.Run(context.Background(), args, &got, &errs)
	switch {
	case bgpErr != nil && code == 0:
		t.Fatalf("%s: rpslq %v wrote a list where bgpq4 failed (%v):\n%s", label, args, bgpErr, got.String())
	case bgpErr == nil && code != 0:
		t.Fatalf("%s: rpslq %v: exit %d (%s) where bgpq4 wrote:\n%s", label, args, code, errs.String(), want)
	case code == 0 && got.String() != string(want):
		t.Fatalf("%s: rpslq %v differs from bgpq4:\nrpslq:\n%s\nbgpq4:\n%s", label, args, got.String(), want)
	}
	return code == 0
}

// rpslq writes what bgpq4 writes for every vendor, kind of list and shape,
// and refuses what bgpq4 refuses: the full matrix over one random IRR, and
// random combinations, bundled or not, over others.
func TestRpslqVendorsMatchBgpq4(t *testing.T) {
	needBgpq4Output(t)
	for seed := uint64(0); seed < 12; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		m := randomModel(r, true)
		addr := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB").IRRd(t)
		var asSets, routeSets []string
		for name, s := range newOracle(m).sets {
			if s.class == types.ClassAsSet {
				asSets = append(asSets, name)
			} else {
				routeSets = append(routeSets, name)
			}
		}
		sort.Strings(asSets)
		sort.Strings(routeSets)
		base := []string{"-h", addr, "-S", modelSources, "-L", "64", "-p"}
		wrote, refused := 0, 0
		run := func(fam string, vendor, kind, shape []string, bundle bool) {
			objs := append(append([]string(nil), asSets...), routeSets...)
			if isASKind(kind) {
				objs = asSets // bgpq4 quietly ignores what rpslq refuses here
			}
			if len(objs) == 0 {
				return
			}
			var flags []string
			switch {
			case bundle && len(vendor) == 1 && len(kind) == 1:
				// bgpq4's getopt reads "-6Jz" as -6 -J -z; so must rpslq.
				flags = []string{fam + vendor[0][1:] + kind[0][1:]}
			default:
				flags = append(append([]string{fam}, vendor...), kind...)
			}
			args := append(append(append(append([]string(nil), base...), flags...), shape...), objs[r.IntN(len(objs))])
			if compareRpslq(t, fmt.Sprintf("seed %d", seed), args) {
				wrote++
			} else {
				refused++
			}
		}
		defer func() {
			// Neither side of the comparison is vacuous: many lists are
			// written, and some combinations refused.
			if wrote < 25 || refused == 0 {
				t.Errorf("seed %d: %d lists written, %d refused", seed, wrote, refused)
			}
		}()
		if seed == 0 {
			for _, fam := range []string{"-4", "-6"} {
				for _, v := range bgpq4Vendors {
					for _, k := range bgpq4Kinds {
						for _, sh := range bgpq4Shapes {
							run(fam, v, k, sh, false)
						}
					}
				}
			}
			continue
		}
		for range 60 {
			// Mostly prefix lists, and IPv6 only where it applies, so that
			// most draws are lists rather than refusals.
			kind := []string(nil)
			if r.IntN(2) == 0 {
				kind = bgpq4Kinds[r.IntN(len(bgpq4Kinds))]
			}
			fam := "-4"
			if !isASKind(kind) && r.IntN(2) == 0 {
				fam = "-6"
			}
			shape := bgpq4Shapes[r.IntN(len(bgpq4Shapes))]
			if r.IntN(3) == 0 {
				shape = bgpq4Shapes[r.IntN(5)] // plain, -A, -R, -r, -A -R
			}
			run(fam, bgpq4Vendors[r.IntN(len(bgpq4Vendors))], kind, shape, r.IntN(2) == 0)
		}
	}
}

// EXCEPT leaves the same sets and AS numbers out of an as-set's expansion as
// bgpq4's stoplist does, for prefix lists and AS lists alike.
func TestRpslqExceptMatchesBgpq4(t *testing.T) {
	needBgpq4Output(t)
	compared, changed := 0, 0
	for seed := uint64(0); seed < 30; seed++ {
		r := rand.New(rand.NewPCG(seed, 19))
		m := randomModel(r, true)
		addr := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB").IRRd(t)
		var asSets []string
		for name, s := range newOracle(m).sets {
			if s.class == types.ClassAsSet {
				asSets = append(asSets, name)
			}
		}
		sort.Strings(asSets)
		for _, top := range asSets {
			var except []string
			for _, name := range asSets {
				if r.IntN(3) == 0 {
					except = append(except, name)
				}
			}
			for a := firstAS; a < firstAS+4; a++ {
				if r.IntN(3) == 0 {
					except = append(except, fmt.Sprintf("AS%d", a))
				}
			}
			if len(except) == 0 {
				except = []string{"AS-NOT-THERE"}
			}
			for _, flags := range [][]string{{"-4"}, {"-6"}, {"-t", "-j"}, {"-4", "-A", "-b"}} {
				args := append(append([]string{"-h", addr, "-S", modelSources, "-p"}, flags...), top, "EXCEPT")
				if compareRpslq(t, fmt.Sprintf("seed %d", seed), append(args, except...)) {
					compared++
					var with, without bytes.Buffer
					rpslq.Run(context.Background(), append(args, except...), &with, io.Discard)
					rpslq.Run(context.Background(), args[:len(args)-1], &without, io.Discard)
					if with.String() != without.String() {
						changed++
					}
				}
			}
		}
	}
	if compared < 100 || changed < 30 {
		t.Errorf("%d lists compared, %d changed by EXCEPT", compared, changed)
	}
}

// SOURCE::SET looks the set up in one registry and what it reaches in the
// default sources, as bgpq4 does (without -L or EXCEPT): over random IRRs that define sets in both
// registries, as-sets named with the registry that holds them, under several
// -S, for prefix lists and AS lists.
func TestRpslqSourcePrefixMatchesBgpq4(t *testing.T) {
	needBgpq4Output(t)
	compared := 0
	for seed := uint64(0); seed < 30; seed++ {
		r := rand.New(rand.NewPCG(seed, 23))
		m := randomModel(r, true)
		addr := irrtest.New(m.texts(r)...).WithSources("RIPE", "RADB").IRRd(t)
		listed := map[string]bool{} // names some set lists as a member
		for _, set := range m.sets {
			for _, mm := range set.members {
				if mm.kind == "set" {
					listed[mm.set] = true
				}
			}
		}
		for _, set := range m.sets {
			if set.class != types.ClassAsSet {
				continue // bgpq4 then expands route-sets shallowly: "source-route-set"
			}
			if listed[set.name] {
				continue // a way back to the top's name: "source-cycle"
			}
			top := set.source + "::" + set.name
			for _, sources := range []string{"RIPE,RADB", "RADB", "RIPE"} {
				for _, flags := range [][]string{{"-4"}, {"-6"}, {"-t", "-j"}} {
					// No -L: with it, bgpq4 ignores SOURCE:: ("source-with-depth").
					args := append(append([]string{"-h", addr, "-S", sources, "-p"}, flags...), top)
					if compareRpslq(t, fmt.Sprintf("seed %d", seed), args) {
						compared++
					}
				}
			}
		}
	}
	if compared < 100 {
		t.Errorf("only %d lists compared", compared)
	}
}

// Where rpslq and bgpq4 knowingly differ over SOURCE:: (divergences.md),
// each side's answer, pinned. Both registries hold AS-TOP; RIPE's lists
// itself.
func TestRpslqSourceDivergences(t *testing.T) {
	needBgpq4Output(t)
	addr := irrtest.New(
		"as-set: AS-TOP\nmembers: AS65001, AS-TOP\nsource: RIPE\n",
		"as-set: AS-TOP\nmembers: AS65002\nsource: RADB\n",
		"route-set: RS-X\nmembers: 192.0.2.0/24, RS-Y\nsource: RADB\n",
		"route-set: RS-Y\nmembers: 198.51.100.0/24\nsource: RADB\n",
		"route: 10.1.0.0/24\norigin: AS65001\nsource: RADB\n",
		"route: 203.0.113.0/24\norigin: AS65003\nsource: RIPE\n",
	).WithSources("RIPE", "RADB").IRRd(t)
	base := []string{"-h", addr, "-S", "RADB", "-p"}
	for _, c := range []struct {
		id         string
		args       []string
		rpslq, bgp string
	}{
		// RIPE's AS-TOP lists AS-TOP: a cycle to the engine; to bgpq4, which
		// has not marked the top as seen, a set to look up in the default
		// sources — RADB's AS-TOP.
		{"source-cycle", []string{"-tj", "RIPE::AS-TOP"}, `{"NN": [ 65001 ]}`, `{"NN": [ 65001,65002 ]}`},
		// With -L (or EXCEPT), bgpq4 looks the top up in the default sources.
		{"source-with-depth", []string{"-L", "8", "-tj", "RIPE::AS-TOP"}, `{"NN": [ 65001 ]}`, `{"NN": [ 65002 ]}`},
		// Once SOURCE:: is used, bgpq4 asks for every route-set with "!i"
		// rather than "!i…,1", and keeps only its prefix members.
		{"source-route-set", []string{"-F", `%n/%l\n`, "RS-X"}, "192.0.2.0/24 198.51.100.0/24", "192.0.2.0/24 198.51.100.0/24"},
		{"source-route-set", []string{"-F", `%n/%l\n`, "RIPE::AS65003", "RS-X"},
			"192.0.2.0/24 198.51.100.0/24 203.0.113.0/24", "192.0.2.0/24"},
		// bgpq4 cannot read SOURCE:: on an AS number, and drops it.
		{"source-as-number", []string{"-F", `%n/%l\n`, "RIPE::AS65003"}, "203.0.113.0/24", ""},
	} {
		args := append(append([]string(nil), base...), c.args...)
		var got, errs bytes.Buffer
		if code := rpslq.Run(context.Background(), args, &got, &errs); code != 0 {
			t.Fatalf("%s: rpslq exit %d: %s", c.id, code, errs.String())
		}
		if g := strings.Join(strings.Fields(got.String()), " "); g != c.rpslq {
			t.Errorf("%s %v: rpslq %q, pinned %q", c.id, c.args, g, c.rpslq)
		}
		if g := strings.Join(strings.Fields(runBgpq4Text(t, args)), " "); g != c.bgp {
			t.Errorf("%s %v: bgpq4 %q, pinned %q", c.id, c.args, g, c.bgp)
		}
	}
}

// Where rpslq and bgpq4 knowingly differ (testdata/bgpq4/divergences.md,
// "rpslq"), each side's answer, pinned.
func TestRpslqKnownDivergences(t *testing.T) {
	needBgpq4Output(t)
	addr := irrtest.New(
		"route-set: RS-TOP\nmembers: 192.0.2.0/24, RS-BAD, AS-BAD, 10.0.0.0/30^+\nsource: RIPE\n",
		"route-set: RS-BAD\nmembers: 198.51.100.0/24\nsource: RIPE\n",
		"as-set: AS-BAD\nmembers: AS65001\nsource: RIPE\n",
		"route: 203.0.113.0/24\norigin: AS65001\nsource: RIPE\n",
	).WithSources("RIPE").IRRd(t)
	base := []string{"-h", addr, "-S", "RIPE", "-p", "-F", `%n/%l\n`}
	for _, c := range []struct {
		id         string
		args       []string
		rpslq, bgp string
	}{
		{"except-in-route-set", []string{"RS-TOP", "EXCEPT", "RS-BAD", "AS-BAD"},
			"10.0.0.0/30 10.0.0.0/31 10.0.0.0/32 10.0.0.1/32 10.0.0.2/31 10.0.0.2/32 10.0.0.3/32 192.0.2.0/24",
			"10.0.0.0/30 10.0.0.0/31 10.0.0.0/32 10.0.0.1/32 10.0.0.2/31 10.0.0.2/32 10.0.0.3/32 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24"},
		{"max-length-full", []string{"-m", "32", "RS-BAD", "10.0.0.0/30^+"},
			"10.0.0.0/30 10.0.0.0/31 10.0.0.0/32 10.0.0.1/32 10.0.0.2/31 10.0.0.2/32 10.0.0.3/32 198.51.100.0/24",
			"10.0.0.0/30 198.51.100.0/24"},
	} {
		args := append(append([]string(nil), base...), c.args...)
		var got, errs bytes.Buffer
		if code := rpslq.Run(context.Background(), args, &got, &errs); code != 0 {
			t.Fatalf("%s: rpslq exit %d: %s", c.id, code, errs.String())
		}
		if g := strings.Join(strings.Fields(got.String()), " "); g != c.rpslq {
			t.Errorf("%s: rpslq %q, pinned %q", c.id, g, c.rpslq)
		}
		if g := strings.Join(strings.Fields(runBgpq4Text(t, args)), " "); g != c.bgp {
			t.Errorf("%s: bgpq4 %q, pinned %q", c.id, g, c.bgp)
		}
	}
}

// -L counts levels as bgpq4 does — the named set is the first — and where
// the sets nest deeper, bgpq4 leaves the deeper ones out and rpslq fails
// ("depth-limit" in divergences.md).
func TestRpslqDepthLimit(t *testing.T) {
	needBgpq4Output(t)
	addr := irrtest.New(
		"as-set: AS-TOP\nmembers: AS1, AS-MID\nsource: RIPE\n",
		"as-set: AS-MID\nmembers: AS2, AS-LOW\nsource: RIPE\n",
		"as-set: AS-LOW\nmembers: AS3\nsource: RIPE\n",
	).WithSources("RIPE").IRRd(t)
	base := []string{"-h", addr, "-S", "RIPE", "-t", "-j"}
	// Deep enough: the two agree.
	compareRpslq(t, "-L 3", append(append([]string(nil), base...), "-L", "3", "AS-TOP"))
	// One level short: bgpq4 leaves AS-LOW out; rpslq refuses.
	args := append(append([]string(nil), base...), "-L", "2", "AS-TOP")
	if got := strings.Join(strings.Fields(runBgpq4Text(t, args)), " "); got != `{"NN": [ 1,2 ]}` {
		t.Errorf("bgpq4 -L 2: %q, pinned AS1 and AS2 only", got)
	}
	var out, errs bytes.Buffer
	if code := rpslq.Run(context.Background(), args, &out, &errs); code != 1 || !strings.Contains(errs.String(), "deeper than -L 2") {
		t.Errorf("rpslq -L 2: exit %d, %q %q; want a failure naming -L 2", code, out.String(), errs.String())
	}
}

// Addresses are written as bgpq4 writes them, with inet_ntop: an
// IPv4-compatible IPv6 address in dotted form, ties between runs of zeros
// broken to the left, a single zero word not compressed — in every vendor,
// and in -F's netmasks.
func TestRpslqAddressesMatchBgpq4(t *testing.T) {
	needBgpq4Output(t)
	addr := irrtest.New().IRRd(t)
	prefixes := []string{"::1.2.3.0/120", "::ffff:1.2.3.0/120", "::/96", "::102/128", "::1/128",
		"1:0:0:2:0:0:3:4/128", "1:0:2:3:4:5:6:7/128", "2001:db8::/32"}
	vendors := append(append([][]string(nil), bgpq4Vendors...), []string{"-F", `%n %m %i\n`})
	for _, v := range vendors {
		for _, shape := range [][]string{nil, {"-A"}} {
			args := append(append(append([]string{"-h", addr, "-6"}, v...), shape...), prefixes...)
			compareRpslq(t, "addresses", args)
		}
	}
}
