package resolve_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslconf"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
	"github.com/rkolesnichenko/rpsl/types"
)

// The rtconfig differential (spec §9.4): IRRToolSet 5.1.3's rtconfig and
// rpslconf write configuration from one @RtConfig template over one irrtest
// server, and cfgsim runs the same routes through both; decision and
// attributes must agree for cisco, junos and ciscoxr. rtconfig reads aut-nums
// with IRRd 2/3's "!man", which the server answers (WithLegacyClasses).
// Where rtconfig is wrong — D1–D16, testdata/rtconfig/divergences.md — the
// random policies keep clear and a test here pins it, so a change on either
// side fails. rtconfig and peval come from PATH (scripts/build-irrtoolset.sh;
// CI builds them); the goldens keep TestRtconfigGoldens comparing without.

// squeezeBlank collapses runs of blank lines to one, as the goldens are kept.
func squeezeBlank(s string) string {
	var b strings.Builder
	blank := false
	for _, line := range strings.SplitAfter(s, "\n") {
		isBlank := line != "" && strings.TrimSpace(line) == ""
		if isBlank && blank {
			continue
		}
		blank = isBlank
		b.WriteString(line)
	}
	return b.String()
}

// rtconfigArgs is rtconfig's command line for a vendor: none for cisco, which
// the Homebrew bottle (it ignores its command line) can run.
func rtconfigArgs(vendor string, andNotOr bool) []string {
	switch {
	case vendor == "junos" && andNotOr:
		return []string{"-config", "junos", "-junos_and_not_or"}
	case vendor == "junos", vendor == "ciscoxr":
		return []string{"-config", vendor}
	}
	return nil
}

// runRtconfig runs rtconfig over template against the IRRd at addr, naming
// the server in the environment, which every build reads. rtconfig exits 0
// even after an error (D9); err is a crash or the timeout.
func runRtconfig(t *testing.T, bin, addr, sources string, args []string, template string) (string, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "IRR_HOST="+host, "IRR_PORT="+port, "IRR_SOURCES="+sources)
	cmd.Stdin = strings.NewReader(template)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return squeezeBlank(out.String()), err
}

// runRpslconf runs rpslconf in-process with args after the server's.
func runRpslconf(addr, sources, stdin string, args ...string) (out string, code int, stderr string) {
	var o, e bytes.Buffer
	code = rpslconf.Run(context.Background(), append([]string{"-h", addr, "-s", sources}, args...), strings.NewReader(stdin), &o, &e)
	return o.String(), code, e.String()
}

// rtconfigVendors are the vendors this rtconfig writes: the bottle writes
// cisco whatever -config asks. It probes with template, which must import.
func rtconfigVendors(t *testing.T, bin, addr, sources, template string) []string {
	var out []string
	for _, v := range []struct{ name, marker string }{{"cisco", "route-map "}, {"junos", "policy-statement "}, {"ciscoxr", "route-policy "}} {
		if text, err := runRtconfig(t, bin, addr, sources, rtconfigArgs(v.name, false), template); err == nil && strings.Contains(text, v.marker) {
			out = append(out, v.name)
		}
	}
	return out
}

type decision struct {
	ok    bool
	attrs cfgsim.Attrs
}

// decide runs routes through the policy config attaches to neighbor. ok is
// false when it attaches none.
func decide(t *testing.T, label, vendor, config string, neighbor netip.Addr, export bool, routes []routemodel.Route) ([]decision, bool) {
	t.Helper()
	c, err := cfgsim.Parse(vendor, config)
	if err != nil {
		t.Fatalf("%s: %v\n%s", label, err, config)
	}
	name, ok := c.Attached(neighbor, export)
	if !ok {
		return nil, false
	}
	out := make([]decision, len(routes))
	for i, r := range routes {
		accepted, a, err := c.Policy(name, r)
		if err != nil {
			t.Fatalf("%s: %v\n%s", label, err, config)
		}
		if accepted {
			out[i] = decision{true, a}
		}
	}
	return out, true
}

// undefinedPolicy reports whether config attaches to neighbor a policy it
// never defines, as rtconfig's IOS rendering of a session whose policy
// denotes no route does (D15).
func undefinedPolicy(t *testing.T, label, vendor, config string, neighbor netip.Addr, export bool) bool {
	t.Helper()
	c, err := cfgsim.Parse(vendor, config)
	if err != nil {
		t.Fatalf("%s: %v\n%s", label, err, config)
	}
	name, ok := c.Attached(neighbor, export)
	return ok && !slices.Contains(c.Policies(), name)
}

func rmRoute(p string, path []types.ASN, comms ...string) routemodel.Route {
	return routemodel.Route{Prefix: netip.MustParsePrefix(p), Path: path, Communities: comms}
}

func goldenObjects(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("testdata/rtconfig/objects.rpsl")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n\n")
}

// goldenRoutes are what the goldens are compared on: every IPv4 route of the
// objects and some around them, on paths from peer, with and without the
// communities the policies test.
func goldenRoutes(peer types.ASN) []routemodel.Route {
	prefixes := []string{"0.0.0.0/0", "10.1.0.0/16", "10.1.0.0/24", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16",
		"10.5.0.0/16", "10.6.0.0/16", "10.10.0.0/16", "10.10.1.0/24", "10.11.0.0/16", "10.12.0.0/16", "10.12.1.0/24",
		"10.13.0.0/16", "10.20.1.0/24", "10.21.5.0/24", "10.21.5.0/25", "10.22.0.0/16", "10.44.0.0/16",
		"10.55.0.0/16", "127.1.0.0/16", "192.0.2.0/24"}
	paths := [][]types.ASN{{peer}, {peer, 10}, {peer, 10, 1}, {peer, 13}, {peer, 11, 14}}
	comms := [][]string{nil, {"4:1"}, {"5:666"}, {"4:1", "5:666"}}
	var out []routemodel.Route
	for _, p := range prefixes {
		for _, path := range paths {
			for _, c := range comms {
				out = append(out, rmRoute(p, path, c...))
			}
		}
	}
	return out
}

var rtconfigGoldens = []struct {
	template string
	export   bool
	peers    map[string]types.ASN // neighbour → its AS
}{
	{"import-v4", false, map[string]types.ASN{"10.0.0.2": 2, "10.0.0.3": 3, "10.0.0.4": 4, "10.0.0.5": 5}},
	{"export-v4", true, map[string]types.ASN{"10.0.0.2": 2, "10.0.0.3": 3, "10.0.0.5": 5}},
}

// goldenDivergence is a neighbour whose golden differs from rpslconf by a
// pinned divergence d: route must be treated differently, and the neighbour
// is not compared otherwise.
type goldenDivergence struct {
	template, vendor, neighbor, d string
	route                         routemodel.Route
}

var goldenDivergences = []goldenDivergence{
	{"import-v4", "cisco", "10.0.0.3", "D2", rmRoute("0.0.0.0/0", []types.ASN{3})},
	{"import-v4", "junos", "10.0.0.3", "D2", rmRoute("0.0.0.0/0", []types.ASN{3})},
	{"import-v4", "ciscoxr", "10.0.0.3", "D2", rmRoute("0.0.0.0/0", []types.ASN{3})},
	{"import-v4", "ciscoxr", "10.0.0.5", "D11", rmRoute("10.55.0.0/16", []types.ASN{5})},
	{"export-v4", "ciscoxr", "10.0.0.3", "D14", rmRoute("10.1.0.0/16", []types.ASN{3})},
}

func TestRtconfigGoldens(t *testing.T) {
	addr := irrtest.New(goldenObjects(t)...).WithLegacyClasses().IRRd(t)
	bin, _ := exec.LookPath("rtconfig")
	update := os.Getenv("RPSL_RTCONFIG_UPDATE") != ""
	var live []string
	if bin != "" {
		live = rtconfigVendors(t, bin, addr, "RADB", "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n")
	}
	for _, g := range rtconfigGoldens {
		raw, err := os.ReadFile(filepath.Join("testdata/rtconfig", g.template+".tmpl"))
		if err != nil {
			t.Fatal(err)
		}
		tmpl := string(raw)
		for _, vendor := range []string{"cisco", "junos", "ciscoxr"} {
			label := g.template + " " + vendor
			path := filepath.Join("testdata/rtconfig/golden", g.template+"-"+vendor+".txt")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			theirs := squeezeBlank(string(raw))
			if slices.Contains(live, vendor) {
				fresh, err := runRtconfig(t, bin, addr, "RADB", rtconfigArgs(vendor, false), tmpl)
				switch {
				case err != nil:
					t.Fatalf("%s: rtconfig: %v\n%s", label, err, fresh)
				case update:
					if err := os.WriteFile(path, []byte(fresh), 0o644); err != nil {
						t.Fatal(err)
					}
					theirs = fresh
				case fresh != theirs:
					t.Errorf("%s: rtconfig no longer writes %s; if that is expected, rerun with RPSL_RTCONFIG_UPDATE=1 and review the diff", label, path)
				}
			}
			ours, code, errOut := runRpslconf(addr, "RADB", tmpl, "-config", vendor)
			if code != 0 {
				t.Fatalf("%s: rpslconf exited %d: %s", label, code, errOut)
			}
			for nb, peer := range g.peers {
				neighbor := netip.MustParseAddr(nb)
				if i := slices.IndexFunc(goldenDivergences, func(d goldenDivergence) bool {
					return d.template == g.template && d.vendor == vendor && d.neighbor == nb
				}); i >= 0 {
					d := goldenDivergences[i]
					a, _ := decide(t, label+" rtconfig", vendor, theirs, neighbor, g.export, []routemodel.Route{d.route})
					b, _ := decide(t, label+" rpslconf", vendor, ours, neighbor, g.export, []routemodel.Route{d.route})
					if reflect.DeepEqual(a, b) {
						t.Errorf("%s %s: %s is gone — route %v is treated alike; update testdata/rtconfig/divergences.md", label, nb, d.d, d.route)
					}
					continue
				}
				routes := goldenRoutes(peer)
				a, okA := decide(t, label+" rtconfig", vendor, theirs, neighbor, g.export, routes)
				b, okB := decide(t, label+" rpslconf", vendor, ours, neighbor, g.export, routes)
				if !okA || !okB {
					t.Fatalf("%s %s: attached: rtconfig %v, rpslconf %v", label, nb, okA, okB)
				}
				for i := range routes {
					if !reflect.DeepEqual(a[i], b[i]) {
						t.Errorf("%s %s: route %v: rtconfig %+v, rpslconf %+v", label, nb, routes[i], a[i], b[i])
						break
					}
				}
			}
		}
	}
}

// rtconfigPolicy draws the aut-num AS64500, whose import (or export) policy
// for the session with AS65002 at 10.0.0.2 uses only what rtconfig renders
// correctly (spec §3; see the file comment), but for three shapes one vendor
// gets wrong, which TestRtconfigMatches sets aside for that vendor only: a
// clause that is ANY or NOT ANY on IOS-XR (D14), a policy that denotes no
// route on IOS (D15), and a clause whose only regexp is negated on IOS-XR
// (D16). The first term is always for that session; a later one may be for
// another, which must not apply.
func rtconfigPolicy(r *rand.Rand, g *filterGen, export bool) string {
	regexps := []string{"<^AS65002>", "<AS65001$>", "<^AS65002 .* AS65003$>", "NOT <AS65004>"}
	comms := []string{"community(1:1)", "community.contains(1:2)"}
	attr, dir, verb := "import", "from", "accept"
	if export {
		attr, dir, verb = "export", "to", "announce"
	}
	var b strings.Builder
	b.WriteString("aut-num: AS64500\nas-name: LOCAL\n")
	for n := 0; n < 1+r.IntN(3); n++ {
		peering := "AS65002 10.0.0.2 at 10.0.0.1"
		if n > 0 && r.IntN(4) == 0 {
			peering = "AS65003 10.0.0.3 at 10.0.0.1"
		}
		f := pevalFilter(g, 2).text()
		if r.IntN(3) == 0 {
			f = "(" + f + ") AND " + regexps[r.IntN(len(regexps))]
		}
		if r.IntN(3) == 0 {
			f = "(" + f + ") AND " + comms[r.IntN(len(comms))]
		}
		var acts []string
		for _, a := range modelActions {
			if r.IntN(3) == 0 {
				acts = append(acts, a)
			}
		}
		fmt.Fprintf(&b, "%s: %s %s", attr, dir, peering)
		if len(acts) > 0 {
			fmt.Fprintf(&b, " action %s;", strings.Join(acts, "; "))
		}
		fmt.Fprintf(&b, " %s %s\n", verb, f)
	}
	b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
	return b.String()
}

// xrDrops reports whether rtconfig's IOS-XR rendering of p goes wrong by
// D14: it writes a clause that is ANY, or one that is NOT ANY, as "drop",
// which ends the policy — refusing every route for ANY, and for NOT ANY the
// routes a later clause accepts.
func xrDrops(p peval.Policy) bool {
	for i, c := range p.Clauses {
		if len(c.Filter.Conjuncts) == 0 && i < len(p.Clauses)-1 {
			return true
		}
		for _, cj := range c.Filter.Conjuncts {
			if cj.AnyPrefix() && cj.NotPrefixes.Len() == 0 && len(cj.Paths) == 0 && len(cj.Communities) == 0 {
				return true
			}
		}
	}
	return false
}

func TestRtconfigMatches(t *testing.T) {
	bin, err := exec.LookPath("rtconfig")
	if err != nil {
		t.Skip("IRRToolSet's rtconfig is not installed (scripts/build-irrtoolset.sh)")
	}
	// Probe over the goldens' objects, whose AS1 surely imports from AS2.
	probe := irrtest.New(goldenObjects(t)...).WithLegacyClasses().IRRd(t)
	vendors := rtconfigVendors(t, bin, probe, "RADB", "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n")
	if len(vendors) == 0 {
		t.Fatal("rtconfig wrote no vendor's configuration")
	}
	t.Logf("rtconfig writes %v here", vendors)
	tally := map[string]int{} // what became of each seed's comparison, by vendor
	defer func() { t.Logf("compared, and set aside by divergence: %v", tally) }()
	for seed := uint64(0); seed < 40; seed++ {
		r := rand.New(rand.NewPCG(seed, 43))
		m := randomModel(r, true)
		g := newFilterGen(r, newOracle(m))
		g.v4only = true
		export := r.IntN(2) == 0
		pol := rtconfigPolicy(r, g, export)
		addr := irrtest.New(append(m.texts(r), pol)...).WithSources("RIPE", "RADB").WithLegacyClasses().IRRd(t)
		cmd := "import"
		if export {
			cmd = "export"
		}
		tmpl := fmt.Sprintf("@RtConfig %s AS64500 10.0.0.1 AS65002 10.0.0.2\n", cmd)
		var routes []routemodel.Route
		for len(routes) < 60 {
			if rt := randomRoute(r, 65002); rt.Prefix.Addr().Is4() {
				routes = append(routes, rt)
			}
		}
		nb := netip.MustParseAddr("10.0.0.2")
		src := &irrd.Source{Addr: addr, Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		s := peval.Session{Local: 64500, Peer: 65002, LocalRtr: netip.MustParseAddr("10.0.0.1"), PeerRtr: nb,
			AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}}
		eval := (&peval.Evaluator{Src: src}).Import
		if export {
			eval = (&peval.Evaluator{Src: src}).Export
		}
		p, err := eval(context.Background(), s)
		src.Close()
		if err != nil {
			t.Fatalf("seed %d: peval: %v\npolicy:\n%s", seed, err, pol)
		}
		for _, v := range vendors {
			if v == "ciscoxr" && xrDrops(p) {
				tally[v+" D14"]++
				continue
			}
			if v == "ciscoxr" && strings.Contains(pol, "NOT <") { // a clause whose only regexp is negated
				tally[v+" D16"]++
				continue
			}
			label := fmt.Sprintf("seed %d %s %s", seed, v, cmd)
			theirs, err := runRtconfig(t, bin, addr, "RIPE,RADB", rtconfigArgs(v, true), tmpl)
			if err != nil {
				t.Fatalf("%s: rtconfig: %v\n%s", label, err, theirs)
			}
			ours, code, errOut := runRpslconf(addr, "RIPE,RADB", tmpl, "-config", v)
			if code != 0 {
				t.Fatalf("%s: rpslconf exited %d: %s\npolicy:\n%s", label, code, errOut, pol)
			}
			b, _ := decide(t, label+" rpslconf", v, ours, nb, export, routes)
			if undefinedPolicy(t, label+" rtconfig", v, theirs, nb, export) { // D15: the policy must accept nothing
				if i := slices.IndexFunc(b, func(d decision) bool { return d.ok }); i >= 0 {
					t.Fatalf("%s: rtconfig attached a policy it never wrote, but rpslconf accepts %v\npolicy:\n%s\nours:\n%s\ntheirs:\n%s", label, routes[i], pol, ours, theirs)
				}
				tally[v+" D15"]++
				continue
			}
			a, attached := decide(t, label+" rtconfig", v, theirs, nb, export, routes)
			if !attached { // D13: rtconfig wrote nothing; the policy must accept nothing
				if i := slices.IndexFunc(b, func(d decision) bool { return d.ok }); i >= 0 {
					t.Fatalf("%s: rtconfig attached no policy, but rpslconf accepts %v\npolicy:\n%s\nours:\n%s\ntheirs:\n%s", label, routes[i], pol, ours, theirs)
				}
				tally[v+" D13"]++
				continue
			}
			for i := range routes {
				if !reflect.DeepEqual(a[i], b[i]) {
					t.Fatalf("%s: route %v: rtconfig %+v, rpslconf %+v\npolicy:\n%s\nrtconfig:\n%s\nrpslconf:\n%s",
						label, routes[i], a[i], b[i], pol, theirs, ours)
				}
			}
			tally[v]++
		}
	}
}

// TestRtconfigDivergences pins the rtconfig divergences that need rtconfig to
// show; D2, D11 and D14's ANY half are pinned in the goldens, D1, D3 and
// D10's peval half in TestPevalDivergences.
func TestRtconfigDivergences(t *testing.T) {
	bin, err := exec.LookPath("rtconfig")
	if err != nil {
		t.Skip("IRRToolSet's rtconfig is not installed (scripts/build-irrtoolset.sh)")
	}
	objs := goldenObjects(t)
	addr := irrtest.New(objs...).WithLegacyClasses().IRRd(t)
	vendors := rtconfigVendors(t, bin, addr, "RADB", "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n")
	theirs := func(t *testing.T, addr string, args []string, tmpl string) string {
		t.Helper()
		out, err := runRtconfig(t, bin, addr, "RADB", args, tmpl)
		if err != nil {
			t.Fatalf("rtconfig: %v\n%s", err, out)
		}
		return out
	}
	t.Run("D4", func(t *testing.T) { // an IPv4 entry in an IPv6 session's map
		const tmpl = "@RtConfig import AS1 2001:db8::1 AS9 2001:db8::9\n"
		if out := theirs(t, addr, nil, tmpl); !strings.Contains(out, "match ip address") {
			t.Errorf("D4 is gone: no IPv4 entry for the IPv6 session:\n%s", out)
		}
		if out, code, errOut := runRpslconf(addr, "RADB", tmpl); code != 0 || strings.Contains(out, "match ip address") {
			t.Errorf("rpslconf: exit %d, %s\n%s", code, errOut, out)
		}
	})
	t.Run("D5", func(t *testing.T) { // import-via: ignored by rtconfig; evaluated, and refused, by us
		const tmpl = "@RtConfig import AS1 10.0.0.1 AS6777 10.0.0.77\n"
		r := rmRoute("10.11.0.0/16", []types.ASN{6777, 15562, 11})
		if d, ok := decide(t, "rtconfig", "cisco", theirs(t, addr, nil, tmpl), netip.MustParseAddr("10.0.0.77"), false, []routemodel.Route{r}); ok && d[0].ok {
			t.Errorf("D5 is gone: rtconfig's policy for AS6777 accepts %v", r)
		}
		src := &irrd.Source{Addr: addr, Sources: []string{"RADB"}, Timeout: 5 * time.Second}
		defer src.Close()
		s := peval.Session{Local: 1, Peer: 6777, LocalRtr: netip.MustParseAddr("10.0.0.1"),
			PeerRtr: netip.MustParseAddr("10.0.0.77"), AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}}
		p, err := (&peval.Evaluator{Src: src}).ImportVia(context.Background(), s)
		if err != nil || len(p.Clauses) == 0 || p.Clauses[0].Remote == nil {
			t.Fatalf("ImportVia: %+v, %v", p, err)
		}
		var ue *rtconfig.UnsupportedError
		if err := (&rtconfig.Generator{Vendor: rtconfig.IOS}).WriteImport(io.Discard, s, p); !errors.As(err, &ue) || ue.Cause != rtconfig.CauseVia {
			t.Errorf("WriteImport of a via policy: %v", err)
		}
	})
	t.Run("D6", func(t *testing.T) { // default: pref dropped (cisco); "not implemented" (junos)
		// The template's default command names no routers, so the default
		// must name none either: the fixture's AS1 default to AS2 does.
		addr := irrtest.New("aut-num: AS1\nas-name: ONE\ndefault: to AS2 action pref = 100; networks ANY\nsource: RADB\n").
			WithLegacyClasses().IRRd(t)
		const tmpl = "@RtConfig default AS1 AS2\n"
		if out := theirs(t, addr, nil, tmpl); !strings.Contains(out, "ip default-network 0.0.0.0") {
			t.Errorf("D6 is gone: rtconfig's cisco default is\n%s", out)
		}
		if slices.Contains(vendors, "junos") {
			if out := theirs(t, addr, rtconfigArgs("junos", false), tmpl); !strings.Contains(out, "default not implemented") {
				t.Errorf("D6 is gone: rtconfig's junos default is\n%s", out)
			}
		}
		if _, code, errOut := runRpslconf(addr, "RADB", tmpl); code != 1 || !strings.Contains(errOut, rtconfig.CauseDefault) {
			t.Errorf("rpslconf: exit %d, %s", code, errOut)
		}
	})
	t.Run("D7", func(t *testing.T) { // configureRouter drops the router-specific clause (pref=10 → 990)
		const tmpl = "@RtConfig configureRouter rtr1.example.net\n"
		if out := theirs(t, addr, nil, tmpl); !strings.Contains(out, "route-map ") || strings.Contains(out, "local-preference 990") {
			t.Errorf("D7 is gone:\n%s", out)
		}
		if _, code, errOut := runRpslconf(addr, "RADB", tmpl); code != 1 || !strings.Contains(errOut, "not supported yet") {
			t.Errorf("rpslconf: exit %d, %s", code, errOut)
		}
	})
	t.Run("D8+D10", func(t *testing.T) { // importGroup: no policy at all; PeerAS queried as AS4294967295
		const tmpl = "@RtConfig importGroup AS1 PRNG-IX\n"
		out := theirs(t, addr, nil, tmpl)
		if !strings.Contains(out, "peer-group") || strings.Contains(out, "route-map ") {
			t.Errorf("D8 is gone:\n%s", out)
		}
		if !strings.Contains(out, "AS4294967295") {
			t.Errorf("D10 is gone: rtconfig no longer names an unbound PeerAS AS4294967295:\n%s", out)
		}
		if _, code, errOut := runRpslconf(addr, "RADB", tmpl); code != 1 || !strings.Contains(errOut, "not supported yet") {
			t.Errorf("rpslconf: exit %d, %s", code, errOut)
		}
	})
	t.Run("D9", func(t *testing.T) { // exit status 0 after an error
		const tmpl = "@RtConfig import AS99 10.0.0.1 AS2 10.0.0.2\n"
		out, err := runRtconfig(t, bin, addr, "RADB", nil, tmpl)
		if err != nil || !strings.Contains(out, "AS99") {
			t.Errorf("D9 is gone: rtconfig: %v\n%s", err, out)
		}
		if _, code, _ := runRpslconf(addr, "RADB", tmpl); code != 1 {
			t.Errorf("rpslconf exited %d", code)
		}
	})
	t.Run("D12", func(t *testing.T) { // Junos: a policy chain lets the community test decide alone
		if !slices.Contains(vendors, "junos") {
			t.Skip("this rtconfig writes no Junos")
		}
		addr := irrtest.New("aut-num: AS1\nas-name: ONE\nimport: from AS2 10.0.0.2 at 10.0.0.1 accept {10.0.0.0/8^+} AND community(1:1)\nsource: RADB\n").
			WithLegacyClasses().IRRd(t)
		const tmpl = "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n"
		r := []routemodel.Route{rmRoute("192.0.2.0/24", []types.ASN{2}, "1:1")}
		nb := netip.MustParseAddr("10.0.0.2")
		if d, _ := decide(t, "rtconfig", "junos", theirs(t, addr, rtconfigArgs("junos", false), tmpl), nb, false, r); !d[0].ok {
			t.Errorf("D12 is gone: without -junos_and_not_or, rtconfig refuses %v", r[0])
		}
		if d, _ := decide(t, "rtconfig", "junos", theirs(t, addr, rtconfigArgs("junos", true), tmpl), nb, false, r); d[0].ok {
			t.Errorf("with -junos_and_not_or, rtconfig accepts %v", r[0])
		}
		out, code, errOut := runRpslconf(addr, "RADB", tmpl, "-config", "junos")
		if d, _ := decide(t, "rpslconf", "junos", out, nb, false, r); code != 0 || d[0].ok {
			t.Errorf("rpslconf: exit %d, %s; accepts %v", code, errOut, r[0])
		}
	})
	t.Run("D13", func(t *testing.T) { // no policy for the session: rtconfig writes none
		const tmpl = "@RtConfig export AS1 10.0.0.1 AS4 10.0.0.4\n"
		nb := netip.MustParseAddr("10.0.0.4")
		r := []routemodel.Route{rmRoute("10.1.0.0/16", []types.ASN{1})}
		if _, ok := decide(t, "rtconfig", "cisco", theirs(t, addr, nil, tmpl), nb, true, r); ok {
			t.Errorf("D13 is gone: rtconfig attaches a policy for a session AS1 has no export to")
		}
		out, code, _ := runRpslconf(addr, "RADB", tmpl)
		if d, ok := decide(t, "rpslconf", "cisco", out, nb, true, r); code != 0 || !ok || d[0].ok {
			t.Errorf("rpslconf: exit %d, attached %v, decisions %v\n%s", code, ok, d, out)
		}
	})
	// A clause that is NOT ANY, or ANY, ends an IOS-XR policy: "drop". The
	// goldens pin ANY (export-v4, 10.0.0.3); this is NOT ANY before a clause
	// that accepts.
	t.Run("D14", func(t *testing.T) {
		if !slices.Contains(vendors, "ciscoxr") {
			t.Skip("this rtconfig writes no IOS-XR")
		}
		addr := irrtest.New("aut-num: AS1\nas-name: ONE\nimport: from AS2 10.0.0.2 at 10.0.0.1 accept NOT ANY\n" +
			"import: from AS2 10.0.0.2 at 10.0.0.1 accept {10.1.0.0/16}\nsource: RADB\n").WithLegacyClasses().IRRd(t)
		const tmpl = "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n"
		r := []routemodel.Route{rmRoute("10.1.0.0/16", []types.ASN{2})}
		nb := netip.MustParseAddr("10.0.0.2")
		if d, _ := decide(t, "rtconfig", "ciscoxr", theirs(t, addr, rtconfigArgs("ciscoxr", false), tmpl), nb, false, r); d[0].ok {
			t.Errorf("D14 is gone: rtconfig accepts %v after a NOT ANY clause", r[0])
		}
		out, code, errOut := runRpslconf(addr, "RADB", tmpl, "-config", "ciscoxr")
		if d, _ := decide(t, "rpslconf", "ciscoxr", out, nb, false, r); code != 0 || !d[0].ok {
			t.Errorf("rpslconf: exit %d, %s; refuses %v", code, errOut, r[0])
		}
	})
	// A session whose policy denotes no route: rtconfig's IOS attaches a
	// route-map it neither writes nor clears.
	t.Run("D15", func(t *testing.T) {
		addr := irrtest.New("aut-num: AS1\nas-name: ONE\nimport: from AS2 10.0.0.2 at 10.0.0.1 accept NOT ANY\nsource: RADB\n").
			WithLegacyClasses().IRRd(t)
		const tmpl = "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n"
		nb := netip.MustParseAddr("10.0.0.2")
		if out := theirs(t, addr, nil, tmpl); !undefinedPolicy(t, "rtconfig", "cisco", out, nb, false) || strings.Contains(out, "no route-map") {
			t.Errorf("D15 is gone: rtconfig writes\n%s", out)
		}
		out, code, errOut := runRpslconf(addr, "RADB", tmpl)
		r := []routemodel.Route{rmRoute("10.1.0.0/16", []types.ASN{2})}
		if d, ok := decide(t, "rpslconf", "cisco", out, nb, false, r); code != 0 || !ok || d[0].ok {
			t.Errorf("rpslconf: exit %d, %s; attached %v, decisions %v", code, errOut, ok, d)
		}
	})
	// A clause whose only AS-path regexp is negated: rtconfig's IOS-XR
	// as-path-set holds "permit .*", which is not RPL.
	t.Run("D16", func(t *testing.T) {
		if !slices.Contains(vendors, "ciscoxr") {
			t.Skip("this rtconfig writes no IOS-XR")
		}
		addr := irrtest.New("aut-num: AS1\nas-name: ONE\nimport: from AS2 10.0.0.2 at 10.0.0.1 accept NOT <AS65004>\nsource: RADB\n").
			WithLegacyClasses().IRRd(t)
		const tmpl = "@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2\n"
		out := theirs(t, addr, rtconfigArgs("ciscoxr", false), tmpl)
		if _, err := cfgsim.Parse("ciscoxr", out); err == nil || !strings.Contains(out, "permit .*") {
			t.Errorf("D16 is gone: rtconfig writes (%v)\n%s", err, out)
		}
		ours, code, errOut := runRpslconf(addr, "RADB", tmpl, "-config", "ciscoxr")
		nb := netip.MustParseAddr("10.0.0.2")
		r := []routemodel.Route{rmRoute("10.1.0.0/16", []types.ASN{2}), rmRoute("10.1.0.0/16", []types.ASN{2, 65004})}
		if d, _ := decide(t, "rpslconf", "ciscoxr", ours, nb, false, r); code != 0 || !d[0].ok || d[1].ok {
			t.Errorf("rpslconf: exit %d, %s; decisions %v", code, errOut, d)
		}
	})
}

// cappedBuffer keeps the first 1 MiB written to it: peval's D3 writes without
// end.
type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := 1<<20 - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// TestPevalDivergences pins the divergences IRRToolSet's peval shows.
func TestPevalDivergences(t *testing.T) {
	bin, err := exec.LookPath("peval")
	if err != nil {
		t.Skip("IRRToolSet's peval is not installed (scripts/build-irrtoolset.sh)")
	}
	addr := irrtest.New(goldenObjects(t)...).IRRd(t)
	host, port, _ := net.SplitHostPort(addr)
	theirs := func(filter string, timeout time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Env = append(os.Environ(), "IRR_HOST="+host, "IRR_PORT="+port, "IRR_SOURCES=RADB")
		cmd.Stdin = strings.NewReader(filter + "\n")
		var out cappedBuffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		// A build with GNU readline (Linux; not the Homebrew bottle) echoes
		// the line it reads before its answer.
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out.String()), filter)), err
	}
	ours := func(t *testing.T, filter string) string {
		t.Helper()
		out, code, errOut := runRpslconf(addr, "RADB", "", "-e", filter)
		if code != 0 {
			t.Fatalf("rpslconf -e %q: exit %d, %s", filter, code, errOut)
		}
		return strings.TrimSpace(out)
	}
	t.Run("D1", func(t *testing.T) {
		if out, err := theirs("AS-FOO AND NOT AS10", 10*time.Second); err != nil || out != "NOT ANY" {
			t.Errorf("D1 is gone: peval says %q, %v", out, err)
		}
		if out := ours(t, "afi ipv4.unicast AS-FOO AND NOT AS10"); out == "NOT ANY" {
			t.Errorf("rpslconf says NOT ANY")
		}
	})
	t.Run("D2", func(t *testing.T) {
		if out, err := theirs("RS-BAR", 10*time.Second); err != nil || !strings.Contains(out, "0.0.0.0/0") {
			t.Errorf("D2 is gone: peval says %q, %v", out, err)
		}
		if out := ours(t, "afi ipv4.unicast RS-BAR"); strings.Contains(out, "0.0.0.0/0") {
			t.Errorf("rpslconf says %q", out)
		}
	})
	t.Run("D3", func(t *testing.T) {
		if _, err := theirs("afi ipv6.unicast {2001:db8::/32^+}", 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("D3 is gone: peval finished an IPv6 ^+ range: %v", err)
		}
		if out := ours(t, "afi ipv6.unicast {2001:db8::/32^+}"); out != "{2001:db8::/32^+}" {
			t.Errorf("rpslconf says %q", out)
		}
	})
	t.Run("D10", func(t *testing.T) { // peval prints ranges as AS10-AS12; ours parses back
		if out, err := theirs("<^AS1 AS-FOO*$>", 10*time.Second); err != nil || !strings.Contains(out, "AS10-AS12") {
			t.Errorf("D10 is gone: peval says %q, %v", out, err)
		}
		out := ours(t, "afi ipv4.unicast <^AS1 AS-FOO*$>")
		_, diags := policy.ParseFilter(out)
		for _, d := range diags {
			if d.Severity >= ast.Error {
				t.Errorf("rpslconf's %q does not parse back: %v", out, d)
			}
		}
	})
}
