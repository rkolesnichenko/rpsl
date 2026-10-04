package resolve_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/types"
)

// sourceOf is an object's source:, upper-case ("" without one).
func sourceOf(o *ast.Object) string {
	if a, ok := o.GetFirst("source"); ok {
		return strings.ToUpper(strings.TrimSpace(a.Value))
	}
	return ""
}

// lastOfEach keeps, of texts, the last object of each (class, canonical
// primary key, source), in place. A registry holds one object per primary
// key, and a resolve.Corpus (so irrdq) keeps the last it is given, but
// irrtest keeps every copy; the random model can draw a route or aut-num
// twice in one source, so both are given the IRR a registry could hold.
func lastOfEach(texts []string) []string {
	var out []string
	for _, i := range lastOfEachIndex(texts) {
		out = append(out, texts[i])
	}
	return out
}

// lastOfEachIndex is the indexes of the texts lastOfEach keeps, in order.
func lastOfEachIndex(texts []string) []int {
	key := func(text string) string {
		o, _ := rpsl.ParseObject(text)
		obj, _ := object.Decode(o)
		var pk string
		switch t := obj.(type) {
		case object.AsSet:
			pk = t.Name.String()
		case object.RouteSet:
			pk = t.Name.String()
		case object.AutNum:
			pk = t.AS.String()
		case object.Route:
			pk = t.Prefix.Masked().String() + t.Origin.String()
		case object.Route6:
			pk = t.Prefix.Masked().String() + t.Origin.String()
		default:
			pk = strings.ToUpper(strings.TrimSpace(o.Key()))
		}
		return o.Class() + "\x00" + pk + "\x00" + sourceOf(o)
	}
	last := map[string]int{}
	keys := make([]string, len(texts))
	for i, text := range texts {
		keys[i] = key(text)
		last[keys[i]] = i
	}
	var out []int
	for i := range texts {
		if last[keys[i]] == i {
			out = append(out, i)
		}
	}
	return out
}

// askIRRdq plays one connection's lines through a Session, as a server
// would: each reply in order, until one closes the connection.
func askIRRdq(t testing.TB, snap *irrdq.Snapshot, send string) string {
	t.Helper()
	s := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
	var b strings.Builder
	lines := strings.Split(send, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // a last line without its newline is a command too
	}
	for _, l := range lines {
		r, err := s.Do(context.Background(), l)
		if err != nil {
			t.Fatalf("Do(%q): %v", l, err)
		}
		r.WriteTo(&b)
		if r.Close() {
			break
		}
	}
	return b.String()
}

// askTCP sends send on a fresh connection to addr (irrdoracle.Send) and
// returns everything read until the server closes it.
func askTCP(t testing.TB, addr, send string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := irrdoracle.Send(c, send); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("%s did not close the connection: read %q", addr, out)
			}
			return string(out)
		}
	}
}

// firstDiffering names the command of the first reply on which got and
// want differ under k: reply 0 answers the "!s", reply i the command
// cmds[i-1].
func firstDiffering(k irrdoracle.Kind, got, want string, cmds []string) string {
	g, w := irrdoracle.Split(got), irrdoracle.Split(want)
	for i := 0; i < len(g) && i < len(w); i++ {
		if irrdoracle.Compare(k, g[i], w[i]) != nil {
			if i == 0 || i > len(cmds) {
				return "reply " + strconv.Itoa(i)
			}
			return cmds[i-1]
		}
	}
	return "the reply count"
}

// family is one kind of command TestIRRdqMatchesIrrtest compares, sent on a
// connection of its own: irrdoracle.Compare holds one kind per stream.
type family struct {
	name string
	kind irrdoracle.Kind
	cmds []string
}

// irrNames is what a random IRR's texts name: its sets as written (the
// model writes them lower-case), its AS numbers, its aut-nums, and its
// routes' and route6s' prefixes and primary keys.
type irrNames struct {
	sets, asSets, routeSets []string
	asns, autNums           []types.ASN
	routes, routes6         []string // canonical prefixes, each once
	routeKeys, route6Keys   []string // prefix and origin run together
}

func namesOf(texts []string) irrNames {
	var n irrNames
	asns, autNums, prefixes := map[types.ASN]bool{}, map[types.ASN]bool{}, map[string]bool{}
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		obj, _ := object.Decode(o)
		key := strings.TrimSpace(o.Key())
		switch t := obj.(type) {
		case object.AsSet:
			n.sets, n.asSets = append(n.sets, key), append(n.asSets, key)
		case object.RouteSet:
			n.sets, n.routeSets = append(n.sets, key), append(n.routeSets, key)
		case object.AutNum:
			asns[t.AS], autNums[t.AS] = true, true
		case object.Route:
			asns[t.Origin] = true
			if p := t.Prefix.Masked().String(); !prefixes[p] {
				prefixes[p] = true
				n.routes = append(n.routes, p)
			}
			n.routeKeys = append(n.routeKeys, t.Prefix.Masked().String()+t.Origin.String())
		case object.Route6:
			asns[t.Origin] = true
			if p := t.Prefix.Masked().String(); !prefixes[p] {
				prefixes[p] = true
				n.routes6 = append(n.routes6, p)
			}
			n.route6Keys = append(n.route6Keys, t.Prefix.Masked().String()+t.Origin.String())
		}
	}
	for as := range asns {
		n.asns = append(n.asns, as)
	}
	for as := range autNums {
		n.autNums = append(n.autNums, as)
	}
	slices.Sort(n.asns)
	slices.Sort(n.autNums)
	for _, l := range [][]string{n.sets, n.asSets, n.routeSets, n.routes, n.routes6, n.routeKeys, n.route6Keys} {
		sort.Strings(l)
	}
	return n
}

// commandFamilies are the command families of spec §7 for an IRR naming n: the
// set and route-origin lists (!i, !i…,1, !a, !g, !6), object lookups (!m),
// and RIPE-style text searches, inverse searches and their -K forms.
func commandFamilies(n irrNames) []family {
	var words, objs, text, inverse, keys []string
	// Each set as written and upper-case, as bgpq4 sends them: IRRd removes
	// a set's own name from "!i" only as sent.
	var names []string
	for _, s := range n.sets {
		names = append(names, s, strings.ToUpper(s))
	}
	for _, s := range append(names, "AS-NOSUCH", "RS-NOSUCH") {
		words = append(words, "!i"+s, "!i"+s+",1", "!a"+s, "!a4"+s, "!a6"+s)
	}
	for _, as := range n.asns {
		words = append(words, "!g"+as.String(), "!6"+as.String())
		text = append(text, "-T aut-num "+as.String())
		inverse = append(inverse, "-T route,route6 -i origin "+as.String())
		keys = append(keys, "-K -T route,route6 -i origin "+as.String())
	}
	for _, s := range n.asSets {
		objs = append(objs, "!mas-set,"+s, "!mas-set,"+strings.ToUpper(s))
		text = append(text, "-T as-set "+s, "-T as-set,route-set "+strings.ToUpper(s))
		keys = append(keys, "-K -T as-set "+s)
	}
	for _, s := range n.routeSets {
		objs = append(objs, "!mroute-set,"+s)
		text = append(text, "-T route-set "+s)
		keys = append(keys, "-K -T route-set "+s)
	}
	for _, s := range append(slices.Clone(n.sets), "AS-NOSUCH", "RS-NOSUCH") {
		inverse = append(inverse, "-i member-of "+s)
		keys = append(keys, "-K -i member-of "+s)
	}
	for _, as := range n.autNums {
		objs = append(objs, "!maut-num,"+as.String())
	}
	objs = append(objs, "!maut-num,AS4200000000", "!mas-set,AS-NOSUCH", "!mroute,192.0.2.0/24AS1")
	// A sample of routes: the first and last few of each family's.
	sample := func(l []string) []string {
		if len(l) <= 8 {
			return l
		}
		return append(slices.Clone(l[:4]), l[len(l)-4:]...)
	}
	for _, k := range sample(n.routeKeys) {
		objs = append(objs, "!mroute,"+k)
	}
	for _, k := range sample(n.route6Keys) {
		objs = append(objs, "!mroute6,"+k)
	}
	for _, p := range sample(n.routes) {
		text = append(text, "-T route "+p, "-K -T route "+p)
	}
	for _, p := range sample(n.routes6) {
		text = append(text, "-T route6 "+p)
	}
	for _, l := range [][]string{words, objs, text, inverse, keys} {
		sort.Strings(l)
	}
	return []family{
		{"lists", irrdoracle.Words, words},
		{"objects", irrdoracle.Objects, objs},
		{"text searches", irrdoracle.Objects, text},
		{"inverse searches", irrdoracle.Objects, inverse},
		{"-K", irrdoracle.Objects, keys},
	}
}

// compareFamilies sends each family, under each selection, to irrtest at
// addr and through a Session on snap, which must agree under the family's
// kind, and to irrdserver serving snap at served, which must answer byte for
// byte as the Session. It returns the commands compared, and counts in
// answered each family's replies that hold data (not D, F or "No entries").
func compareFamilies(t *testing.T, label, addr, served string, snap *irrdq.Snapshot, sels []string, fams []family, answered map[string]int) int {
	t.Helper()
	n := 0
	for _, f := range fams {
		if len(f.cmds) == 0 {
			continue
		}
		for _, sel := range sels {
			send := "!!\n" + sel + "\n" + strings.Join(f.cmds, "\n") + "\n!q\n"
			got, want := askIRRdq(t, snap, send), askTCP(t, addr, send)
			if err := irrdoracle.Compare(f.kind, got, want); err != nil {
				t.Fatalf("%s, %s, %s: %s: %v", label, f.name, sel, firstDiffering(f.kind, got, want, f.cmds), err)
			}
			if tcp := askTCP(t, served, send); tcp != got {
				t.Fatalf("%s, %s, %s: irrdserver answered otherwise than the session: %s", label, f.name, sel,
					firstDiffering(irrdoracle.Exact, tcp, got, f.cmds))
			}
			n += len(f.cmds)
			for _, r := range irrdoracle.Split(got)[1:] {
				if r != "D\n" && !strings.HasPrefix(r, "F ") && !strings.HasPrefix(r, "%") {
					answered[f.name]++
				}
			}
		}
	}
	return n
}

// TestIRRdqMatchesIrrtest: on random IRRs, irrdq answers as irrtest (held to
// IRRd's recordings by irrtest's TestMatchesIRRd) for every family of
// commands spec §7 names: !i, !i…,1, !a, !a4, !a6, !g and !6 for every set
// and AS the IRR names; !m for every set and aut-num and a sample of routes;
// RIPE-style -T text searches, -i origin and -i member-of, and their -K
// forms — under both source orders, each family on a connection of its own.
// A further pass puts both in IRRd's RPKI-aware mode with random ROAs, with
// and without the RPKI pseudo source selected. irrdserver, serving the same
// snapshot on a socket, answers each pipelined burst byte for byte as the
// session does.
func TestIRRdqMatchesIrrtest(t *testing.T) {
	const seeds = 60
	total := 0
	answered, rpkiAnswered := map[string]int{}, map[string]int{}
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 24))
		m := randomModel(r, false)
		texts := lastOfEach(m.texts(r))
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t)
		snap := rpsldtest.Snapshot(t, texts, irrdq.SnapshotOptions{}, "RIPE", "RADB")
		served := rpsldtest.Serve(t, snap)
		total += compareFamilies(t, "seed "+strconv.FormatUint(seed, 10), addr, served, snap,
			[]string{"!sRIPE,RADB", "!sRADB,RIPE"}, commandFamilies(namesOf(texts)), answered)
	}
	rpkiTotal, hidden := 0, 0
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 25))
		m := randomModel(r, false)
		texts := lastOfEach(m.texts(r))
		roas := randomROAs(r, m)
		var iroas []irrtest.ROA
		for _, roa := range roas {
			iroas = append(iroas, irrtest.ROA{Prefix: roa.pfx, ASN: roa.as, MaxLength: roa.maxLen, TA: "model"})
		}
		v := vrpsOf(t, roas)
		for _, c := range m.objs {
			if newOracle(m).withRPKI(roas, false).suppressed(c) {
				hidden++
			}
		}
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").WithRPKI(iroas...).IRRd(t)
		snap := rpsldtest.Snapshot(t, texts, irrdq.SnapshotOptions{VRPs: v}, "RIPE", "RADB")
		served := rpsldtest.Serve(t, snap)
		// The pseudo routes' ASes and prefixes too.
		n := namesOf(append(slices.Clone(texts), pseudoTexts(t, v)...))
		n.sets, n.asSets, n.routeSets = namesOf(texts).sets, namesOf(texts).asSets, namesOf(texts).routeSets
		var rfams []family
		for _, f := range commandFamilies(n) {
			if f.name == "lists" || f.name == "objects" {
				rfams = append(rfams, f)
			}
		}
		rpkiTotal += compareFamilies(t, "rpki seed "+strconv.FormatUint(seed, 10), addr, served, snap,
			[]string{"!sRIPE,RADB", "!sRIPE,RADB,RPKI", "!sRPKI,RADB,RIPE"}, rfams, rpkiAnswered)
	}
	if hidden < 20 {
		t.Errorf("only %d of the models' routes hidden as RPKI-invalid over all seeds: the ROAs miss the model", hidden)
	}
	for _, f := range commandFamilies(irrNames{}) {
		if answered[f.name] < 100 {
			t.Errorf("%s: only %d replies held data", f.name, answered[f.name])
		}
	}
	t.Logf("%d seeds, %d commands compared, replies with data by family %v; RPKI-aware, %d seeds, %d commands, replies with data %v, %d of the models' routes hidden",
		seeds, total, answered, seeds, rpkiTotal, rpkiAnswered, hidden)
}
