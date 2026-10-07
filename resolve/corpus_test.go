package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// sameAnswers holds a MemSource built from a Corpus to NewMemSource over the
// same objects: every set looked up, unscoped and under each of scopes plus an
// unknown registry ("NOSUCH"), every AS's routes in each family (as sets: the
// engine deduplicates), and every set's honored claimants, unscoped and per
// scope. When policy is set, got and want are PolicySources built from a
// Corpus{KeepPolicy: true} and NewMemSource over the same objects: AutNum and
// InetRtr are also compared, for every ASN and inet-rtr name objs holds,
// unscoped, per scope and under an unknown registry; when it is not, got is
// a plain Corpus build and must answer both with ErrNoPolicy.
func sameAnswers(t *testing.T, label string, objs []object.Object, got, want *resolve.MemSource, scopes []string, policy bool) {
	t.Helper()
	ctx := context.Background()
	names := map[string]types.SetName{}
	asns := map[types.ASN]bool{0: true, 64999: true}
	rtrNames := map[string]bool{"no-such.example.net": true}
	for _, o := range objs {
		if s, ok := o.(object.NamedSet); ok {
			names[s.SetName().String()] = s.SetName()
		}
		switch r := o.(type) {
		case *object.Route:
			asns[r.Origin] = true
		case *object.Route6:
			asns[r.Origin] = true
		case *object.AutNum:
			asns[r.AS] = true
		case *object.InetRtr:
			rtrNames[r.Name] = true
		}
	}
	missing, _ := types.ParseSetName("AS-NOT-THERE")
	names[missing.String()] = missing
	checkRef := func(refLabel string, ref types.SetRef) {
		gs, gerr := got.GetSet(ctx, ref)
		ws, werr := want.GetSet(ctx, ref)
		if (gerr == nil) != (werr == nil) || !reflect.DeepEqual(gs, ws) {
			t.Fatalf("%s: GetSet(%s) = %v, %v; want %v, %v", label, refLabel, gs, gerr, ws, werr)
		}
		if ws == nil {
			return
		}
		gm, _ := got.MembersByRef(ctx, ws)
		wm, _ := want.MembersByRef(ctx, ws)
		if !slices.Equal(texts(gm), texts(wm)) {
			t.Fatalf("%s: MembersByRef(%s) = %v; want %v", label, refLabel, texts(gm), texts(wm))
		}
	}
	for _, n := range names {
		checkRef(n.String(), types.Ref(n))
		for _, scope := range append(append([]string{}, scopes...), "NOSUCH") {
			ref, err := types.NewSetRef(scope, n)
			if err != nil {
				t.Fatalf("%s: NewSetRef(%s, %s): %v", label, scope, n, err)
			}
			checkRef(ref.String(), ref)
		}
	}
	for as := range asns {
		for _, afi := range []types.AFI{types.AFIv4, types.AFIv6, types.AFIAny} {
			gr, _ := got.OriginatedRoutes(ctx, as, afi)
			wr, _ := want.OriginatedRoutes(ctx, as, afi)
			if !slices.Equal(distinct(gr), distinct(wr)) {
				t.Fatalf("%s: OriginatedRoutes(%s, %v) = %v; want %v", label, as, afi, gr, wr)
			}
		}
	}
	if !policy {
		// got is a Corpus built without KeepPolicy: it serves no policy
		// objects at all, never the subset (claimants) it happens to hold.
		for as := range asns {
			if _, err := got.AutNum(ctx, as, ""); !errors.Is(err, resolve.ErrNoPolicy) {
				t.Fatalf("%s: plain corpus AutNum(%s) err = %v; want ErrNoPolicy", label, as, err)
			}
		}
		for name := range rtrNames {
			if _, err := got.InetRtr(ctx, name, ""); !errors.Is(err, resolve.ErrNoPolicy) {
				t.Fatalf("%s: plain corpus InetRtr(%s) err = %v; want ErrNoPolicy", label, name, err)
			}
		}
		return
	}
	for as := range asns {
		for _, src := range []string{"", "RIPE", "RADB", "NOSUCH"} {
			ga, gerr := got.AutNum(ctx, as, src)
			wa, werr := want.AutNum(ctx, as, src)
			if (gerr == nil) != (werr == nil) {
				t.Fatalf("%s: AutNum(%s, %q) err = %v; want %v", label, as, src, gerr, werr)
			}
			if gerr != nil {
				continue
			}
			if ga.Raw().String() != wa.Raw().String() || ga.AS != wa.AS || ga.AsName != wa.AsName || ga.Source != wa.Source {
				t.Fatalf("%s: AutNum(%s, %q) = %+v; want %+v", label, as, src, ga, wa)
			}
		}
	}
	for name := range rtrNames {
		for _, src := range []string{"", "RIPE", "RADB", "NOSUCH"} {
			gi, gerr := got.InetRtr(ctx, name, src)
			wi, werr := want.InetRtr(ctx, name, src)
			if (gerr == nil) != (werr == nil) {
				t.Fatalf("%s: InetRtr(%s, %q) err = %v; want %v", label, name, src, gerr, werr)
			}
			if gerr != nil {
				continue
			}
			if gi.Raw().String() != wi.Raw().String() || gi.Name != wi.Name || gi.LocalAS != wi.LocalAS || gi.Source != wi.Source {
				t.Fatalf("%s: InetRtr(%s, %q) = %+v; want %+v", label, name, src, gi, wi)
			}
		}
	}
}

func texts(objs []object.Object) []string {
	var out []string
	for _, o := range objs {
		out = append(out, o.Raw().String())
	}
	sort.Strings(out)
	return out
}

func distinct(ps []netip.Prefix) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p.String())
		}
	}
	sort.Strings(out)
	return out
}

// latest returns objs with one object per identity — class, primary key,
// source — the later one, at its own position: what a Corpus holds, since a
// registry has one object per key and a later one is an update. The model
// draws duplicates (two aut-nums for one AS in one source), which real
// registries cannot have.
func latest(objs []object.Object) []object.Object {
	id := func(o object.Object) string {
		src := ""
		if a, ok := o.Raw().GetFirst("source"); ok {
			src = strings.ToUpper(strings.TrimSpace(a.Value))
		}
		switch t := o.(type) {
		case object.NamedSet:
			return o.Class() + " " + t.SetName().String() + " " + src
		case *object.Route:
			return fmt.Sprintf("route %s%s %s", t.Prefix.Masked(), t.Origin, src)
		case *object.Route6:
			return fmt.Sprintf("route6 %s%s %s", t.Prefix.Masked(), t.Origin, src)
		case *object.AutNum:
			return fmt.Sprintf("aut-num %s %s", t.AS, src)
		case *object.InetRtr:
			return fmt.Sprintf("inet-rtr %s %s", strings.ToUpper(strings.TrimSpace(t.Name)), src)
		}
		return fmt.Sprintf("%p", o)
	}
	last := map[string]int{}
	for i, o := range objs {
		last[id(o)] = i
	}
	var out []object.Object
	for i, o := range objs {
		if last[id(o)] == i {
			out = append(out, o)
		}
	}
	return out
}

func corpusOf(objs []object.Object) *resolve.Corpus {
	c := &resolve.Corpus{}
	for _, o := range objs {
		c.Put(o)
	}
	return c
}

// A MemSource built from a Corpus answers as NewMemSource over the same
// objects does, and so expands every set to the oracle's answer, over the
// random IRRs of the model — two sources, precedence, claims honored and not,
// and objects the engine has no use for.
func TestCorpusMatchesMemSource(t *testing.T) {
	checked := 0
	seeds, full := resolve.ModelSeeds(1500)
	defer func() {
		if full && !t.Failed() && checked < 100 {
			t.Errorf("only %d seeds were checked against the oracle", checked)
		}
	}()
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 5))
		m := randomModel(r, false)
		texts := m.texts(r)
		objs := latest(decodeAll(t, texts))
		label := fmt.Sprintf("seed %d", seed)
		c := corpusOf(objs)
		// The random model draws no inet-rtrs; add a few (claiming and not, both
		// sources, sharing names so ties and precedence both get exercised) so
		// the policy comparison below covers InetRtr as well as AutNum.
		rtrTexts := []string{
			fmt.Sprintf("inet-rtr: rtr%d.example.net\nlocal-as: AS%d\nifaddr: 192.0.2.1 masklen 30\nsource: RIPE\n", r.IntN(3), firstAS+r.IntN(4)),
			fmt.Sprintf("inet-rtr: rtr%d.example.net\nlocal-as: AS%d\nifaddr: 192.0.2.2 masklen 30\nsource: RADB\n", r.IntN(3), firstAS+r.IntN(4)),
			fmt.Sprintf("inet-rtr: rtr%d.example.net\nlocal-as: AS%d\nmember-of: AS-X\nsource: RIPE\n", r.IntN(3), firstAS+r.IntN(4)),
			fmt.Sprintf("inet-rtr: rtr%d.example.net\nlocal-as: AS%d\nmember-of: AS-X\nsource: RADB\n", r.IntN(3), firstAS+r.IntN(4)),
		}
		policyObjs := latest(append(append([]object.Object(nil), objs...), decodeAll(t, rtrTexts)...))
		cp := &resolve.Corpus{KeepPolicy: true}
		for _, o := range policyObjs {
			cp.Put(o)
		}
		// What the model never draws but registries hold: an origin that does
		// not decode (on a claimant, and not), a prefix with host bits set.
		rs := fmt.Sprintf("RS-S%d", r.IntN(3))
		oddTexts := []string{
			fmt.Sprintf("route: 10.0.0.%d/29\norigin: AS%d\nsource: RIPE\n", 1+r.IntN(6), firstAS+r.IntN(4)),
			fmt.Sprintf("route: 10.0.0.0/30\norigin: ASX\nmember-of: %s\nmnt-by: MNT-A\nsource: RIPE\n", rs),
			fmt.Sprintf("route6: 2001:db8::1/126\norigin: AS%d\nmember-of: %s\nmnt-by: MNT-A\nsource: RIPE\n", firstAS, rs),
			"route: 10.0.0.4/30\norigin: ASY\nsource: RIPE\n",
		}
		odd := latest(append(append([]object.Object(nil), objs...), decodeAll(t, oddTexts)...))
		sameAnswers(t, label+" with odd routes", odd, corpusOf(odd).Source("RIPE", "RADB"), resolve.NewMemSource(odd, "RIPE", "RADB"), []string{"RIPE", "RADB"}, false)
		sameAnswers(t, label, policyObjs, cp.Source("RIPE", "RADB"), resolve.NewMemSource(policyObjs, "RIPE", "RADB"), []string{"RIPE", "RADB"}, true)
		sameAnswers(t, label+" without precedence", objs, c.Source(), resolve.NewMemSource(objs), []string{"RIPE", "RADB"}, false)
		if seed%5 == 0 && len(objs) == len(decodeAll(t, texts)) { // the oracle reads every object
			checkModel(t, label+" (corpus)", newOracle(m), texts, c.Source("RIPE", "RADB"), true)
			checked++
		}
		// SourceOf: one registry alone.
		var ripe []object.Object
		for _, o := range objs {
			if a, ok := o.Raw().GetFirst("source"); ok && strings.EqualFold(strings.TrimSpace(a.Value), "RIPE") {
				ripe = append(ripe, o)
			}
		}
		sameAnswers(t, label+" SourceOf(RIPE)", ripe, c.SourceOf("ripe"), resolve.NewMemSource(ripe, "ripe"), []string{"RIPE"}, false)
	}
}

func decodeOne(t *testing.T, text string) object.Object {
	t.Helper()
	raw, _ := rpsl.ParseObject(text)
	o, _ := rpsl.Decode(raw)
	return o
}

// TestCorpusKeeps: sets and objects that claim membership whole, other routes
// reduced, and nothing of the rest.
func TestCorpusKeeps(t *testing.T) {
	c := &resolve.Corpus{}
	for _, tc := range []struct {
		text string
		kept bool
	}{
		{"as-set: AS-X\nmembers: AS1\nsource: RIPE\n", true},
		{"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n", true},
		{"route: 198.51.100.0/24\norigin: AS1\nmember-of: RS-X\nmnt-by: M\nsource: RIPE\n", true},
		{"aut-num: AS1\nas-name: X\nmember-of: AS-X\nsource: RIPE\n", true},
		{"aut-num: AS2\nas-name: Y\nsource: RIPE\n", false},           // claims nothing: no expansion reads it
		{"person: A\nnic-hdl: A1-RIPE\nsource: RIPE\n", false},        // not the engine's
		{"route: 203.0.113.0/24\norigin: ASX\nsource: RIPE\n", false}, // no AS's route
		{"route: 203.0.113.0/24\nsource: RIPE\n", false},              // no origin at all
	} {
		if got := c.Put(decodeOne(t, tc.text)); got != tc.kept {
			t.Errorf("Put(%q) = %v, want %v", tc.text, got, tc.kept)
		}
	}
	if c.Len() != 4 {
		t.Errorf("Len = %d, want 4", c.Len())
	}
	var nilRoute *object.Route
	if c.Put(nilRoute) {
		t.Error("a nil *Route was kept")
	}
	r := decodeOne(t, "route: 10.0.0.0/8\norigin: AS7\nsource: RIPE\n").(*object.Route)
	if !c.Put(r) || c.Len() != 5 {
		t.Error("a *Route was not kept")
	}
}

// TestCorpusReplaces: an object replaces the one with its class, primary key
// and source — whole or reduced, either way round — and a replacement the
// engine has no use for removes the old one.
func TestCorpusReplaces(t *testing.T) {
	ctx := context.Background()
	routes := func(c *resolve.Corpus, as types.ASN) []string {
		ps, _ := c.Source().OriginatedRoutes(ctx, as, types.AFIAny)
		return distinct(ps)
	}
	c := &resolve.Corpus{}
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n"))
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nsource: RADB\n")) // another source: both kept
	if c.Len() != 2 {
		t.Fatalf("Len = %d", c.Len())
	}
	// The same route gains member-of: now whole, still one object.
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: as1\nmember-of: RS-X\nmnt-by: M\nsource: ripe\n"))
	if c.Len() != 2 || !slices.Equal(routes(c, 1), []string{"192.0.2.0/24"}) {
		t.Fatalf("after gaining member-of: Len %d, routes %v", c.Len(), routes(c, 1))
	}
	set := decodeOne(t, "route-set: RS-X\nmbrs-by-ref: ANY\nsource: RIPE\n")
	c.Put(set)
	if m, _ := c.Source().MembersByRef(ctx, set.(object.NamedSet)); len(m) != 1 {
		t.Fatalf("claimants %v", m)
	}
	// ... and loses it: reduced again, and no longer a claimant.
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n"))
	if m, _ := c.Source().MembersByRef(ctx, set.(object.NamedSet)); len(m) != 0 || c.Len() != 3 {
		t.Fatalf("after losing member-of: claimants %v, Len %d", m, c.Len())
	}
	// An aut-num that stops claiming membership is gone.
	c.Put(decodeOne(t, "aut-num: AS1\nas-name: X\nmember-of: AS-X\nsource: RIPE\n"))
	if c.Put(decodeOne(t, "aut-num: AS1\nas-name: X\nsource: RIPE\n")) || c.Len() != 3 {
		t.Fatalf("an aut-num that no longer claims: Len %d", c.Len())
	}
	// A set replaced keeps one version.
	c.Put(decodeOne(t, "as-set: AS-Y\nmembers: AS1\nsource: RIPE\n"))
	c.Put(decodeOne(t, "as-set: as-y\nmembers: AS2\nsource: RIPE\n"))
	n, _ := types.ParseSetName("AS-Y")
	s, _ := c.Source().GetSet(ctx, types.Ref(n))
	if as := s.(*object.AsSet); len(as.Members) != 1 || as.Members[0].AS != 2 {
		t.Fatalf("AS-Y = %+v", as.Members)
	}
}

func TestCorpusDelete(t *testing.T) {
	c := &resolve.Corpus{}
	c.Put(decodeOne(t, "route6: 2001:db8::/32\norigin: AS1\nsource: RIPE\n"))
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-X\nsource: RIPE\n"))
	c.Put(decodeOne(t, "as-set: AS1:AS-FOO\nsource: RIPE\n"))
	c.Put(decodeOne(t, "aut-num: AS1\nmember-of: AS1:AS-FOO\nsource: RIPE\n"))
	for _, d := range [][3]string{
		{"ROUTE6", "2001:DB8::/32as1", "ripe"}, // reduced, spelled otherwise
		{"route", "192.0.2.0/24AS1", "RIPE"},   // whole
		{"as-set", "as1:as-foo", "RIPE"},       // a set
		{"aut-num", "as1", "RIPE"},             // an aut-num
	} {
		if !c.Delete(d[0], d[1], d[2]) {
			t.Errorf("Delete(%v) found nothing", d)
		}
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d after deleting everything", c.Len())
	}
	if c.Delete("route", "192.0.2.0/24AS1", "RIPE") || c.Delete("route", "not a key", "RIPE") {
		t.Error("deleted twice, or deleted junk")
	}
}

// TestCorpusMerge: another corpus's objects join, a same-keyed one replacing;
// ties between sources still go to the object loaded first.
func TestCorpusMerge(t *testing.T) {
	a, b := &resolve.Corpus{}, &resolve.Corpus{}
	a.Put(decodeOne(t, "as-set: AS-X\nmembers: AS1\nsource: ALTDB\n"))
	b.Put(decodeOne(t, "as-set: AS-X\nmembers: AS2\nsource: NTTCOM\n"))
	b.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS2\nsource: NTTCOM\n"))
	a.Merge(b)
	if a.Len() != 3 || b.Len() != 2 {
		t.Fatalf("Len %d, %d", a.Len(), b.Len())
	}
	n, _ := types.ParseSetName("AS-X")
	s, _ := a.Source().GetSet(context.Background(), types.Ref(n)) // no precedence: the first loaded
	if s.SetSource() != "ALTDB" {
		t.Errorf("a tie went to %s", s.SetSource())
	}
	s, _ = a.Source("NTTCOM").GetSet(context.Background(), types.Ref(n))
	if s.SetSource() != "NTTCOM" {
		t.Errorf("precedence gave %s", s.SetSource())
	}
	// Every build answers in one order.
	for i := 0; i < 5; i++ {
		c := &resolve.Corpus{}
		for _, p := range []string{"203.0.113.0/24", "10.0.0.0/8", "2001:db8::/32", "10.0.0.0/16", "192.0.2.0/24"} {
			c.Put(decodeOne(t, fmt.Sprintf("route: %s\norigin: AS9\nsource: X\n", p)))
		}
		ps, _ := c.Source().OriginatedRoutes(context.Background(), 9, types.AFIAny)
		if got := fmt.Sprint(ps); got != "[10.0.0.0/8 10.0.0.0/16 192.0.2.0/24 203.0.113.0/24 2001:db8::/32]" {
			t.Fatalf("routes in the order %s", got)
		}
	}
	// The source a MemSource was built from does not change with the corpus.
	src := a.Source()
	a.Delete("route", "192.0.2.0/24AS2", "NTTCOM")
	if ps, _ := src.OriginatedRoutes(context.Background(), 2, types.AFIAny); len(ps) != 1 {
		t.Errorf("a built MemSource changed: %v", ps)
	}
}

// TestCorpusMergePolicyText: review fix round 1, findings 3 and 4. A merged
// corpus's aut-num/inet-rtr text entries (KeepPolicy) keep load order, a
// same-identity text entry replaces a whole (claimant) one, source names are
// interned (so Delete afterwards finds them), and a target without KeepPolicy
// drops them, as Put would the non-claiming object they represent.
func TestCorpusMergePolicyText(t *testing.T) {
	ctx := context.Background()

	// Same identity: a whole claimant is replaced by a merged text entry.
	a := &resolve.Corpus{KeepPolicy: true}
	a.Put(decodeOne(t, "aut-num: AS1\nas-name: CLAIM\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n")) // whole
	b := &resolve.Corpus{KeepPolicy: true}
	b.Put(decodeOne(t, "aut-num: AS1\nas-name: PLAIN\nsource: RIPE\n")) // text: same identity, no longer claims
	a.Merge(b)
	if a.Len() != 1 {
		t.Fatalf("Len = %d after merging one aut-num over itself, want 1", a.Len())
	}
	if an, err := a.Source().AutNum(ctx, 1, ""); err != nil || an.AsName != "PLAIN" {
		t.Fatalf("merged AS1 = %+v, %v; want PLAIN (the whole claimant is replaced)", an, err)
	}
	// Source interning: Delete after the merge still finds it.
	if !a.Delete("aut-num", "AS1", "RIPE") || a.Len() != 0 {
		t.Fatalf("Delete after merge: found nothing, Len %d", a.Len())
	}

	// Ordering: ties between sources outside the precedence go to load order
	// across the merge — the target's own entry, loaded before the merge, wins.
	c1 := &resolve.Corpus{KeepPolicy: true}
	c1.Put(decodeOne(t, "aut-num: AS2\nas-name: FIRST\nsource: ALTDB\n"))
	c2 := &resolve.Corpus{KeepPolicy: true}
	c2.Put(decodeOne(t, "aut-num: AS2\nas-name: SECOND\nsource: NTTCOM\n"))
	c1.Merge(c2)
	if an, err := c1.Source().AutNum(ctx, 2, ""); err != nil || an.AsName != "FIRST" {
		t.Fatalf("tied merge = %+v, %v; want FIRST (loaded before the merge)", an, err)
	}
	if an, err := c1.Source().AutNum(ctx, 2, "NTTCOM"); err != nil || an.AsName != "SECOND" {
		t.Fatalf("scoped lookup after merge = %+v, %v; want SECOND", an, err)
	}

	// A target without KeepPolicy drops a merged text entry, as Put would the
	// non-claiming object it represents.
	plain := &resolve.Corpus{}
	src := &resolve.Corpus{KeepPolicy: true}
	src.Put(decodeOne(t, "aut-num: AS3\nas-name: DROPPED\nsource: RIPE\n"))
	plain.Merge(src)
	if plain.Len() != 0 {
		t.Fatalf("Len = %d after merging a text entry into a plain corpus, want 0", plain.Len())
	}
	if _, err := plain.Source().AutNum(ctx, 3, ""); !errors.Is(err, resolve.ErrNoPolicy) {
		t.Errorf("a plain corpus answered a policy lookup: %v; want ErrNoPolicy", err)
	}
	// A whole claimant merged into a plain corpus is unaffected by that rule:
	// it is held, as a claimant (a plain corpus serves no policy objects).
	plain2 := &resolve.Corpus{}
	claim := &resolve.Corpus{KeepPolicy: true}
	claim.Put(decodeOne(t, "aut-num: AS4\nas-name: CLAIM4\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n"))
	plain2.Merge(claim)
	if plain2.Len() != 1 {
		t.Fatalf("a plain corpus dropped a merged whole claimant: Len = %d", plain2.Len())
	}
	if _, err := plain2.Source().AutNum(ctx, 4, ""); !errors.Is(err, resolve.ErrNoPolicy) {
		t.Errorf("a plain corpus answered a policy lookup: %v; want ErrNoPolicy", err)
	}
}

// TestCorpusMemory holds a reduced route to a bound on the heap: its prefix,
// origin and source, not the decoded object (4.7 KB for a RIPE route).
func TestCorpusMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the heap")
	}
	const n = 100_000
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	c := &resolve.Corpus{}
	for i := 0; i < n; i++ {
		text := fmt.Sprintf("route: 10.%d.%d.0/24\ndescr: a route with the remarks RIPE adds\norigin: AS%d\nmnt-by: MNT-X\n"+
			"remarks: ****************************\nremarks: * THIS OBJECT IS MODIFIED\nsource: RIPE\n", i>>8&255, i&255, 64500+i%1000)
		c.Put(decodeOne(t, text))
	}
	per := (heap() - before) / n
	if per > 300 {
		t.Errorf("%d bytes per reduced route, want at most 300", per)
	}
	t.Logf("%d bytes per reduced route", per)
	runtime.KeepAlive(c)
}

// Review regressions (v0.19.0).

// A primary key whose upper-case form is longer than itself ("ɐ" is two
// bytes, "Ɐ" three) must not panic Delete.
func TestCorpusDeleteUnicodeKey(t *testing.T) {
	c := &resolve.Corpus{}
	c.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n"))
	if c.Delete("route", strings.Repeat("ɐ", 10)+"AS1", "TEST") {
		t.Error("deleted a junk key")
	}
	if c.Delete("route6", "2001:db8::/32ɐas1", "TEST") {
		t.Error("deleted a junk key")
	}
}

// A route whose origin does not decode still claims membership, as
// NewMemSource reads it: a route-set's member is not lost.
func TestCorpusKeepsClaimantWithBadOrigin(t *testing.T) {
	objs := []object.Object{
		decodeOne(t, "route-set: RS-FOO\nmbrs-by-ref: ANY\nsource: TEST\n"),
		decodeOne(t, "route: 192.0.2.0/24\norigin: ASX\nmember-of: RS-FOO\nsource: TEST\n"),
	}
	n, _ := types.ParseSetName("RS-FOO")
	ctx := context.Background()
	want, err := (&resolve.Expander{Src: resolve.NewMemSource(objs)}).ExpandPrefixes(ctx, types.Ref(n))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&resolve.Expander{Src: corpusOf(objs).Source()}).ExpandPrefixes(ctx, types.Ref(n))
	if err != nil || !slices.Equal(got.List(), want.List()) {
		t.Errorf("corpus %v (%v), NewMemSource %v", got.List(), err, want.List())
	}
}

// Routes are answered as decoded, host bits and all, as NewMemSource answers.
func TestCorpusKeepsPrefixAsDecoded(t *testing.T) {
	objs := []object.Object{decodeOne(t, "route: 192.0.2.1/24\norigin: AS1\nsource: TEST\n")}
	ctx := context.Background()
	got, _ := corpusOf(objs).Source().OriginatedRoutes(ctx, 1, types.AFIAny)
	want, _ := resolve.NewMemSource(objs).OriginatedRoutes(ctx, 1, types.AFIAny)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("corpus %v, NewMemSource %v", got, want)
	}
}

// Merging a whole route over a reduced one of the same identity leaves one.
func TestCorpusMergeReplacesReduced(t *testing.T) {
	a, b := &resolve.Corpus{}, &resolve.Corpus{}
	a.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n"))
	b.Put(decodeOne(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-X\nsource: TEST\n"))
	a.Merge(b)
	if a.Len() != 1 {
		t.Fatalf("Len %d after merging one route over itself", a.Len())
	}
	a.Delete("route", "192.0.2.0/24AS1", "TEST")
	if ps, _ := a.Source().OriginatedRoutes(context.Background(), 1, types.AFIAny); len(ps) != 0 || a.Len() != 0 {
		t.Errorf("after Delete: %v, Len %d", ps, a.Len())
	}
}

// An update keeps an object's place in load order: ties between sources
// not in the precedence still go to the object loaded first.
func TestCorpusUpdateKeepsLoadOrder(t *testing.T) {
	c := &resolve.Corpus{}
	c.Put(decodeOne(t, "as-set: AS-FOO\nmembers: AS1\nsource: A\n"))
	c.Put(decodeOne(t, "as-set: AS-FOO\nmembers: AS2\nsource: B\n"))
	c.Put(decodeOne(t, "as-set: AS-FOO\nmembers: AS3\nsource: A\n")) // A updated
	n, _ := types.ParseSetName("AS-FOO")
	s, _ := c.Source().GetSet(context.Background(), types.Ref(n))
	if s.SetSource() != "A" {
		t.Errorf("after A's update, %s's AS-FOO wins", s.SetSource())
	}
}

// FuzzCorpusDelete: no class or primary key panics Delete.
func FuzzCorpusDelete(f *testing.F) {
	f.Add("route", "192.0.2.0/24AS1")
	f.Add("route6", "2001:db8::/32as1")
	f.Add("route", strings.Repeat("ɐ", 10)+"AS1")
	f.Add("as-set", "AS1:AS-FOO")
	f.Fuzz(func(t *testing.T, class, pk string) {
		c := &resolve.Corpus{}
		c.Put(decodeOneF(t, "route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n"))
		c.Delete(class, pk, "TEST")
	})
}

func decodeOneF(t *testing.T, text string) object.Object {
	raw, _ := rpsl.ParseObject(text)
	o, _ := rpsl.Decode(raw)
	return o
}

// ExpandableClass is Expandable by class name: for each class, a decoded
// object is Expandable exactly when its class name is ExpandableClass.
func TestExpandableClassAgrees(t *testing.T) {
	for _, text := range []string{
		"as-set: AS-X\nsource: T\n", "route-set: RS-X\nsource: T\n", "rtr-set: RTRS-X\nsource: T\n",
		"filter-set: FLTR-X\nfilter: ANY\nsource: T\n", "peering-set: PRNG-X\nsource: T\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: T\n", "route6: 2001:db8::/32\norigin: AS1\nsource: T\n",
		"aut-num: AS1\nsource: T\n", "inet-rtr: rtr.example.net\nsource: T\n",
		"person: A\nnic-hdl: A1-T\nsource: T\n", "mntner: M\nsource: T\n", "inetnum: 192.0.2.0 - 192.0.2.255\nsource: T\n",
	} {
		o := decodeOne(t, text)
		if resolve.Expandable(o) != resolve.ExpandableClass(o.Class()) {
			t.Errorf("%s: Expandable %v, ExpandableClass %v", o.Class(), resolve.Expandable(o), resolve.ExpandableClass(o.Class()))
		}
	}
	if !resolve.ExpandableClass(" AS-SET ") {
		t.Error("ExpandableClass is not case- and space-blind")
	}
}

// TestCorpusKeepRouteText: with KeepRouteText a reduced route keeps its text
// (from its first attribute line), a replacement replaces it, Delete removes
// it, Merge carries it into a corpus that keeps text and drops it into one
// that does not; without the flag no text is kept.
func TestCorpusKeepRouteText(t *testing.T) {
	text := "route: 192.0.2.0/24\norigin: AS1\ndescr: one\nsource: RIPE\n"
	textOf := func(c *resolve.Corpus, p string, as types.ASN) (string, bool) {
		for r := range c.Routes() {
			if r.Prefix.String() == p && r.Origin == as {
				return r.Text, true
			}
		}
		return "", false
	}

	plain := &resolve.Corpus{}
	plain.Put(decodeOne(t, text))
	if got, ok := textOf(plain, "192.0.2.0/24", 1); !ok || got != "" {
		t.Errorf("without KeepRouteText: %q, %v", got, ok)
	}

	c := &resolve.Corpus{KeepRouteText: true}
	c.Put(decodeOne(t, "# a comment the stream attached\n"+text))
	if got, _ := textOf(c, "192.0.2.0/24", 1); got != text {
		t.Errorf("kept %q, want %q", got, text)
	}
	c.Put(decodeOne(t, strings.Replace(text, "one", "two", 1)))
	if got, _ := textOf(c, "192.0.2.0/24", 1); !strings.Contains(got, "descr: two") {
		t.Errorf("a replacement kept %q", got)
	}
	if !c.Delete("route", "192.0.2.0/24AS1", "RIPE") {
		t.Fatal("Delete found nothing")
	}
	if _, ok := textOf(c, "192.0.2.0/24", 1); ok {
		t.Error("a deleted route is still there")
	}

	src := &resolve.Corpus{KeepRouteText: true}
	src.Put(decodeOne(t, text))
	dst := &resolve.Corpus{KeepRouteText: true}
	dst.Merge(src)
	if got, _ := textOf(dst, "192.0.2.0/24", 1); got != text {
		t.Errorf("Merge carried %q", got)
	}
	bare := &resolve.Corpus{}
	bare.Merge(src)
	if got, ok := textOf(bare, "192.0.2.0/24", 1); !ok || got != "" {
		t.Errorf("Merge into a corpus without KeepRouteText: %q, %v", got, ok)
	}
}

// TestCorpusRoutes: Routes yields every route and route6 the corpus holds,
// reduced and whole (a member-of claimant), once each, with the claimant's
// text whatever KeepRouteText says, and nothing for a route with no valid
// prefix or origin.
func TestCorpusRoutes(t *testing.T) {
	c := &resolve.Corpus{}
	for _, text := range []string{
		"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n",
		"route6: 2001:db8::/32\norigin: AS1\nsource: RADB\n",
		"route: 198.51.100.0/24\norigin: AS2\nmember-of: RS-X\nmnt-by: M\nsource: RIPE\n",
		"route: 203.0.113.0/24\norigin: ASX\nmember-of: RS-X\nmnt-by: M\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
	} {
		c.Put(decodeOne(t, text))
	}
	var got []string
	for r := range c.Routes() {
		got = append(got, fmt.Sprintf("%s %s %s %v", r.Prefix, r.Origin, r.Source, r.Text != ""))
	}
	sort.Strings(got)
	want := []string{
		"192.0.2.0/24 AS1 RIPE false",
		"198.51.100.0/24 AS2 RIPE true",
		"2001:db8::/32 AS1 RADB false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Routes:\n got %q\nwant %q", got, want)
	}
	for r := range c.Routes() {
		if r.Origin == 2 && !strings.HasPrefix(r.Text, "route: 198.51.100.0/24\n") {
			t.Errorf("a claimant's text: %q", r.Text)
		}
	}
	// Breaking out of the loop early is allowed.
	for range c.Routes() {
		break
	}
}

// TestCorpusWhole: Whole yields the sets and member-of claimants, in load
// order, and nothing kept only as text or as a route tuple.
func TestCorpusWhole(t *testing.T) {
	c := &resolve.Corpus{KeepPolicy: true}
	for _, text := range []string{
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
		"aut-num: AS1\nas-name: ONE\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n",
		"aut-num: AS2\nas-name: TWO\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n",
		"route-set: RS-X\nmembers: 10.0.0.0/8\nsource: RIPE\n",
	} {
		c.Put(decodeOne(t, text))
	}
	var got []string
	for o := range c.Whole() {
		got = append(got, o.Class())
	}
	if want := []string{"as-set", "aut-num", "route-set"}; !slices.Equal(got, want) {
		t.Errorf("Whole: %q, want %q", got, want)
	}
}

func TestDumpLoaderKeepsPolicy(t *testing.T) {
	l := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(strings.Join(policyTexts, "\n"))); err != nil {
		t.Fatalf("Read: %v", err)
	}
	checkPolicy(t, "DumpLoader", l.Source())
	// Without KeepPolicy the loader's sources serve no policy objects.
	plain := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}}
	if err := plain.Read(strings.NewReader(strings.Join(policyTexts, "\n"))); err != nil {
		t.Fatalf("Read: %v", err)
	}
	for label, src := range map[string]*resolve.MemSource{"Source": plain.Source(), "SourceOf": plain.SourceOf("RIPE")} {
		if _, err := src.AutNum(context.Background(), 3, ""); !errors.Is(err, resolve.ErrNoPolicy) {
			t.Errorf("DumpLoader without KeepPolicy, %s: AutNum = %v; want ErrNoPolicy", label, err)
		}
	}
}

// TestObjectText: an object's text runs from its first attribute line to its
// last attribute or continuation line, without the blank, comment and
// malformed lines a dump stream attached before it or, to its last object,
// after it; a comment line between its attributes stays.
func TestObjectText(t *testing.T) {
	dump := "# head\n\nroute: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n\n# tail\nEOF\n\n"
	var got []string
	for o := range rpsl.Parse(strings.NewReader(dump)) {
		got = append(got, resolve.ObjectText(o))
	}
	want := []string{"route: 192.0.2.0/24\n# inside\norigin: AS1\nremarks: a\n+\n b\nsource: RIPE\n"}
	if !slices.Equal(got, want) {
		t.Errorf("ObjectText:\n got %q\nwant %q", got, want)
	}
	l := &resolve.DumpLoader{KeepRouteText: true}
	if err := l.Read(strings.NewReader(dump)); err != nil {
		t.Fatal(err)
	}
	for r := range l.Corpus().Routes() {
		if r.Text != want[0] {
			t.Errorf("kept route text %q, want %q", r.Text, want[0])
		}
	}
}

// TestObjectTextKeepsAttributesAfterABlankLine: an object parsed on its own
// (rpsl.ParseObject, as the NRTMv4 client builds them) keeps attributes after
// an internal blank line, and ObjectText keeps them too — a Corpus that kept
// less would serve an aut-num without the imports its peer index read.
func TestObjectTextKeepsAttributesAfterABlankLine(t *testing.T) {
	text := "aut-num: AS1\nas-name: A\n\nimport: from AS2 accept ANY\nsource: RIPE\n"
	o, _ := rpsl.ParseObject(text + "# trailing\nEOF\n\n")
	if got := resolve.ObjectText(o); got != text {
		t.Errorf("ObjectText: %q, want %q", got, text)
	}
	obj, _ := rpsl.Decode(o)
	c := &resolve.Corpus{IndexPeers: true}
	c.Put(obj)
	an, err := c.Source().AutNum(context.Background(), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(an.Imports) != 1 {
		t.Errorf("served %d imports, want 1", len(an.Imports))
	}
}

// TestObjectTextLineRules: ObjectText reads lines as the lexer does. A line
// led by a space, a tab or '+' continues an attribute only right after an
// attribute or continuation line; after a blank, comment or malformed line it
// is malformed (lexer/malformed-line), and trailing it is dropped like any
// other trivia.
func TestObjectTextLineRules(t *testing.T) {
	const obj = "aut-num: AS1\nsource: RIPE\n"
	for _, c := range []struct{ text, want string }{
		{obj + "\n stray\n", obj},
		{obj + "\n+\n", obj},
		{obj + "\n  # c\n", obj},
		{obj + "# c\n stray\n", obj},
		{obj + "EOF\n\tstray\n", obj},
		{"aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n\r\n  # c\r\n", "aut-num: AS1\r\nremarks: a\r\n b\r\n+\r\nsource: RIPE\r\n"},
		{"aut-num: AS1\n\n stray\nsource: RIPE\n\n stray\n", "aut-num: AS1\n\n stray\nsource: RIPE\n"},
		{"aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n", "aut-num: AS1\nremarks: a\n b\n\tc\n+ d\n"},
	} {
		o, _ := rpsl.ParseObject(c.text)
		if got := resolve.ObjectText(o); got != c.want {
			t.Errorf("ObjectText(%q) = %q, want %q", c.text, got, c.want)
		}
	}
	// In a dump stream the last object owns the dump's closing lines.
	var got []string
	for o := range rpsl.Parse(strings.NewReader("as-set: AS-X\nsource: RIPE\n\n" + obj + "\n  # closing\n")) {
		got = append(got, resolve.ObjectText(o))
	}
	if want := []string{"as-set: AS-X\nsource: RIPE\n", obj}; !slices.Equal(got, want) {
		t.Errorf("stream: %q, want %q", got, want)
	}
}
