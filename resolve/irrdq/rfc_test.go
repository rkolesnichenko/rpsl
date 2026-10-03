package irrdq

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// fixtureObjects are the goldens' fixture objects, RIPE's then RADB's,
// decoded.
func fixtureObjects(t *testing.T) []object.Object {
	t.Helper()
	var objs []object.Object
	dir := irrdoracle.Fixture(t)
	for _, file := range []string{"ripe.db", "radb.db"} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range strings.Split(string(b), "\n\n") {
			if o, _ := rpsl.ParseObject(text); o != nil && o.Class() != "" {
				obj, _ := rpsl.Decode(o)
				objs = append(objs, obj)
			}
		}
	}
	return objs
}

// engineMembers is the engine's "!i<name>,1" answer over e, framed as IRRd
// frames it (words sorted as strings), and the engine's error.
func engineMembers(t *testing.T, e *resolve.Expander, name string) (string, error) {
	t.Helper()
	n, err := types.ParseSetName(name)
	if err != nil {
		t.Fatal(name, err)
	}
	var words []string
	ctx := context.Background()
	if n.Class() == types.ClassRouteSet {
		rs, err := e.ExpandPrefixRanges(ctx, types.Ref(n))
		if err != nil {
			return "", err
		}
		for _, r := range rs.List() {
			words = append(words, r.String())
		}
	} else {
		as, err := e.ExpandAS(ctx, types.Ref(n))
		if err != nil {
			return "", err
		}
		for _, a := range as.List() {
			words = append(words, a.String())
		}
	}
	slices.Sort(words)
	return frameWords(words), nil
}

// enginePrefixes is the engine's "!a" answer over e for afi, framed.
func enginePrefixes(t *testing.T, e *resolve.Expander, name string, afi types.AFI) (string, error) {
	t.Helper()
	n, err := types.ParseSetName(name)
	if err != nil {
		t.Fatal(name, err)
	}
	c := *e
	c.AFI = afi
	ps, err := c.ExpandPrefixes(context.Background(), types.Ref(n))
	if err != nil {
		return "", err
	}
	list := ps.List()
	slices.SortFunc(list, prefixCmp)
	words := make([]string, len(list))
	for i, p := range list {
		words[i] = p.String()
	}
	return frameWords(words), nil
}

// frameWords is the answer listing words, or "D" when there are none.
func frameWords(words []string) string {
	if len(words) == 0 {
		return "D\n"
	}
	return "A" + itoa(len(strings.Join(words, " "))+1) + "\n" + strings.Join(words, " ") + "\nC\n"
}

func itoa(i int) string { return strconv.Itoa(i) }

// anyRefusal is RFC mode's answer for an expansion reaching AS-ANY.
const anyRefusal = "F AS-ANY denotes the whole registry: not expanded in RFC mode\n"

// TestRFCMode: with RFC set, !i…,1 and !a answer what resolve.Expander
// answers over the same objects (a MemSource with precedence RIPE, RADB),
// formatted as IRRd formats them; every other command is unchanged.
func TestRFCMode(t *testing.T) {
	rfc := fixture(t, SnapshotOptions{RFC: true})
	plain := fixture(t, SnapshotOptions{})
	e := &resolve.Expander{Src: resolve.NewMemSource(fixtureObjects(t), "RIPE", "RADB")}
	for _, name := range []string{"RS-INNER", "AS-REF", "RS-NOLEN", "AS-NORM"} {
		want, err := engineMembers(t, e, name)
		if err != nil {
			t.Fatal(name, err)
		}
		if got := ask(t, rfc, "!i"+name+",1"); got != want {
			t.Errorf("RFC !i%s,1: %q, want %q", name, got, want)
		}
	}
	// AS-FOO lists AS-ANY; RS-FOO, AS-BAR and AS-RADBONLY reach it through
	// AS-FOO (R7). The engine refuses each, and so does RFC mode.
	for _, name := range []string{"AS-FOO", "RS-FOO", "AS-BAR", "AS-RADBONLY"} {
		_, err := engineMembers(t, e, name)
		var anySet *resolve.AnySetError
		if !errors.As(err, &anySet) || anySet.Name.String() != "AS-ANY" {
			t.Fatalf("the engine's %s: %v, want AS-ANY's AnySetError", name, err)
		}
		if got := ask(t, rfc, "!i"+name+",1"); got != anyRefusal {
			t.Errorf("RFC !i%s,1: %q, want %q", name, got, anyRefusal)
		}
	}
	for _, c := range []struct {
		send, name string
		afi        types.AFI
	}{
		{"!aAS-REF", "AS-REF", types.AFIAny},
		{"!a4AS-REF", "AS-REF", types.AFIv4},
		{"!a6AS-REF", "AS-REF", types.AFIv6},
		{"!aAS-NORM", "AS-NORM", types.AFIAny},
		{"!aAS-EMPTY", "AS-EMPTY", types.AFIAny},
	} {
		want, err := enginePrefixes(t, e, c.name, c.afi)
		if err != nil {
			t.Fatal(c.send, err)
		}
		if got := ask(t, rfc, c.send); got != want {
			t.Errorf("RFC %s: %q, want %q", c.send, got, want)
		}
	}
	for _, send := range []string{"!aAS-FOO", "!a4AS-BAR", "!aAS-RADBONLY", "!iAS-ANY,1", "!aAS-ANY"} {
		if got := ask(t, rfc, send); got != anyRefusal {
			t.Errorf("RFC %s: %q, want %q", send, got, anyRefusal)
		}
	}
	if got := ask(t, rfc, "!iRS-ANY,1"); got != "F RS-ANY denotes the whole registry: not expanded in RFC mode\n" {
		t.Errorf("RFC !iRS-ANY,1: %q", got)
	}
	// Nothing to expand: a missing set, a name of neither class, a route-set
	// for !a, a set of another class than its name's.
	for _, send := range []string{"!iAS-MISSING,1", "!aAS-MISSING", "!iFLTR-FOO,1", "!iAS65001,1", "!aRS-FOO", "!a4RS-FOO"} {
		if got := ask(t, rfc, send); got != "D\n" {
			t.Errorf("RFC %s: %q, want D", send, got)
		}
	}
	for _, cmd := range []string{"!iRS-FOO", "!iAS-FOO", "!gAS65001", "!6AS65001", "!mas-set,AS-FOO",
		"!r192.0.2.0/24,o", "!r192.0.2.0/24,M", "-i origin AS65001", "-i member-of RS-INNER", "!iAS-FOO,2", "!s-lc"} {
		if a, b := ask(t, rfc, cmd), ask(t, plain, cmd); a != b {
			t.Errorf("RFC mode changed %s: %q, plain %q", cmd, a, b)
		}
	}
}

// TestRFCModeSelection: RFC mode expands over the session's selection, in
// its order.
func TestRFCModeSelection(t *testing.T) {
	rfc := fixture(t, SnapshotOptions{RFC: true})
	objs := fixtureObjects(t)
	for _, c := range []struct {
		sel  string
		srcs []string
	}{{"RADB", []string{"RADB"}}, {"RIPE", []string{"RIPE"}}, {"RADB,RIPE", []string{"RADB", "RIPE"}}} {
		// The objects of the selected registries only: a MemSource ranks a
		// source its precedence leaves out last, where !s leaves it out.
		var sel []object.Object
		for _, o := range objs {
			if o.Raw() != nil && slices.Contains(c.srcs, sourceOfRaw(o.Raw())) {
				sel = append(sel, o)
			}
		}
		e := &resolve.Expander{Src: resolve.NewMemSource(sel, c.srcs...)}
		for _, name := range []string{"AS-FOO", "AS-REF", "RS-INNER", "AS-RADBONLY"} {
			want, err := engineMembers(t, e, name)
			var anySet *resolve.AnySetError
			if errors.As(err, &anySet) {
				want = "F " + anySet.Name.String() + " denotes the whole registry: not expanded in RFC mode\n"
			} else if errors.Is(err, resolve.ErrNotFound) {
				want = "D\n"
			} else if err != nil {
				t.Fatal(name, err)
			}
			s := NewSession(func() *Snapshot { return rfc })
			s.Do(context.Background(), "!!")
			s.Do(context.Background(), "!s"+c.sel)
			r, err := s.Do(context.Background(), "!i"+name+",1")
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			r.WriteTo(&b)
			if got := b.String(); got != want {
				t.Errorf("!s%s, RFC !i%s,1: %q, want %q", c.sel, name, got, want)
			}
		}
	}
}

// TestRFCModeRPKI: RFC mode in RPKI-aware mode expands without the routes
// IRRd hides — what the engine answers over the objects through
// rpki.Filter — and the pseudo registry's routes are never hidden.
func TestRFCModeRPKI(t *testing.T) {
	base := fixtureRPKI(t)
	opts := base.opts
	opts.RFC = true
	rfc, err := NewSnapshot(base.Registries(), opts)
	if err != nil {
		t.Fatal(err)
	}
	e := &resolve.Expander{Src: &rpki.Filter{Src: resolve.NewMemSource(fixtureObjects(t), "RIPE", "RADB"), VRPs: opts.VRPs}}
	for _, name := range []string{"RS-INNER", "AS-REF", "RS-NOLEN", "AS-NORM"} {
		want, err := engineMembers(t, e, name)
		if err != nil {
			t.Fatal(name, err)
		}
		if got := ask(t, rfc, "!i"+name+",1"); got != want {
			t.Errorf("RFC+RPKI !i%s,1: %q, want %q", name, got, want)
		}
	}
	// RS-INNER's claimants are both RPKI-invalid (golden rpki/!iRS-INNER).
	if got := ask(t, rfc, "!iRS-INNER,1"); got != framed("192.0.2.128/25 198.18.0.0/15^16-24") {
		t.Errorf("RFC+RPKI !iRS-INNER,1: %q", got)
	}
	for _, c := range []struct {
		send, name string
		afi        types.AFI
	}{{"!aAS-REF", "AS-REF", types.AFIAny}, {"!a4AS-REF", "AS-REF", types.AFIv4}, {"!aAS-NORM", "AS-NORM", types.AFIAny}} {
		want, err := enginePrefixes(t, e, c.name, c.afi)
		if err != nil {
			t.Fatal(c.send, err)
		}
		if got := ask(t, rfc, c.send); got != want {
			t.Errorf("RFC+RPKI %s: %q, want %q", c.send, got, want)
		}
	}
	// The AS0 pseudo route is RPKI-invalid by RFC 6811 (AS0 never matches),
	// yet the pseudo registry's routes are never hidden, as in IRRd mode.
	snap, err := NewSnapshot(append(base.Registries(), mustRegistry(t, "LOCAL",
		"as-set: AS-ZERO\nmembers: AS0\nsource: LOCAL\n")), func() SnapshotOptions {
		o := opts
		o.Default = []string{"LOCAL", "RPKI"}
		return o
	}())
	if err != nil {
		t.Fatal(err)
	}
	if got := ask(t, snap, "!aAS-ZERO"); got != framed("100.64.0.0/24") {
		t.Errorf("RFC+RPKI !aAS-ZERO over the pseudo registry: %q", got)
	}
}

// rfcCommand reports whether send holds a command RFC mode answers
// otherwise: "!a…" or "!i…,1".
func rfcCommand(send string) bool {
	for _, line := range strings.Split(send, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "!a") || strings.HasPrefix(line, "!i") && strings.HasSuffix(line, ",1") {
			return true
		}
	}
	return false
}

// TestRFCModeChangesNothingElse: every recorded golden exchange without an
// "!a" or "!i…,1" — the plain and the rpki ones — is answered in RFC mode
// exactly as without it; the ones with one that differ are logged.
func TestRFCModeChangesNothingElse(t *testing.T) {
	rpkiBase := fixtureRPKI(t)
	rpkiOpts := rpkiBase.opts
	rpkiOpts.RFC = true
	rpkiRFC, err := NewSnapshot(rpkiBase.Registries(), rpkiOpts)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		config     string
		plain, rfc *Snapshot
	}{
		{"plain", fixture(t, SnapshotOptions{}), fixture(t, SnapshotOptions{RFC: true})},
		{"rpki", rpkiBase, rpkiRFC},
	} {
		same, other := 0, 0
		for _, g := range irrdoracle.Load(t, c.config) {
			if c.config == "plain" && !isCovered(g.Name) {
				continue
			}
			a, b := replay(t, c.rfc, g.Send), replay(t, c.plain, g.Send)
			switch {
			case !rfcCommand(g.Send) && a != b:
				t.Errorf("RFC mode changed %s (%q):\n got %q\nplain %q", g.Name, g.Send, a, b)
			case !rfcCommand(g.Send):
				same++
			case a != b:
				other++
				t.Logf("%s: RFC %q, IRRd mode %q", g.Name, a, b)
			}
		}
		if same == 0 {
			t.Errorf("%s: no golden case compared", c.config)
		}
		t.Logf("%s: %d cases unchanged, %d !a/!i…,1 cases answered otherwise", c.config, same, other)
	}
}

// TestRFCModeExclude: Expander.Exclude applies in RFC mode, and the
// snapshot keeps its own copy of the lists.
func TestRFCModeExclude(t *testing.T) {
	ex := []types.ASN{65010}
	snap := fixture(t, SnapshotOptions{RFC: true, Expander: resolve.Expander{Exclude: resolve.Exclusion{ASNs: ex}}})
	if got := ask(t, snap, "!iAS-REF,1"); got != framed("AS65001") {
		t.Fatalf("RFC !iAS-REF,1 excluding AS65010: %q", got)
	}
	ex[0] = 65001
	if got := ask(t, snap, "!iAS-REF,1"); got != framed("AS65001") {
		t.Errorf("RFC !iAS-REF,1 after the caller changed its Exclude list: %q", got)
	}
}

// mustRegistry is a registry of name from texts, route text kept.
func mustRegistry(t *testing.T, name string, texts ...string) *Registry {
	t.Helper()
	r, err := NewRegistry(name, 0, corpusOf(t, true, texts...))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRFCModeScoped: a scoped src-members: reference is looked up in its
// registry whether the session selects it or not, as the engine's scoping
// asks; IRRd mode does not read src-members:.
func TestRFCModeScoped(t *testing.T) {
	ripe := mustRegistry(t, "RIPE",
		"route-set: RS-X\nmembers: 192.0.2.0/24\nsrc-members: RADB::RS-Y\nsource: RIPE\n",
		"route-set: RS-Y\nmembers: 198.51.100.0/24\nsource: RIPE\n")
	radb := mustRegistry(t, "RADB", "route-set: RS-Y\nmembers: 203.0.113.0/24\nsource: RADB\n")
	for _, rfc := range []bool{true, false} {
		snap, err := NewSnapshot([]*Registry{ripe, radb}, SnapshotOptions{Default: []string{"RIPE"}, RFC: rfc})
		if err != nil {
			t.Fatal(err)
		}
		want := framed("192.0.2.0/24 203.0.113.0/24")
		if !rfc {
			want = framed("192.0.2.0/24") // members: only, and RADB is not selected
		}
		if got := ask(t, snap, "!iRS-X,1"); got != want {
			t.Errorf("RFC %v: !iRS-X,1 = %q, want %q", rfc, got, want)
		}
	}
}

// limitTexts are sets that exceed each of the engine's limits at 1 without
// reaching AS-ANY: AS-L1 nests AS-L2 nests AS-L3, RS-L1 nests RS-L2.
var limitTexts = []string{
	"as-set: AS-L1\nmembers: AS-L2, AS1\nsource: RIPE\n",
	"as-set: AS-L2\nmembers: AS-L3, AS2\nsource: RIPE\n",
	"as-set: AS-L3\nmembers: AS3\nsource: RIPE\n",
	"route-set: RS-L1\nmembers: RS-L2, 10.0.0.0/8\nsource: RIPE\n",
	"route-set: RS-L2\nmembers: 192.0.2.0/24, AS1\nsource: RIPE\n",
	"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n",
	"route: 10.2.0.0/16\norigin: AS2\nsource: RIPE\n",
	"route6: 2001:db8:3::/48\norigin: AS3\nsource: RIPE\n",
}

// TestRFCModeLimits: an expansion over a limit is refused with the
// engine's error, never answered in part — each limit at least once.
func TestRFCModeLimits(t *testing.T) {
	reg := mustRegistry(t, "RIPE", limitTexts...)
	var objs []object.Object
	for _, text := range limitTexts {
		o, _ := rpsl.ParseObject(text)
		obj, _ := rpsl.Decode(o)
		objs = append(objs, obj)
	}
	for _, c := range []struct {
		lim  resolve.Expander
		want map[string]string // command -> exact answer
	}{
		{resolve.Expander{MaxDepth: 1}, map[string]string{
			"!iAS-L1,1": "F resolve: expansion of AS-L1 exceeds MaxDepth (1): reached 2\n",
			"!aAS-L1":   "F resolve: expansion of AS-L1 exceeds MaxDepth (1): reached 2\n",
		}},
		{resolve.Expander{MaxVisited: 1}, map[string]string{
			"!iAS-L1,1": "F resolve: expansion of AS-L1 exceeds MaxVisited (1): reached 2\n",
			"!iRS-L1,1": "F resolve: expansion of RS-L1 exceeds MaxVisited (1): reached 2\n",
			"!aAS-L2":   "F resolve: expansion of AS-L2 exceeds MaxVisited (1): reached 2\n",
		}},
		{resolve.Expander{MaxPrefixes: 1}, map[string]string{
			"!iRS-L2,1": "F resolve: expansion of RS-L2 exceeds MaxPrefixes (1): reached 2\n",
			"!aAS-L2":   "F resolve: expansion of AS-L2 exceeds MaxPrefixes (1): reached 2\n",
		}},
	} {
		snap, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{RFC: true, Expander: c.lim})
		if err != nil {
			t.Fatal(err)
		}
		for send, want := range c.want {
			if got := ask(t, snap, send); got != want {
				t.Errorf("%+v %s: %q, want %q", c.lim, send, got, want)
			}
			// The same refusal the engine gives, word for word.
			e := c.lim
			e.Src = resolve.NewMemSource(objs, "RIPE")
			name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(send, "!i"), ",1"), "!a")
			if strings.HasPrefix(send, "!a") {
				_, err = enginePrefixes(t, &e, name, types.AFIAny)
			} else {
				_, err = engineMembers(t, &e, name)
			}
			var big *resolve.SetTooLargeError
			if !errors.As(err, &big) || "F "+big.Error()+"\n" != want {
				t.Errorf("%+v %s: the engine's error is %v", c.lim, send, err)
			}
		}
		// Under no limit, the same sets expand.
		plain, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{RFC: true})
		if err != nil {
			t.Fatal(err)
		}
		for send := range c.want {
			if got := ask(t, plain, send); !strings.HasPrefix(got, "A") {
				t.Errorf("%s without limits: %q", send, got)
			}
		}
	}
}

// TestRFCModeDiffers pins where RFC mode's "!i…,1" and "!a" differ from IRRd
// mode's on purpose (resolve/testdata/rpsld/divergences.md, RFC mode): a
// range operator on a member applied rather than the member dropped, a
// route-set in an as-set not followed, a set reaching AS-ANY refused rather
// than expanded without it.
func TestRFCModeDiffers(t *testing.T) {
	reg := mustRegistry(t, "RIPE",
		// Operators on members: a set, an AS number, a prefix.
		"route-set: RS-OP\nmembers: RS-IN^25, AS1^24, 198.51.100.0/24^+\nsource: RIPE\n",
		"route-set: RS-IN\nmembers: 192.0.2.0/24\nsource: RIPE\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n",
		// A route-set listed in an as-set, reached from a route-set root.
		"route-set: RS-TOP\nmembers: AS-X\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2, RS-Y\nsource: RIPE\n",
		"route-set: RS-Y\nmembers: AS3, 203.0.113.0/24\nsource: RIPE\n",
		"route: 10.2.0.0/16\norigin: AS2\nsource: RIPE\n",
		"route: 10.3.0.0/16\norigin: AS3\nsource: RIPE\n",
		// AS-ANY as a member.
		"as-set: AS-Z\nmembers: AS2, AS-ANY\nsource: RIPE\n",
	)
	irrd, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rfc, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{RFC: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ send, irrd, rfc string }{
		{"!iRS-OP,1", framed("198.51.100.0/24^+"), framed("10.0.0.0/8^24 192.0.2.0/24^25 198.51.100.0/24^+")},
		{"!iRS-TOP,1", framed("10.2.0.0/16 10.3.0.0/16 203.0.113.0/24"), framed("10.2.0.0/16")},
		{"!iAS-X,1", framed("AS2"), framed("AS2")}, // an as-set root never follows it, in either mode
		{"!iAS-Z,1", framed("AS2"), anyRefusal},
		{"!aAS-Z", framed("10.2.0.0/16"), anyRefusal},
	} {
		if got := ask(t, irrd, c.send); got != c.irrd {
			t.Errorf("IRRd mode %s: %q, want %q", c.send, got, c.irrd)
		}
		if got := ask(t, rfc, c.send); got != c.rfc {
			t.Errorf("RFC mode %s: %q, want %q", c.send, got, c.rfc)
		}
	}
}

// TestRPKIStateLines holds the rpki-ov-state: line to IRRd's recorded text
// byte for byte (two spaces after the colon, the not_found comment), which
// the goldens' objects comparison normalizes away.
func TestRPKIStateLines(t *testing.T) {
	snap := fixtureRPKI(t)
	goldens := map[string]string{}
	for _, g := range irrdoracle.Load(t, "rpki") {
		goldens[g.Name] = g.Got
	}
	for _, c := range []struct{ name, send, line string }{
		{"rpki/!mroute,192.0.2.0/24AS65001", "!mroute,192.0.2.0/24AS65001", "rpki-ov-state:  valid\n"},
		{"rpki/!mroute,64.6.160.0/19AS65007", "!mroute,64.6.160.0/19AS65007",
			"rpki-ov-state:  not_found # No ROAs found, or RPKI validation not enabled for source\n"},
	} {
		golden, ok := goldens[c.name]
		if !ok {
			t.Fatalf("no golden %s", c.name)
		}
		if !strings.HasSuffix(golden, c.line+"C\n") {
			t.Fatalf("golden %s does not end in %q: %q", c.name, c.line, golden)
		}
		got := ask(t, snap, c.send)
		if !strings.HasSuffix(got, c.line+"C\n") {
			t.Errorf("%s: %q does not end in %q", c.send, got, c.line)
		}
		if strings.Count(got, "rpki-ov-state:") != 1 {
			t.Errorf("%s: %q holds not exactly one rpki-ov-state: line", c.send, got)
		}
	}
	// The first route's text is IRRd's to the byte, line included.
	if got, want := ask(t, snap, "!mroute,192.0.2.0/24AS65001"), goldens["rpki/!mroute,192.0.2.0/24AS65001"]; got != want {
		t.Errorf("!mroute,192.0.2.0/24AS65001: %q, want IRRd's %q", got, want)
	}
	// A pseudo route carries none.
	s := NewSession(func() *Snapshot { return snap })
	s.Do(context.Background(), "!!")
	s.Do(context.Background(), "!sRPKI")
	r, err := s.Do(context.Background(), "!r192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	r.WriteTo(&b)
	if !strings.HasPrefix(b.String(), "A") || strings.Contains(b.String(), "rpki-ov-state:") {
		t.Errorf("a pseudo route: %q", b.String())
	}
}

// TestRFCModeContext: a context that ends partway through an RFC-mode
// expansion stops it within the breadth-first level it is in, the answer is
// an F, and Do returns the context's error.
func TestRFCModeContext(t *testing.T) {
	// Wide, not deep: the engine's MaxDepth (32) would refuse a long chain.
	const n = 1000
	var texts, sets, ases []string
	for i := 0; i < n; i++ {
		texts = append(texts, fmt.Sprintf("as-set: AS-C%d\nmembers: AS%d\nsource: RIPE\n", i, i+1),
			fmt.Sprintf("route: 10.%d.%d.0/24\norigin: AS%d\nsource: RIPE\n", i/256, i%256, i+1))
		sets = append(sets, fmt.Sprintf("AS-C%d", i))
		ases = append(ases, fmt.Sprintf("AS%d", i+1))
	}
	texts = append(texts, "as-set: AS-TOP\nmembers: "+strings.Join(sets, ", ")+"\nsource: RIPE\n",
		"route-set: RS-WIDE\nmembers: "+strings.Join(ases, ", ")+"\nsource: RIPE\n")
	reg := mustRegistry(t, "RIPE", texts...)
	snap, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{RFC: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"!iAS-TOP,1", "!aAS-TOP", "!iRS-WIDE,1"} {
		if got := ask(t, snap, line); !strings.HasPrefix(got, "A") {
			t.Fatalf("%s on a live context: %.60q", line, got)
		}
		ctx := &countingCtx{Context: context.Background(), n: 10}
		s := NewSession(func() *Snapshot { return snap })
		r, err := s.Do(ctx, line)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s cancelled partway: %v", line, err)
		}
		var b strings.Builder
		r.WriteTo(&b)
		if !strings.HasPrefix(b.String(), "F ") {
			t.Errorf("%s cancelled partway answered %.60q", line, b.String())
		}
		// The engine finishes the fetches of a breadth-first level before it
		// reads their errors; each is answered at once with the context's
		// error, no lookup done, so the checks stay within one level's width.
		if ctx.calls > n+20 {
			t.Errorf("%s went on for %d checks of an ended context", line, ctx.calls)
		}
	}
}
