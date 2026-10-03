package irrdq

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
)

// covered are the golden-case name prefixes irrdq answers so far; every
// case under one must agree with IRRd, or be in diverges.
var covered = []string{"session/", "i/", "i1/", "a/", "g/", "m/", "r/", "ripe/"}

// framed is IRRd's frame of payload: "A<len>", the payload and its newline
// (counted in len), then "C". Pinned answers are built with it, so a length
// cannot drift from its payload.
func framed(payload string) string {
	payload += "\n"
	return fmt.Sprintf("A%d\n%sC\n", len(payload), payload)
}

// version is irrdq's "!v" answer on the fixture (Version "test").
var version = framed("IRRd -- version 4.5.3 (rpsld test)")

// diverges are the cases where irrdq knowingly answers otherwise than IRRd,
// with irrdq's own answer pinned (an exact string). Each is listed in
// resolve/testdata/rpsld/divergences.md (TestDivergencesDocumented).
var diverges = map[string]string{
	"session/v":                version,
	"session/not-persistent":   version,
	"session/blank-first":      version,
	"session/crlf":             version,
	"session/spaces-first":     version,
	"session/blank-in-session": version,
	// A Words case (IRRd's "!g" order varies), pinned for its "!v".
	"session/pipeline": version + framed("192.0.2.0/24 192.0.2.0/25") + framed("2001:db8::/32") +
		framed("AS-ANY AS-BAR AS-MISSING AS65001 AS65002 RS-INNER"),
	// An Objects case, pinned for its "!v" (R6); its objects are served as
	// loaded.
	"ripe/in-session": asFooRIPE + "\n" + asFooRADB + "\n\n" + version +
		route203 + "\n" + route203x128 + "\n\n" + refusedLookup("AS-NOSUCH"),

	// What the mirror does not keep is refused, never "not found"
	// (Refinement 11).
	"m/mntner,MNT-A":       "F Class mntner is not kept by this mirror\n",
	"m/person,JD1-RIPE":    "F Class person is not kept by this mirror\n",
	"ripe/-T mntner MNT-A": "%% ERROR: Class mntner is not kept by this mirror\n\n\n",
	"ripe/-i mnt-by MNT-B": "%% ERROR: Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only\n\n\n",
	"ripe/-i foo bar":      "%% ERROR: Inverse attribute search not supported for foo, only supported for attributes: origin, member-of, mbrs-by-ref, members, mp-members\n\n\n",

	// A plain lookup without -T is refused: IRRd's text search also answers
	// with classes the mirror does not keep (as-block, inetnum, person, …).
	"session/q-bare":        refusedLookup("q"),
	"ripe/MNT-A":            refusedLookup("MNT-A"),
	"ripe/JD1-RIPE":         refusedLookup("JD1-RIPE"),
	"ripe/AS65001":          refusedLookup("AS65001"),
	"ripe/as65001":          refusedLookup("as65001"),
	"ripe/AS-NOSUCH":        refusedLookup("AS-NOSUCH"),
	"ripe/192.0.2.0/24":     refusedLookup("192.0.2.0/24"),
	"ripe/-s ripe AS-FOO":   refusedLookup("AS-FOO"),
	"ripe/AS65001 AS65002":  refusedLookup("AS65002"),
	"ripe/rtr1.example.net": refusedLookup("rtr1.example.net"),
	"ripe/-K AS-NORM":       refusedLookup("AS-NORM"),
	"ripe/-s RADB AS-NORM":  refusedLookup("AS-NORM"),
	// The same in the RPKI pseudo registry (rpki goldens).
	"rpki/-s RPKI 192.0.2.0/24": refusedLookup("192.0.2.0/24"),
}

// refusedLookup is rpsld's answer to a plain lookup of key without -T.
func refusedLookup(key string) string {
	return "%% ERROR: This mirror keeps only the routing classes, so it cannot answer a lookup of " + key +
		" whole; ask with -T and any of as-set, route-set, rtr-set, filter-set, peering-set, aut-num, inet-rtr, route, route6\n\n\n"
}

// Fixture objects as loaded, for pinned answers.
const (
	asFooRIPE = "as-set:         AS-FOO\ndescr:          the main as-set\nmembers:        AS65001, AS65002, AS-BAR\n" +
		"members:        RS-INNER, AS-ANY, AS-MISSING\nadmin-c:        JD1-RIPE\ntech-c:         JD1-RIPE\n" +
		"mnt-by:         MNT-A\nsource:         RIPE\n"
	asFooRADB = "as-set:         AS-FOO\ndescr:          same name, other registry\nmembers:        AS65099\n" +
		"mnt-by:         MNT-A\nsource:         RADB\n"
	route203 = "route:          203.0.113.0/24\norigin:         AS65003\nmember-of:      RS-INNER\n" +
		"mnt-by:         MNT-A\nsource:         RIPE\n"
	route203x128 = "route:          203.0.113.128/25\norigin:         AS65003\nmember-of:      RS-INNER\n" +
		"mnt-by:         MNT-B\nsource:         RIPE\n"
)

// divergesObj are divergences whose rpsld answer is one fixture object, as
// loaded, in an A-frame (IRRd answers D): IRRToolSet's legacy class names
// (Refinement 12).
var divergesObj = map[string]struct{ file, class, key string }{
	"m/an,AS65001":              {"ripe.db", "aut-num", "AS65001"},
	"m/rt,192.0.2.0/24-AS65001": {"ripe.db", "route", "192.0.2.0/24AS65001"},
}

// fixtureText is the text of the fixture object of class and key (a route's
// key its prefix and origin run together) in file, ending in one newline.
func fixtureText(t *testing.T, file, class, key string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(irrdoracle.Fixture(t), file))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range strings.Split(string(b), "\n\n") {
		o, _ := rpsl.ParseObject(text)
		if o == nil || o.Class() != class {
			continue
		}
		k := strings.TrimSpace(o.Key())
		if a, ok := o.GetFirst("origin"); ok && (class == "route" || class == "route6") {
			k += strings.TrimSpace(a.Value)
		}
		if strings.EqualFold(k, key) {
			return strings.Trim(text, "\n") + "\n"
		}
	}
	t.Fatalf("no %s %s in %s", class, key, file)
	return ""
}

// testPins are divergences no golden case can show, each named in its
// divergences.md row by the unit test that pins it (a function of this
// package's tests).
var testPins = []string{"TestInvalidMembersServed", "TestRouteSearchOptions", "TestNotServed", "TestRFCMode"}

// pending are covered cases that also need a later task's commands; they
// are logged and skipped until that task removes them.
var pending = map[string]string{}

// fixture builds the snapshot the goldens were recorded on: RIPE from
// ripe.db, RADB from radb.db, serial 0 (IRRd's "-"), default RIPE, RADB.
func fixture(t *testing.T, opts SnapshotOptions) *Snapshot {
	t.Helper()
	dir := irrdoracle.Fixture(t)
	var regs []*Registry
	for _, r := range []struct{ name, file string }{{"RIPE", "ripe.db"}, {"RADB", "radb.db"}} {
		f, err := os.Open(filepath.Join(dir, r.file))
		if err != nil {
			t.Fatal(err)
		}
		l := &resolve.DumpLoader{KeepPolicy: true, KeepRouteText: true}
		err = l.Read(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		reg, err := NewRegistry(r.name, 0, l.Corpus())
		if err != nil {
			t.Fatal(err)
		}
		regs = append(regs, reg)
	}
	if opts.Default == nil {
		opts.Default = []string{"RIPE", "RADB"}
	}
	if opts.Version == "" {
		opts.Version = "test"
	}
	s, err := NewSnapshot(regs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// replay plays send as a client on a fresh connection would: line by line
// through one Session, each reply written in order, until a reply closes the
// connection. A last fragment without a newline is never answered (IRRd waits
// for its end).
func replay(t *testing.T, snap *Snapshot, send string) string {
	t.Helper()
	s := NewSession(func() *Snapshot { return snap })
	var out strings.Builder
	lines := strings.Split(send, "\n")
	for _, line := range lines[:len(lines)-1] {
		r, err := s.Do(context.Background(), line)
		if err != nil {
			t.Fatalf("Do(%q): %v", line, err)
		}
		if _, err := r.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		if r.Close() {
			break
		}
	}
	return out.String()
}

func isCovered(name string) bool {
	for _, p := range covered {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func TestGoldens(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	n := 0
	seen := map[string]bool{}
	for _, g := range irrdoracle.Load(t, "plain") {
		seen[g.Name] = true
		if !isCovered(g.Name) {
			continue
		}
		n++
		checkGolden(t, snap, g)
	}
	if n == 0 {
		t.Fatal("no golden case is covered")
	}
	// A pin or a pending entry naming no golden case would never run.
	for _, g := range irrdoracle.Load(t, "rpki") {
		seen[g.Name] = true
	}
	for name := range diverges {
		if !seen[name] {
			t.Errorf("diverges names %s, which is no golden case", name)
		}
	}
	for name := range divergesObj {
		if !seen[name] {
			t.Errorf("divergesObj names %s, which is no golden case", name)
		}
		if _, ok := diverges[name]; ok {
			t.Errorf("%s is pinned in both diverges and divergesObj", name)
		}
	}
	for name := range pending {
		if !seen[name] {
			t.Errorf("pending names %s, which is no golden case", name)
		}
	}
}

// checkGolden replays g on snap and holds the answer to IRRd's, or to its
// pinned divergence; a pin that agrees with IRRd, or a pending case that
// passes, fails too.
func checkGolden(t *testing.T, snap *Snapshot, g irrdoracle.Golden) {
	t.Helper()
	got := replay(t, snap, g.Send)
	if d, ok := divergesObj[g.Name]; ok {
		text := fixtureText(t, d.file, d.class, d.key)
		want := "A" + strconv.Itoa(len(text)) + "\n" + text + "C\n"
		if irrdoracle.Compare(g.Kind, want, g.Got) == nil {
			t.Errorf("%s: the pinned divergence %q agrees with IRRd; remove it from divergesObj and divergences.md", g.Name, want)
		}
		if got != want {
			t.Errorf("%s, a pinned divergence:\n got %q\nwant %q", g.Name, got, want)
		}
		return
	}
	pin, pinned := diverges[g.Name]
	if pinned && irrdoracle.Compare(g.Kind, pin, g.Got) == nil {
		t.Errorf("%s: the pinned divergence %q agrees with IRRd; remove it from diverges and divergences.md", g.Name, pin)
	}
	// A pending case is replayed too, so one that starts to pass is
	// flagged rather than skipped for ever.
	var err error
	if pinned {
		if got != pin {
			err = fmt.Errorf("a pinned divergence:\n got %q\nwant %q", got, pin)
		}
	} else {
		err = irrdoracle.Compare(g.Kind, got, g.Got)
	}
	if why, ok := pending[g.Name]; ok {
		if err == nil {
			t.Errorf("%s is pending (%s) but now agrees with IRRd (or its pin); remove it from pending", g.Name, why)
		} else {
			t.Logf("%s: pending: %s", g.Name, why)
		}
		return
	}
	if err != nil {
		t.Errorf("%s (%q): %v", g.Name, g.Send, err)
	}
}

// fixtureRPKI is the snapshot the rpki goldens were recorded on: RIPE with
// serial 7 (IRRd imported it with RIPE.CURRENTSERIAL), RADB, and the RPKI
// pseudo registry from roas.json; default RIPE, RADB.
func fixtureRPKI(t *testing.T) *Snapshot {
	t.Helper()
	dir := irrdoracle.Fixture(t)
	f, err := os.Open(filepath.Join(dir, "roas.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vrps, err := rpki.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	var pseudo strings.Builder
	if err := vrps.WriteRPSL(&pseudo); err != nil {
		t.Fatal(err)
	}
	l := &resolve.DumpLoader{KeepPolicy: true, KeepRouteText: true}
	if err := l.Read(strings.NewReader(pseudo.String())); err != nil {
		t.Fatal(err)
	}
	rpkiReg, err := NewRegistry(rpki.PseudoSource, 0, l.Corpus())
	if err != nil {
		t.Fatal(err)
	}
	base := fixture(t, SnapshotOptions{})
	regs := base.Registries()
	s, err := NewSnapshot([]*Registry{regs[0].WithSerial(7), regs[1], rpkiReg}, SnapshotOptions{Default: []string{"RIPE", "RADB"}, VRPs: vrps, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestGoldensRPKI holds the RPKI-aware snapshot to IRRd's rpki goldens,
// every one of them.
func TestGoldensRPKI(t *testing.T) {
	snap := fixtureRPKI(t)
	n := 0
	for _, g := range irrdoracle.Load(t, "rpki") {
		n++
		checkGolden(t, snap, g)
	}
	if n == 0 {
		t.Fatal("no rpki golden case")
	}
}

// caseName is a case named in backquotes.
var caseName = regexp.MustCompile("`([^`]+)`")

// TestDivergencesDocumented: every pinned divergence is in
// resolve/testdata/rpsld/divergences.md, and every case a row of its table
// names is pinned.
func TestDivergencesDocumented(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(irrdoracle.Fixture(t), "..", "rpsld", "divergences.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue // not a table row naming cases
		}
		cells := strings.Split(line, "|")
		for _, m := range caseName.FindAllStringSubmatch(cells[1], -1) {
			documented[m[1]] = true
		}
	}
	if len(documented) == 0 {
		t.Fatal("divergences.md names no case")
	}
	for name := range diverges {
		if !documented[name] {
			t.Errorf("divergence %s is not in divergences.md", name)
		}
	}
	for name := range divergesObj {
		if !documented[name] {
			t.Errorf("divergence %s is not in divergences.md", name)
		}
	}
	tests := testFuncs(t)
	pinnedByTest := map[string]bool{}
	for _, name := range testPins {
		pinnedByTest[name] = true
		if !documented[name] {
			t.Errorf("divergence pinned by %s is not in divergences.md", name)
		}
		if !tests[name] {
			t.Errorf("testPins names %s, which is no test of this package", name)
		}
	}
	for name := range documented {
		_, obj := divergesObj[name]
		if _, ok := diverges[name]; !ok && !obj && !pinnedByTest[name] {
			t.Errorf("divergences.md names %s, which no test pins", name)
		}
	}
}

// testFunc is a test function's declaration.
var testFunc = regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)

// testFuncs are the names of this package's test functions.
func testFuncs(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range testFunc.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}
