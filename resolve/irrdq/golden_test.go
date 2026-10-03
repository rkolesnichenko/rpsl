package irrdq

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
)

// covered are the golden-case name prefixes irrdq answers so far; every
// case under one must agree with IRRd, or be in diverges.
var covered = []string{"session/", "i/", "i1/", "a/", "g/"}

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
}

// pending are covered cases that also need a later task's commands; they
// are logged and skipped until that task removes them.
var pending = map[string]string{
	"session/q-bare": "q is a RIPE-style query: Task 6",
}

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
		got := replay(t, snap, g.Send)
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
			continue
		}
		if err != nil {
			t.Errorf("%s (%q): %v", g.Name, g.Send, err)
		}
	}
	if n == 0 {
		t.Fatal("no golden case is covered")
	}
	// A pin or a pending entry naming no golden case would never run.
	for name := range diverges {
		if !seen[name] {
			t.Errorf("diverges names %s, which is no golden case", name)
		}
	}
	for name := range pending {
		if !seen[name] {
			t.Errorf("pending names %s, which is no golden case", name)
		}
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
	for name := range documented {
		if _, ok := diverges[name]; !ok {
			t.Errorf("divergences.md names %s, which no test pins", name)
		}
	}
}
