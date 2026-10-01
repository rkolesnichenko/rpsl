package rpslcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/buildinfo"
)

const fixture = "../../testdata/rpslcheck/objects.rpsl"

func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errw bytes.Buffer
	code = Run(context.Background(), args, strings.NewReader(""), &out, &errw)
	return out.String(), errw.String(), code
}

// golden compares got with testdata/rpslcheck/<name>.golden; with
// RPSL_RPSLCHECK_UPDATE=1 it rewrites the file instead.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("../../testdata/rpslcheck", name+".golden")
	if os.Getenv("RPSL_RPSLCHECK_UPDATE") != "" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s: output differs from %s:\n%s", name, path, got)
	}
}

func TestGoldens(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		code int
	}{
		{"as65001", []string{"-dump", fixture, "AS65001"}, 1},
		{"as65001-json", []string{"-dump", fixture, "-json", "AS65001"}, 1},
		{"as65003", []string{"-dump", fixture, "AS65003"}, 0},
		{"pair", []string{"-dump", fixture, "AS65001", "AS65002"}, 1},
		{"pair-ipv6", []string{"-dump", fixture, "-af", "ipv6", "AS65001", "AS65002"}, 1}, // lint is of both families: AS65001's shadowed term
		{"sweep", []string{"-dump", fixture, "-sweep"}, 1},
		{"sweep-json", []string{"-dump", fixture, "-sweep", "-json"}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, errw, code := run(t, c.args...)
			if code != c.code {
				t.Errorf("exit %d, want %d; stderr %s", code, c.code, errw)
			}
			golden(t, c.name, out)
			if strings.HasSuffix(c.name, "json") {
				for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
					if !json.Valid([]byte(line)) {
						t.Errorf("not JSON: %s", line)
					}
				}
			}
		})
	}
}

// Review Focus 5: the sweep is the same for any -c.
func TestSweepIsDeterministic(t *testing.T) {
	one, _, _ := run(t, "-dump", fixture, "-sweep", "-c", "1")
	eight, _, _ := run(t, "-dump", fixture, "-sweep", "-c", "8")
	if one != eight {
		t.Errorf("-c 1 and -c 8 differ:\n%s\n---\n%s", one, eight)
	}
	sample1, _, _ := run(t, "-dump", fixture, "-sweep", "-sample", "2", "-seed", "7", "-c", "1")
	sample8, _, _ := run(t, "-dump", fixture, "-sweep", "-sample", "2", "-seed", "7", "-c", "8")
	if sample1 != sample8 {
		t.Errorf("a sample differs with -c")
	}
}

func TestExitStatus(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		code int
	}{
		{"no AS", []string{"-dump", fixture}, 2},
		{"three ASes", []string{"-dump", fixture, "AS1", "AS2", "AS3"}, 2},
		{"bad AS", []string{"-dump", fixture, "ASX"}, 2},
		{"same AS twice", []string{"-dump", fixture, "AS65001", "AS65001"}, 2},
		{"bad family", []string{"-dump", fixture, "-af", "ipv5", "AS65001"}, 2},
		{"unknown flag", []string{"-nope"}, 2},
		{"sweep without dumps", []string{"-sweep"}, 2},
		{"sweep with an AS", []string{"-dump", fixture, "-sweep", "AS65001"}, 2},
		{"sample without sweep", []string{"-dump", fixture, "-sample", "2", "AS65001"}, 2},
		{"aut-num not found", []string{"-dump", fixture, "AS64999"}, 3},
		{"dump not found", []string{"-dump", "no-such-file", "AS65001"}, 3},
		{"server unreachable", []string{"-h", "127.0.0.1", "-p", "1", "AS65001"}, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, errw, code := run(t, c.args...); code != c.code {
				t.Errorf("exit %d, want %d; stderr %s", code, c.code, errw)
			}
		})
	}
}

func TestAcceptsPlainNumbers(t *testing.T) {
	a, _, ca := run(t, "-dump", fixture, "AS65003")
	b, _, cb := run(t, "-dump", fixture, "65003")
	if a != b || ca != cb {
		t.Errorf("65003 and AS65003 differ")
	}
}

func TestVersion(t *testing.T) {
	out, _, code := run(t, "-v")
	if code != 0 || out != "rpslcheck "+buildinfo.Version()+"\n" {
		t.Errorf("-v: %q, exit %d", out, code)
	}
}

// A source with no reverse index says so on stderr, not in the output.
func TestNote(t *testing.T) {
	if got := peerNote(true, "AS65001"); !strings.Contains(got, "no reverse index") {
		t.Errorf("note %q", got)
	}
	if got := peerNote(false, "AS65001"); got != "" {
		t.Errorf("note %q with an index", got)
	}
}

// A pair whose filter cannot be evaluated (a regexp's set reaching AS-ANY,
// AS1887's shape) is counted beside the limits, and the sweep goes on; a
// single check of it still fails.
func TestSweepCountsUndecidable(t *testing.T) {
	const dump = "../../testdata/rpslcheck/undecidable.rpsl"
	out, errw, code := run(t, "-dump", dump, "-sweep")
	if code == exitFailed {
		t.Fatalf("exit %d; stderr %s", code, errw)
	}
	if !strings.Contains(out, "  pairs over a limit or not decidable      1\n") {
		t.Errorf("totals:\n%s", out)
	}
	out, errw, _ = run(t, "-dump", dump, "-sweep", "-json")
	var rec struct{ Type, A, B, AF, Error string }
	found := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.Type == "limit" {
			found = rec.A == "AS65001" && rec.B == "AS65002" && rec.AF == "ipv4.unicast" && strings.Contains(rec.Error, "AS-ANY")
		}
	}
	if !found {
		t.Errorf("no limit record for AS65001 and AS65002 with the error:\n%s%s", out, errw)
	}
	if _, _, code := run(t, "-dump", dump, "AS65001", "AS65002"); code != exitFailed {
		t.Errorf("single check: exit %d, want %d", code, exitFailed)
	}
}

// A sweep gives each Lint and Check its own budget: one that runs out is
// counted and the sweep goes on; the run's own deadline still stops it.
func TestSweepCheckTimeout(t *testing.T) {
	out1, errw, code := run(t, "-dump", fixture, "-sweep", "-check-timeout", "1ns", "-c", "1")
	if code == exitFailed {
		t.Fatalf("exit %d; stderr %s", code, errw)
	}
	var n int
	for _, line := range strings.Split(out1, "\n") {
		if strings.HasPrefix(line, "  checks over their time budget") {
			fmt.Sscanf(strings.TrimPrefix(line, "  checks over their time budget"), "%d", &n)
		}
	}
	if n == 0 {
		t.Errorf("no check over its budget counted:\n%s", out1)
	}
	out8, _, _ := run(t, "-dump", fixture, "-sweep", "-check-timeout", "1ns", "-c", "8")
	if out1 != out8 {
		t.Errorf("-c 1 and -c 8 differ:\n%s\n---\n%s", out1, out8)
	}
	js, _, _ := run(t, "-dump", fixture, "-sweep", "-check-timeout", "1ns", "-json")
	if !strings.Contains(js, `{"type":"timeout",`) {
		t.Errorf("no timeout record:\n%s", js)
	}
	if _, errw, code := run(t, "-dump", fixture, "-sweep", "-timeout", "1ns"); code != exitFailed {
		t.Errorf("-timeout 1ns: exit %d, want %d; stderr %s", code, exitFailed, errw)
	}
}

func TestRunTimeout(t *testing.T) {
	for _, c := range []struct {
		sweep, explicit bool
		flag, want      time.Duration
	}{
		{false, false, 10 * time.Minute, 10 * time.Minute}, // one AS or a pair: the default
		{true, false, 10 * time.Minute, 0},                 // a sweep: no deadline by default
		{true, true, 5 * time.Minute, 5 * time.Minute},     // unless one is given
		{true, true, 0, 0},
		{false, true, time.Second, time.Second},
	} {
		if got := runTimeout(c.sweep, c.flag, c.explicit); got != c.want {
			t.Errorf("runTimeout(%v, %v, %v) = %v, want %v", c.sweep, c.flag, c.explicit, got, c.want)
		}
	}
}

// Ruling R15: a direction where neither side has a term toward the other
// says so, in text and JSON, and the sweep counts it apart from the
// consistent ones.
func TestNoPolicyEitherWay(t *testing.T) {
	out, _, _ := run(t, "-dump", fixture, "AS65003")
	if !strings.Contains(out, "AS65003 -> AS65001 ipv6.unicast: no policy either way\n") ||
		!strings.Contains(out, "AS65001 -> AS65003 ipv4.unicast: consistent\n") {
		t.Errorf("text:\n%s", out)
	}
	js, _, _ := run(t, "-dump", fixture, "-json", "AS65003")
	if !strings.Contains(js, `{"type":"direction","from":"AS65003","to":"AS65001","af":"ipv6.unicast","findings":0,"no_policy":true}`) ||
		!strings.Contains(js, `{"type":"direction","from":"AS65001","to":"AS65003","af":"ipv4.unicast","findings":0}`) {
		t.Errorf("JSON:\n%s", js)
	}
	sw, _, _ := run(t, "-dump", fixture, "-sweep")
	if !strings.Contains(sw, "  directions with no policy either way") {
		t.Errorf("sweep totals:\n%s", sw)
	}
	sj, _, _ := run(t, "-dump", fixture, "-sweep", "-json")
	if !strings.Contains(sj, `"no_policy":`) {
		t.Errorf("sweep JSON totals:\n%s", sj)
	}
}

// slowRouters is a MemSource whose inet-rtr lookups wait until the call's
// context ends: Lint looks them up, Peers never does.
type slowRouters struct{ *resolve.MemSource }

func (s slowRouters) InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) {
	<-ctx.Done()
	return object.InetRtr{}, ctx.Err()
}

// Ruling R15: a sweep lists an aut-num's peers before its lint, each under
// its own budget, so a lint that runs out never drops the pairs only that
// aut-num names.
func TestSweepPeersBeforeLint(t *testing.T) {
	const objs = `aut-num: AS65001
as-name: ONE
export: to AS65002 announce AS65001
import: from AS65002 at r1.example.net accept ANY
mnt-by: MNT-A
source: RIPE

aut-num: AS65002
as-name: TWO
mnt-by: MNT-A
source: RIPE
`
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, IndexPeers: true}
	if err := l.Read(strings.NewReader(objs)); err != nil {
		t.Fatal(err)
	}
	src := slowRouters{l.Source()}
	afs, _ := families("both")
	var out, errw bytes.Buffer
	code := runSweep(context.Background(), src, afs, 0, 1, 1, 200*time.Millisecond, newWriter(&out, false), &errw)
	if code == exitFailed {
		t.Fatalf("exit %d; stderr %s", code, errw.String())
	}
	for _, want := range []string{
		"  pairs checked (per family)               2\n", // AS65001 and AS65002, both families
		"  checks over their time budget            1\n", // AS65001's lint
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("want %q in:\n%s", want, out.String())
		}
	}
}
