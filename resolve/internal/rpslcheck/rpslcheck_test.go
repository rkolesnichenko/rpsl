package rpslcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
