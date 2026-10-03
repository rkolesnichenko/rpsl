package irrdoracle

import (
	"strconv"
	"strings"
	"testing"
)

// frame is an IRRd A-frame around payload, its length counted from the
// payload itself (the payload's trailing newline included), so a test's
// frames cannot carry a wrong length.
func frame(payload string) string {
	return "A" + strconv.Itoa(len(payload)) + "\n" + payload + "C\n"
}

func TestFrameLength(t *testing.T) {
	// The two lengths IRRd itself wrote in the spike's recordings.
	if got := frame("RIPE\n"); got != "A5\nRIPE\nC\n" {
		t.Errorf("frame = %q", got)
	}
	if got := frame("IRRd -- version 4.5.3\n"); got != "A22\nIRRd -- version 4.5.3\nC\n" {
		t.Errorf("frame = %q", got)
	}
}

func TestSplit(t *testing.T) {
	ripe, version := frame("RIPE\n"), frame("IRRd -- version 4.5.3\n")
	in := ripe + "C\nD\nF One or more selected sources are unavailable.\n" +
		"as-set:         AS-FOO\nsource:         RIPE\n\n\n" +
		"%  No entries found for the selected source(s).\n\n\n" +
		version
	want := []string{
		ripe, "C\n", "D\n", "F One or more selected sources are unavailable.\n",
		"as-set:         AS-FOO\nsource:         RIPE\n\n\n",
		"%  No entries found for the selected source(s).\n\n\n",
		version,
	}
	got := Split(in)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Split:\n got %q\nwant %q", got, want)
	}
	// A frame whose payload holds a blank line and an object is one reply.
	f := frame("route: 1\n\nroute: 2\n")
	if got := Split(f); len(got) != 1 || got[0] != f {
		t.Errorf("a multi-object frame split into %q", got)
	}
	// Hostile or truncated input: no panic, and every byte kept.
	for _, s := range []string{"A", "A9", "A9\nab", "A99999999999999999999\nx\n", "A-1\nx\n", "\n", "x", "C", "\n\n\n"} {
		if got := strings.Join(Split(s), ""); got != s {
			t.Errorf("Split(%q) lost bytes: %q", s, got)
		}
	}
}

func TestCompare(t *testing.T) {
	const (
		obj1 = "route:          192.0.2.0/24\norigin:         AS1\nsource:         RIPE\n"
		obj2 = "route:          10.0.0.0/8\norigin:         AS1\nsource:         RIPE\n"
	)
	for _, tc := range []struct {
		k         Kind
		got, want string
		ok        bool
	}{
		{Exact, "C\n", "C\n", true},
		{Exact, "C\n", "D\n", false},
		{Words, frame("192.0.2.0/25 192.0.2.0/24\n"), frame("192.0.2.0/24 192.0.2.0/25\n"), true},
		{Words, frame("192.0.2.0/24\n"), frame("192.0.2.0/24 192.0.2.0/25\n"), false},
		{Words, "D\n", "D\n", true},
		{Words, "F Missing parameter for s query\n", "F Missing parameter for i query\n", false},
		{Words, "%% ERROR: for foo,only: a, b, c\n\n\n", "%% ERROR: for foo,only: c, a, b\n\n\n", true},
		{Words, "%% ERROR: for foo,only: a, b, c\n\n\n", "%% ERROR: for foo,only: a, b, d\n\n\n", false},
		{Objects,
			"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n\nroute: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n\n\n",
			"route:          10.0.0.0/8\norigin:         AS1\nsource:         RIPE\n\nroute:          192.0.2.0/24\norigin:         AS1\nsource:         RIPE\n\n\n",
			true},
		{Objects,
			frame("as-set: AS-X\nmembers: AS1, AS2\nsource: RIPE\n"),
			frame("as-set:         AS-X\nmembers:        AS1,AS2\nsource:         RIPE\n"),
			true},
		{Objects,
			frame("as-set: AS-X\nmembers: AS1\nsource: RIPE\n"),
			frame("as-set: AS-X\nmembers: AS2\nsource: RIPE\n"),
			false},

		// Only order may differ: each reply's envelope is compared exactly.
		{Words, "A5\nRIPE\nD\n", frame("RIPE\n"), false},   // another frame status
		{Words, "A5\nRIPE\n", frame("RIPE\n"), false},      // the C line missing
		{Words, "A5\nRIPE\nXYZ\n", frame("RIPE\n"), false}, // garbage after the payload
		{Words, "A4\nRIPE\nC\n", frame("RIPE\n"), false},   // a header shorter than its payload
		{Words, frame("a  b\n"), frame("b a\n"), false},    // other whitespace between words
		{Words, frame("a b\n"), frame("b a \n"), false},    // other trailing whitespace
		{Words, frame("a b\n"), "a b\n\n\n", false},        // a frame for RIPE text
		{Words, "C\n", "D\n", false},
		{Words, "%% ERROR: x, y\n", "%% ERROR: x, y\n\n\n", false}, // a % message missing its terminator
		{Words, "%% ERROR: x, y", "%% ERROR: x, y\n\n\n", false},
		{Words, "%% ERROR: y, x\n\n\n", "%% ERROR: x, y\n\n\n", true},
		{Objects, frame(obj1), obj1 + "\n\n", false},                                       // a frame for RIPE text
		{Objects, "A" + strconv.Itoa(len(obj1)) + "\n" + obj1 + "D\n", frame(obj1), false}, // D, not C
		{Objects, obj1, obj1 + "\n\n", false},                                              // RIPE text without its blank lines
		{Objects, obj1 + "\n", obj1 + "\n\n", false},
		{Objects, obj1 + "\n\n\n" + obj2 + "\n\n", obj1 + "\n" + obj2 + "\n\n", false}, // two blank lines between objects
		{Objects, frame(obj1 + "\n"), frame(obj1), false},                              // a blank line ending the payload
		{Objects, frame("\n" + obj1), frame(obj1), false},
		{Objects, "C\n", "D\n", false},
		{Objects, "%  No entries found.\n\n\n", "%  No entries found.\n\n", false},
		{Objects, obj2 + "\n" + obj1 + "\n\n", obj1 + "\n" + obj2 + "\n\n", true},
		{Objects, frame(obj2 + "\n" + obj1), frame(obj1 + "\n" + obj2), true},
	} {
		err := Compare(tc.k, tc.got, tc.want)
		if (err == nil) != tc.ok {
			t.Errorf("Compare(%v, %q, %q) = %v, want ok=%v", tc.k, tc.got, tc.want, err, tc.ok)
		}
	}
}

func TestNormalize(t *testing.T) {
	// The rewrites IRRd applies when it serves an object, applied alike to
	// the text as loaded: so both spellings normalize to one form.
	loaded := "MEMBERS:        AS65001 # comment\n                AS65002\n+               AS65003,\n\tAS65004\n"
	served := "members:        AS65001 # comment\n                AS65002\n+               AS65003,\n\t               AS65004\n"
	if Normalize("as-set: AS-NORM\n"+loaded) != Normalize("as-set:         AS-NORM\n"+served) {
		t.Error("a continuation's padding changed the normal form")
	}
	if Normalize("route-set: RS-X\nmembers: 206.197.238.0, 206.197.238.0^+\n") !=
		Normalize("route-set:      RS-X\nmembers:        206.197.238.0/32,206.197.238.0/32^+\n") {
		t.Error("a bare address and its host prefix differ")
	}
	if Normalize("route: 064.006.160.000/19\norigin: AS1\n") != Normalize("route:          64.6.160.0/19\norigin:         AS1\n") {
		t.Error("a zero-padded route key and IRRd's rewrite differ")
	}
}

func TestGoldensLoad(t *testing.T) {
	for _, config := range []string{"plain", "rpki"} {
		gs := Load(t, config)
		if len(gs) == 0 {
			t.Fatalf("%s: no goldens", config)
		}
		names := map[string]bool{}
		cases := map[string]Case{}
		for _, c := range Cases() {
			if c.Config == config {
				names[c.Name] = true
				cases[c.Name] = c
			}
		}
		for _, g := range gs {
			if !names[g.Name] {
				t.Errorf("%s: golden %q is no case (re-record with RPSL_IRRD_DOCKER=1)", config, g.Name)
			}
			delete(names, g.Name)
			if err := Compare(g.Kind, g.Got, g.Got); err != nil {
				t.Errorf("%s: golden %q differs from itself: %v", config, g.Name, err)
			}
			// A golden recorded for another send, or under another kind, is
			// stale: it would be compared wrongly.
			if c, ok := cases[g.Name]; ok && (c.Send != g.Send || c.Kind != g.Kind) {
				t.Errorf("%s: golden %q is %v %q, the case %v %q (re-record with RPSL_IRRD_DOCKER=1)",
					config, g.Name, g.Kind, g.Send, c.Kind, c.Send)
			}
		}
		for n := range names {
			t.Errorf("%s: case %q was never recorded (re-record with RPSL_IRRD_DOCKER=1)", config, n)
		}
	}
}
