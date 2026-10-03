package irrdq

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// setsSnapshot is one registry, RIPE, of texts.
func setsSnapshot(t *testing.T, texts ...string) *Snapshot {
	t.Helper()
	reg, err := NewRegistry("RIPE", 0, corpusOf(t, false, texts...))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := NewSnapshot([]*Registry{reg}, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// ask answers one command on a fresh persistent session.
func ask(t *testing.T, snap *Snapshot, line string) string {
	t.Helper()
	s := NewSession(func() *Snapshot { return snap })
	s.Do(context.Background(), "!!")
	r, err := s.Do(context.Background(), line)
	if err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	var b strings.Builder
	r.WriteTo(&b)
	return b.String()
}

// TestSetsByIRRdRules covers what the goldens' fixture does not hold: a set
// listing itself, a prefix in an as-set, a cycle, a set whose class is not
// its name's, and a route-set reaching AS numbers through an as-set.
func TestSetsByIRRdRules(t *testing.T) {
	snap := setsSnapshot(t,
		"as-set: AS-SELF\nmembers: AS-SELF, AS1, 192.0.2.0/24, AS-LOOP\nsource: RIPE\n",
		"as-set: AS-LOOP\nmembers: AS-SELF, AS2\nsource: RIPE\n",
		"route-set: AS-EVIL\nmembers: 198.51.100.0/24\nsource: RIPE\n",
		"route-set: RS-VIA\nmembers: AS-LOOP, 203.0.113.0/24^+\nsource: RIPE\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n",
		"route6: 2001:db8::/32\norigin: AS2\nsource: RIPE\n",
	)
	for _, c := range []struct{ send, want string }{
		// IRRd removes the parameter as sent: upper-case drops AS-SELF,
		// lower-case keeps it (its members are stored upper-case).
		{"!iAS-SELF", framed("192.0.2.0/24 AS-LOOP AS1")},
		{"!ias-self", framed("192.0.2.0/24 AS-LOOP AS-SELF AS1")},
		// A prefix in an as-set is looked up as a set name and dropped;
		// the cycle AS-SELF -> AS-LOOP -> AS-SELF ends.
		{"!iAS-SELF,1", framed("AS1 AS2")},
		{"!iAS-LOOP,1", framed("AS1 AS2")},
		{"!aAS-SELF", framed("10.0.0.0/8 2001:db8::/32")},
		{"!a4AS-SELF", framed("10.0.0.0/8")},
		{"!a6AS-SELF", framed("2001:db8::/32")},
		// route-set: AS-EVIL is no set of that name, as IRRd never stores it.
		{"!iAS-EVIL", "D\n"},
		{"!iAS-EVIL,1", "D\n"},
		// A route-set's AS numbers, reached through an as-set, become the
		// prefixes they originate, in both families; under a route-set root
		// the as-set's prefix member is a result too.
		{"!iRS-VIA,1", framed("10.0.0.0/8 192.0.2.0/24 2001:db8::/32 203.0.113.0/24^+")},
		{"!aRS-VIA", "D\n"},
		{"!gAS1", framed("10.0.0.0/8")},
		{"!6AS1", "D\n"},
		{"!gAS0", "D\n"},
		{"!gAS01", framed("10.0.0.0/8")},
		{"!g AS1", framed("10.0.0.0/8")},
		{"!gAS-1", "F Invalid AS number AS-1: number part is not numeric\n"},
		{"!gAS1^24", "F Invalid AS number AS1^24: number part is not numeric\n"},
		{"!gAS99999999999999999999", "F Invalid AS number AS99999999999999999999: valid range is 0-4294967295\n"},
	} {
		if got := ask(t, snap, c.send); got != c.want {
			t.Errorf("%q: %q, want %q", c.send, got, c.want)
		}
	}
}

// TestSetsHostile: no argument panics, and every answer is one IRRd reply.
func TestSetsHostile(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	long := strings.Repeat("AS-X:", 1<<12)
	for _, cmd := range []string{"!i", "!a", "!a4", "!a6", "!g", "!6"} {
		for _, arg := range []string{",1", ",", ",1,1", "^", "AS-FOO^+", "AS-FOO,1^", "\xff", "AS\xff", "ɐs-foo",
			"AS-FOO:", ":", "AS65001:AS-FOO,1", long, long + ",1", "1.2.3.4/33", "::/0", "4", "6", "44AS-FOO"} {
			out := ask(t, snap, cmd+arg)
			if out != "D\n" && !strings.HasPrefix(out, "F ") && !strings.HasPrefix(out, "A") {
				t.Errorf("%.40q: %.80q is no IRRd reply", cmd+arg, out)
			}
		}
	}
}

// TestSetsContext: a query on an ended context returns its error.
func TestSetsContext(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, line := range []string{"!iRS-FOO,1", "!aAS-FOO", "!gAS65001", "!iAS-FOO"} {
		s := NewSession(func() *Snapshot { return snap })
		if _, err := s.Do(ctx, line); !errors.Is(err, context.Canceled) {
			t.Errorf("%s on a cancelled context: %v", line, err)
		}
	}
}
