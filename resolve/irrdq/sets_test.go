package irrdq

import (
	"context"
	"errors"
	"fmt"
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
		// The parameter is not trimmed (only the line is), and the number
		// is read by Python's int(): a sign, inner spaces and underscores.
		{"!g AS1", "F Invalid AS number  AS1: must start with \"AS\"\n"},
		{"!gAS 1", framed("10.0.0.0/8")},
		{"!gAS+1", framed("10.0.0.0/8")},
		{"!gAS0_1", framed("10.0.0.0/8")},
		{"!gAS\u0661", framed("10.0.0.0/8")}, // ARABIC-INDIC DIGIT ONE
		{"!gAS-0", "D\n"},
		{"!gAS1__0", "F Invalid AS number AS1__0: number part is not numeric\n"},
		{"!gAS_1", "F Invalid AS number AS_1: number part is not numeric\n"},
		{"!gAS1_", "F Invalid AS number AS1_: number part is not numeric\n"},
		{"!gAS- 1", "F Invalid AS number AS- 1: number part is not numeric\n"},
		{"!gAS-1", "F Invalid AS number AS-1: valid range is 0-4294967295\n"},
		{"!gAS" + strings.Repeat("1", 4300), "F Invalid AS number AS" + strings.Repeat("1", 4300) + ": valid range is 0-4294967295\n"},
		{"!gAS" + strings.Repeat("1", 4301), "F Invalid AS number AS" + strings.Repeat("1", 4301) + ": number part is not numeric\n"},
		// The line is stripped as Python strips it, before dispatch.
		{"\t!gAS1 \r", framed("10.0.0.0/8")},
		{"\x1c!gAS1\u3000", framed("10.0.0.0/8")},
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

// countingCtx is a context that ends after its Err has been asked n
// times: a cancellation partway through a query, at a point the test
// chooses without timing.
type countingCtx struct {
	context.Context
	n, calls int
}

func (c *countingCtx) Err() error {
	c.calls++
	if c.calls > c.n {
		return context.Canceled
	}
	return nil
}

// TestSetsContext: a context that ends partway through a recursion stops
// it — through a chain of as-sets (each set lookup checks it) and through a
// route-set's AS numbers (each AS's routes check it) — and Do returns its
// error.
func TestSetsContext(t *testing.T) {
	const n = 1000
	var texts []string
	var ases []string
	for i := 0; i < n; i++ {
		texts = append(texts, fmt.Sprintf("as-set: AS-C%d\nmembers: AS-C%d, AS%d\nsource: RIPE\n", i, i+1, i+1),
			fmt.Sprintf("route: 10.%d.%d.0/24\norigin: AS%d\nsource: RIPE\n", i/256, i%256, i+1))
		ases = append(ases, fmt.Sprintf("AS%d", i+1))
	}
	texts = append(texts, "route-set: RS-WIDE\nmembers: "+strings.Join(ases, ", ")+"\nsource: RIPE\n")
	snap := setsSnapshot(t, texts...)
	for _, line := range []string{"!iAS-C0,1", "!aAS-C0", "!iRS-WIDE,1"} {
		if got := ask(t, snap, line); !strings.HasPrefix(got, "A") {
			t.Fatalf("%s on a live context: %.60q", line, got)
		}
		ctx := &countingCtx{Context: context.Background(), n: 10}
		s := NewSession(func() *Snapshot { return snap })
		if _, err := s.Do(ctx, line); !errors.Is(err, context.Canceled) {
			t.Errorf("%s cancelled partway: %v", line, err)
		}
		if ctx.calls > 20 {
			t.Errorf("%s went on for %d checks of an ended context", line, ctx.calls)
		}
	}
}

// TestInvalidMembersServed pins a divergence no golden can show (IRRd's
// loader refuses such objects, so the fixture cannot hold them): IRRd
// refuses a whole set whose members:/mp-members: holds an item it cannot
// parse, or whose route-set members: holds an IPv6 prefix; rpsld serves the
// set as the library parses it — every valid item, and an unreadable one as
// written, upper-cased.
func TestInvalidMembersServed(t *testing.T) {
	snap := setsSnapshot(t,
		"as-set: AS-JUNK\nmembers: AS1, bad!member\nmembers: AS2\nsource: RIPE\n",
		"route-set: RS-JUNK\nmembers: 192.0.2.0/24, bad!member\nmembers: 2001:db8::/32\nmp-members: 2001:db8:1::/48\nsource: RIPE\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n",
	)
	for _, c := range []struct{ send, want string }{
		{"!iAS-JUNK", framed("AS1 AS2 BAD!MEMBER")},
		{"!iAS-JUNK,1", framed("AS1 AS2")},
		{"!aAS-JUNK", framed("10.0.0.0/8")},
		{"!iRS-JUNK", framed("192.0.2.0/24 2001:db8:1::/48 2001:db8::/32 BAD!MEMBER")},
		{"!iRS-JUNK,1", framed("192.0.2.0/24 2001:db8:1::/48 2001:db8::/32")},
	} {
		if got := ask(t, snap, c.send); got != c.want {
			t.Errorf("%q: %q, want %q", c.send, got, c.want)
		}
	}
}

// A route-set's set names are kept as written, so one route-set can name
// the same set in many spellings; "!i…,1" still expands it once. 64
// spellings cost about what one does, not 64 expansions.
func TestRecursiveSpellingsExpandOnce(t *testing.T) {
	var big []string
	for i := range 500 {
		big = append(big, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	var spellings []string
	for mask := range 64 {
		b := []byte("rs-big")
		for i, j := 0, 0; i < len(b); i++ {
			if b[i] == '-' {
				continue
			}
			if mask&(1<<j) != 0 {
				b[i] -= 'a' - 'A'
			}
			j++
		}
		spellings = append(spellings, string(b))
	}
	snap := setsSnapshot(t,
		"route-set: RS-BIG\nmembers: "+strings.Join(big, ", ")+"\nsource: RIPE\n",
		"route-set: RS-ONE\nmembers: RS-BIG\nsource: RIPE\n",
		"route-set: RS-MANY\nmembers: "+strings.Join(spellings, ", ")+"\nsource: RIPE\n",
	)
	if one, many := ask(t, snap, "!iRS-ONE,1"), ask(t, snap, "!iRS-MANY,1"); one != many {
		t.Fatalf("one spelling %.60q, 64 spellings %.60q", one, many)
	}
	allocs := func(line string) float64 {
		return testing.AllocsPerRun(5, func() { ask(t, snap, line) })
	}
	if one, many := allocs("!iRS-ONE,1"), allocs("!iRS-MANY,1"); many > 2*one {
		t.Errorf("64 spellings took %.0f allocations, one %.0f: the set was expanded per spelling", many, one)
	}
}
