package irrdq

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSessionPersistence(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	s := NewSession(func() *Snapshot { return snap })
	r, _ := s.Do(context.Background(), "")
	if r.Len() != 0 || r.Close() {
		t.Error("a blank line was answered or closed the connection")
	}
	r, _ = s.Do(context.Background(), "!n test")
	if !r.Close() {
		t.Error("without !! the first command did not close")
	}
	s = NewSession(func() *Snapshot { return snap })
	s.Do(context.Background(), "!!")
	r, _ = s.Do(context.Background(), "!n test")
	if r.Close() {
		t.Error("after !! a command closed")
	}
	r, _ = s.Do(context.Background(), "!q")
	if !r.Close() || r.Len() != 0 {
		t.Error("!q did not close silently")
	}
}

func TestSessionTimeout(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	s := NewSession(func() *Snapshot { return snap })
	s.Do(context.Background(), "!!")
	if s.Timeout() != 0 {
		t.Error("a timeout before !t")
	}
	s.Do(context.Background(), "!t5")
	if s.Timeout() != 5*time.Second {
		t.Errorf("!t5: %v", s.Timeout())
	}
	s.Do(context.Background(), "!t0")
	if s.Timeout() != 5*time.Second {
		t.Errorf("a refused !t changed the timeout: %v", s.Timeout())
	}
}

func TestSnapshotReadOncePerCommand(t *testing.T) {
	a := fixture(t, SnapshotOptions{})
	calls := 0
	s := NewSession(func() *Snapshot { calls++; return a })
	s.Do(context.Background(), "!!")
	for _, cmd := range []string{"!s-lc", "!v", "!j-*", "!sRIPE", "!n x", "!x"} {
		before := calls
		s.Do(context.Background(), cmd)
		if calls-before != 1 {
			t.Errorf("%s read the snapshot %d times", cmd, calls-before)
		}
	}
}

// TestSessionSeesNewSnapshot: a session's selection outlives a snapshot, and
// each command answers from the snapshot current when it arrives.
func TestSessionSeesNewSnapshot(t *testing.T) {
	a := fixture(t, SnapshotOptions{})
	cur := a
	s := NewSession(func() *Snapshot { return cur })
	s.Do(context.Background(), "!!")
	s.Do(context.Background(), "!sRADB")
	ripe, _ := NewRegistry("RIPE", 0, corpusOf(t, false))
	radb, _ := NewRegistry("RADB", 42, corpusOf(t, false))
	cur, _ = NewSnapshot([]*Registry{ripe, radb}, SnapshotOptions{Version: "v2"})
	for cmd, want := range map[string]string{
		"!s-lc":  framed("RADB"),
		"!jRADB": framed("RADB:N:0-42"),
		"!v":     framed("IRRd -- version 4.5.3 (rpsld v2)"),
	} {
		var b strings.Builder
		r, _ := s.Do(context.Background(), cmd)
		r.WriteTo(&b)
		if b.String() != want {
			t.Errorf("%s: %q, want %q", cmd, b.String(), want)
		}
	}
}

func TestSessionCommands(t *testing.T) {
	ripe, _ := NewRegistry("RIPE", 7, corpusOf(t, false))
	radb, _ := NewRegistry("RADB", 0, corpusOf(t, false))
	snap, err := NewSnapshot([]*Registry{ripe, radb}, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ send, want string }{
		{"!v", framed("IRRd -- version 4.5.3 (rpsld)")}, // Version "": just rpsld
		{"!j-*", framed("RIPE:N:0-7\nRADB:N:-")},        // Refinement 6
		{"!jradb,nosuch,ripe", framed("RADB:N:-\nRIPE:N:0-7\nNOSUCH:X:Database unknown")},
		{"!sRADB,RIPE\n!s-lc", "C\n" + framed("RADB,RIPE")},
		{"!s ripe , radb\n!s-lc", "F One or more selected sources are unavailable.\n" + framed("RIPE,RADB")}, // split at commas only: " radb" is no source
		{"!jRIPE, RADB", framed("RIPE:N:0-7\n RADB:X:Database unknown")},
		{"!sRIPE,\n!s-lc", "F One or more selected sources are unavailable.\n" + framed("RIPE,RADB")},
		{"!s-*\n!s-lc", "C\n" + framed("RIPE,RADB")},
		{"!t1000", "C\n"},
		{"!t-1", "F Invalid value for timeout: -1\n"},
		{"!t5x", "F Invalid value for timeout: 5x\n"},
		{"!!x\n!q", ""},
		{"!\xff", "F Unrecognised command: �\n"},
		{"!é", "F Unrecognised command: é\n"},
		{"\x00", "F Queries may not contain null bytes\n"},
	} {
		s := NewSession(func() *Snapshot { return snap })
		s.Do(context.Background(), "!!")
		var b strings.Builder
		for _, line := range strings.Split(c.send, "\n") {
			r, err := s.Do(context.Background(), line)
			if err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			r.WriteTo(&b)
		}
		if b.String() != c.want {
			t.Errorf("%q: %q, want %q", c.send, b.String(), c.want)
		}
	}
}

// TestDoHostile: no line panics, and every answer is one IRRd reply.
func TestDoHostile(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for _, line := range []string{"!", "!!", "!\x00", "\x00", "!s", "!s,", "!s,,,", "!s ", "!j,", "!j ",
		"!t", "!t ", "!t99999999999999999999", "!n", "!\xff\xfe", "!s\xff", "!j\xff", "\r\r", "!v\x00",
		"!" + strings.Repeat("s", 1<<16), "!j" + strings.Repeat("A,", 1<<12)} {
		s := NewSession(func() *Snapshot { return snap })
		s.Do(context.Background(), "!!")
		r, err := s.Do(context.Background(), line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		var b strings.Builder
		r.WriteTo(&b)
		out := b.String()
		if out != "" && out != "C\n" && !strings.HasPrefix(out, "F ") && !strings.HasPrefix(out, "A") {
			t.Errorf("%.40q: %.80q is no IRRd reply", line, out)
		}
		if r.Len() != len(out) {
			t.Errorf("%.40q: Len %d, wrote %d", line, r.Len(), len(out))
		}
	}
}

// TestDoContext: Do returns an error only when its context has ended.
func TestDoContext(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewSession(func() *Snapshot { return snap })
	if _, err := s.Do(ctx, "!v"); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: %v", err)
	}
	if _, err := s.Do(context.Background(), "!v"); err != nil {
		t.Errorf("a live context: %v", err)
	}
}

func TestReplyFraming(t *testing.T) {
	var b strings.Builder
	frame("IRRd -- version 4.5.3").WriteTo(&b)
	if b.String() != "A22\nIRRd -- version 4.5.3\nC\n" {
		t.Errorf("frame: %q", b.String())
	}
	b.Reset()
	Fail("x").WriteTo(&b)
	if b.String() != "F x\n" {
		t.Errorf("Fail: %q", b.String())
	}
	if framed("x") != "A2\nx\nC\n" {
		t.Errorf("framed: %q", framed("x"))
	}
}

// TestRefused: a refusal is IRRd's F line in place of the reply, closing
// the connection exactly when the reply would have.
func TestRefused(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	s := NewSession(func() *Snapshot { return snap })
	r, _ := s.Do(context.Background(), "!iAS-FOO")
	f := r.Refused("Answer larger than 1 bytes")
	var b strings.Builder
	f.WriteTo(&b)
	if got := b.String(); got != "F Answer larger than 1 bytes\n" || f.Len() != len(got) {
		t.Errorf("refused: %q (Len %d)", got, f.Len())
	}
	if !r.Close() || !f.Close() {
		t.Error("a refusal of a one-shot reply did not close the connection")
	}
	s = NewSession(func() *Snapshot { return snap })
	s.Do(context.Background(), "!!")
	r, _ = s.Do(context.Background(), "!iAS-FOO")
	if f := r.Refused("x"); f.Close() {
		t.Error("a refusal in a persistent session closed the connection")
	}
}
