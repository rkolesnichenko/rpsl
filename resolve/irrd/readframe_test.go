package irrd

import (
	"bufio"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

// A hostile or buggy mirror can advertise a negative or absurd payload length.
// readFrame must reject it (a negative length would otherwise panic in make),
// not allocate.
func TestReadFrameRejectsBadLength(t *testing.T) {
	for _, in := range []string{
		"A-1\n",           // negative: make([]byte,-1) would panic
		"A300000000\n",    // 300 MB > maxFrame
		"A999999999999\n", // absurd / overflow-ish
		"Axyz\n",          // non-numeric
	} {
		if _, err := readFrame(bufio.NewReader(strings.NewReader(in)), defaultMaxResponse); err == nil {
			t.Errorf("readFrame(%q) = nil error, want rejection", in)
		}
	}
}

func TestReadFrameValid(t *testing.T) {
	payload := "AS1 AS2\n"
	in := fmt.Sprintf("A%d\n%sC\n", len(payload), payload)
	got, err := readFrame(bufio.NewReader(strings.NewReader(in)), defaultMaxResponse)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// A mirror that returns a valid payload but a non-'C' trailer is sending
// something we do not understand; the framer must reject rather than silently
// accept (otherwise persistent connections in the pool would desynchronize).
func TestReadFrameRejectsBadTrailer(t *testing.T) {
	payload := "AS1 AS2\n"
	in := fmt.Sprintf("A%d\n%sXfoo\n", len(payload), payload)
	if _, err := readFrame(bufio.NewReader(strings.NewReader(in)), defaultMaxResponse); err == nil {
		t.Errorf("readFrame accepted non-'C' trailer, want rejection")
	}
}

// junk is an endless stream of 'x' with no newline, as a hostile server might
// send it; it allocates nothing itself.
type junk struct{}

func (junk) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// MaxResponse bounds the payload, and the header and status lines around it are
// bounded too: a server that never ends a status line must not make the reader
// buffer it. The trailer after a payload must be exactly "C".
func TestReadFrameBoundsStatusLines(t *testing.T) {
	const flood = 64 << 20
	cases := map[string]io.Reader{
		"header":      io.MultiReader(strings.NewReader("A"), io.LimitReader(junk{}, flood)),
		"error":       io.MultiReader(strings.NewReader("F "), io.LimitReader(junk{}, flood)),
		"unknown":     io.MultiReader(strings.NewReader("X"), io.LimitReader(junk{}, flood)),
		"trailer":     io.MultiReader(strings.NewReader("A5\nabcd\nC"), io.LimitReader(junk{}, flood)),
		"trailer-ext": strings.NewReader("A5\nabcd\nCfoo\n"),
	}
	for name, in := range cases {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := readFrame(bufio.NewReader(in), 1000)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("%s: readFrame accepted it, want an error", name)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
			t.Errorf("%s: readFrame allocated %d bytes, want under 1 MiB", name, alloc)
		}
	}
	for _, ok := range []string{"A5\nabcd\nC\n", "A5\nabcd\nC\r\n"} {
		if got, err := readFrame(bufio.NewReader(strings.NewReader(ok)), 1000); err != nil || string(got) != "abcd\n" {
			t.Errorf("readFrame(%q) = %q, %v; want the payload", ok, got, err)
		}
	}
}
