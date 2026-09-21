package irrd

import (
	"bufio"
	"fmt"
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

func TestSanitizeLine(t *testing.T) {
	if got := sanitizeLine("RADB,RIPE\n!gAS1"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("sanitizeLine left control chars: %q", got)
	}
}
