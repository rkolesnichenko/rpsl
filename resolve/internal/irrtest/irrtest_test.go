package irrtest

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// talk sends lines on one IRRd connection and returns everything it answered.
func talk(t *testing.T, addr string, lines ...string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, l := range lines {
		if _, err := c.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := io.ReadAll(bufio.NewReader(c))
	return string(b)
}

var db = func() *DB {
	return New(
		"route: 10.1.0.0/16\ndescr: one\norigin: AS1\nsource: RIPE\n",
		"route: 10.2.0.0/16\ndescr: two\norigin: AS1\nsource: RADB\n",
		"route6: 2001:db8:1::/48\norigin: AS1\nsource: RIPE\n",
	).WithSources("RIPE", "RADB")
}

// IRRToolSet reads "!v" for a version (and crashes on an answer without
// one), resets its sources with "!s-*" and ends with "q".
func TestIRRToolSetHandshake(t *testing.T) {
	addr := db().IRRd(t)
	got := talk(t, addr, "!!", "!v", "!s-*", "!sRIPE", "q")
	if !strings.Contains(got, "version") {
		t.Errorf("!v answered %q, which names no version", got)
	}
	if strings.Count(got, "C\n") < 3 || strings.Contains(got, "F ") {
		t.Errorf("!!, !v, !s-*, !sRIPE, q: answered %q", got)
	}
}

// IRRd 4 answers a RIPE-style query on its IRRd port too: with -K only the
// primary key attributes, and two empty lines at the end. IRRToolSet asks
// "-K -r -i origin ASn" for an AS's routes.
func TestRIPEStyleQueryOnIRRdPort(t *testing.T) {
	addr := db().IRRd(t)
	got := talk(t, addr, "!!", "!sRIPE", "-K -r -i origin AS1", "q")
	want := "route: 10.1.0.0/16\norigin: AS1\n\nroute6: 2001:db8:1::/48\norigin: AS1\n\n\n"
	if !strings.Contains(got, want) || strings.Contains(got, "descr") || strings.Contains(got, "10.2.0.0") {
		t.Errorf("-K -r -i origin AS1 with !sRIPE answered %q, want it to contain %q", got, want)
	}
	got = talk(t, addr, "!!", "-K -r -i origin AS9", "q")
	if !strings.Contains(got, "No entries found") || !strings.HasSuffix(got, "\n\n\n") {
		t.Errorf("-K -r -i origin AS9 answered %q", got)
	}
}
