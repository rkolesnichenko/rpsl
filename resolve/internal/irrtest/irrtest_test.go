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

// IRRToolSet asks for an aut-num with IRRd 2/3's "!man,ASn", which IRRd 4
// answers D; WithLegacyClasses answers it, and "!mir" and "!mrt" too.
func TestLegacyClasses(t *testing.T) {
	objs := []string{
		"aut-num: AS1\nas-name: ONE\nsource: RIPE\n",
		"inet-rtr: r1.example.net\nlocal-as: AS1\nifaddr: 192.0.2.1 masklen 24\nsource: RIPE\n",
		"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n",
	}
	modern := New(objs...).IRRd(t)
	if got := talk(t, modern, "!!", "!man,AS1", "q"); !strings.HasPrefix(got, "D\n") {
		t.Errorf("without WithLegacyClasses, !man,AS1 answered %q; IRRd 4 answers D", got)
	}
	legacy := New(objs...).WithLegacyClasses().IRRd(t)
	for cmd, want := range map[string]string{
		"!man,AS1":             "aut-num: AS1",
		"!mir,r1.example.net":  "inet-rtr: r1.example.net",
		"!mrt,10.1.0.0/16-AS1": "route: 10.1.0.0/16",
		"!maut-num,AS1":        "aut-num: AS1",
	} {
		if got := talk(t, legacy, "!!", cmd, "q"); !strings.Contains(got, want) {
			t.Errorf("with WithLegacyClasses, %s answered %q", cmd, got)
		}
	}
}
