package rpslconf

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
)

var texts = []string{
	"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n",
	"route: 10.2.0.0/16\norigin: AS2\nsource: RIPE\n",
	"route6: 2001:db8:1::/48\norigin: AS1\nsource: RIPE\n",
	"as-set: AS-A\nmembers: AS1, AS2\nsource: RIPE\n",
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(context.Background(), args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func dumpFile(t *testing.T) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "irr.db")
	if err := os.WriteFile(name, []byte(strings.Join(texts, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestPevalMode(t *testing.T) {
	dump := dumpFile(t)
	for _, c := range []struct {
		args       []string
		code       int
		out, inErr string
	}{
		{[]string{"-dump", dump, "-e", "AS1"}, 0, "{10.1.0.0/16, 2001:db8:1::/48}\n", ""},
		{[]string{"-dump", dump, "-e", "afi ipv4.unicast AS-A"}, 0, "{10.1.0.0/16, 10.2.0.0/16}\n", ""},
		{[]string{"-dump", dump, "-e", "afi ipv6.unicast AS1"}, 0, "{2001:db8:1::/48}\n", ""},
		{[]string{"-dump", dump, "-e", "PeerAS", "-peer", "AS2"}, 0, "{10.2.0.0/16}\n", ""},
		{[]string{"-dump", dump, "-e", "afi ipv4.unicast AS1 AND <^AS1$>"}, 0, "{10.1.0.0/16} AND <^ AS1 $>\n", ""},
		{[]string{"-dump", dump, "-e", "AS-GONE"}, 0, "NOT ANY\n", "AS-GONE"},
		{[]string{"-dump", dump, "-e", "PeerAS"}, 1, "", "PeerAS"},
		{[]string{"-dump", dump, "-e", "{"}, 1, "", "rpslconf:"},
		{[]string{"-dump", dump, "-e", "AS1", "-peer", "nonsense"}, 2, "", "-peer"},
		{[]string{"-dump", dump}, 2, "", "-e"},
	} {
		code, out, errOut := run(t, c.args...)
		if code != c.code || out != c.out || !strings.Contains(errOut, c.inErr) {
			t.Errorf("rpslconf %q = %d, %q, stderr %q; want %d, %q, stderr containing %q",
				c.args, code, out, errOut, c.code, c.out, c.inErr)
		}
	}
}

func TestPevalModeOverIRRd(t *testing.T) {
	db := irrtest.New(texts...).WithSources("RIPE")
	host, port, _ := net.SplitHostPort(db.IRRd(t))
	for _, args := range [][]string{
		{"-h", host, "-p", port},
		// -h with a port of its own takes it, and -p is ignored.
		{"-h", net.JoinHostPort(host, port)},
		{"-h", net.JoinHostPort(host, port), "-p", "1"},
	} {
		code, out, errOut := run(t, append(args, "-s", "RIPE", "-e", "afi ipv4.unicast AS-A")...)
		if code != 0 || out != "{10.1.0.0/16, 10.2.0.0/16}\n" {
			t.Errorf("rpslconf %q over IRRd = %d, %q, stderr %q", args, code, out, errOut)
		}
	}
}
