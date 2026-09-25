package rpslq

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
)

var corpus = []string{
	"as-set: AS-TOP\nmembers: AS1, AS2, AS-INNER, AS-GONE\nsource: TEST\n",
	"as-set: AS-INNER\nmembers: AS3, AS64500\nsource: TEST\n",
	"route-set: RS-TOP\nmembers: 192.0.2.0/24, 10.0.0.0/30^+, RS-GONE\nmp-members: 2001:db8::/32\nsource: TEST\n",
	"route: 198.51.100.0/24\norigin: AS1\nsource: TEST\n",
	"route: 203.0.113.0/24\norigin: AS2\nsource: TEST\n",
	"route: 203.0.113.128/25\norigin: AS3\nsource: TEST\n",
	"route: 100.64.0.0/24\norigin: AS64500\nsource: TEST\n",
	"route6: 2001:db8:1::/48\norigin: AS1\nsource: TEST\n",
}

// rpslq runs the command and returns its exit code, output and errors.
func rpslq(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := Run(context.Background(), args, &out, &errs)
	return code, out.String(), errs.String()
}

func TestRpslqOverIRRd(t *testing.T) {
	addr := irrtest.New(corpus...).WithSources("TEST").IRRd(t)
	base := []string{"-h", addr, "-S", "TEST"}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"an as-set, special AS numbers dropped", []string{"-P", "AS-TOP"},
			"198.51.100.0/24\n203.0.113.0/24\n203.0.113.128/25\n"},
		{"-p keeps them", []string{"-P", "-p", "AS-TOP"},
			"100.64.0.0/24\n198.51.100.0/24\n203.0.113.0/24\n203.0.113.128/25\n"},
		{"a route-set, its ranges enumerated", []string{"RS-TOP"},
			"no ip prefix-list NN\n" +
				"ip prefix-list NN permit 10.0.0.0/30\nip prefix-list NN permit 10.0.0.0/31\n" +
				"ip prefix-list NN permit 10.0.0.0/32\nip prefix-list NN permit 10.0.0.1/32\n" +
				"ip prefix-list NN permit 10.0.0.2/31\nip prefix-list NN permit 10.0.0.2/32\n" +
				"ip prefix-list NN permit 10.0.0.3/32\nip prefix-list NN permit 192.0.2.0/24\n"},
		{"-ranges keeps the range", []string{"-ranges", "-P", "RS-TOP"}, "10.0.0.0/30^+\n192.0.2.0/24\n"},
		{"-m drops longer prefixes", []string{"-m", "31", "-P", "RS-TOP"},
			"10.0.0.0/30\n10.0.0.0/31\n10.0.0.2/31\n192.0.2.0/24\n"},
		{"IPv6", []string{"-6", "-b", "-l", "V6", "RS-TOP", "AS1"}, "V6 = [\n    2001:db8::/32,\n    2001:db8:1::/48\n];\n"},
		{"an AS list", []string{"-t", "-j", "AS-TOP", "AS9"}, "{\"NN\": [\n  1,2,3,9\n]}\n"},
		{"an AS number's routes", []string{"-P", "AS2"}, "203.0.113.0/24\n"},
	} {
		code, out, errs := rpslq(t, append(append([]string(nil), base...), c.args...)...)
		if code != 0 || out != c.want {
			t.Errorf("%s: exit %d, stderr %q\n got %q\nwant %q", c.name, code, errs, out, c.want)
		}
	}
	// A nested set that does not exist is skipped, and said so.
	_, _, errs := rpslq(t, append(base, "-P", "AS-TOP")...)
	if !strings.Contains(errs, "AS-GONE not found") {
		t.Errorf("no warning for the missing AS-GONE: %q", errs)
	}
}

func TestRpslqWhoisAndDump(t *testing.T) {
	want := "198.51.100.0/24\n203.0.113.0/24\n203.0.113.128/25\n"
	addr := irrtest.New(corpus...).WithSources("TEST").Whois(t)
	if code, out, errs := rpslq(t, "-whois", "-h", addr, "-S", "TEST", "-P", "AS-TOP"); code != 0 || out != want {
		t.Errorf("whois: exit %d %q, got %q", code, errs, out)
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "a.db")
	if err := os.WriteFile(plain, []byte(strings.Join(corpus[:3], "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(strings.Join(corpus[3:], "\n")))
	zw.Close()
	zipped := filepath.Join(dir, "b.db.gz")
	if err := os.WriteFile(zipped, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := rpslq(t, "-dump", plain, "-dump", zipped, "-P", "AS-TOP"); code != 0 || out != want {
		t.Errorf("dumps: exit %d %q, got %q", code, errs, out)
	}
}

func TestRpslqRefuses(t *testing.T) {
	addr := irrtest.New(corpus...).WithSources("TEST").IRRd(t)
	base := []string{"-h", addr, "-S", "TEST"}
	for _, c := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no objects", nil, 2, "usage"},
		{"an unknown flag", []string{"-zz", "AS-TOP"}, 2, "not defined"},
		{"two formats", []string{"-j", "-b", "AS-TOP"}, 2, "choose one"},
		{"-t in Cisco", []string{"-t", "AS-TOP"}, 2, "AS list"},
		{"-t over a route-set", []string{"-t", "-j", "RS-TOP"}, 2, "route-set"},
		{"a filter-set", []string{"FLTR-X"}, 2, "filter-set"},
		{"not an object", []string{"x!"}, 2, "neither"},
		{"AS-ANY", []string{"AS-ANY"}, 2, "whole IRR"},
		{"a missing set", []string{"AS-NOPE"}, 1, "not found"},
		{"Junos with ranges", []string{"-J", "-ranges", "RS-TOP"}, 2, "Junos"},
		{"a dump that is not there", []string{"-dump", "/nonexistent/x.db", "AS-TOP"}, 1, "no such file"},
	} {
		args := append(append([]string(nil), base...), c.args...)
		if c.name == "no objects" {
			args = nil
		}
		code, _, errs := rpslq(t, args...)
		if code != c.code || !strings.Contains(errs, c.msg) {
			t.Errorf("%s: exit %d, stderr %q; want %d with %q", c.name, code, errs, c.code, c.msg)
		}
	}
}
