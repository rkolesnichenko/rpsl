package rpslq

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
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
		{"-ranges keeps the range", []string{"--ranges", "-P", "RS-TOP"}, "10.0.0.0/30^+\n192.0.2.0/24\n"},
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
	if code, out, errs := rpslq(t, "--whois", "-h", addr, "-S", "TEST", "-P", "AS-TOP"); code != 0 || out != want {
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
	if code, out, errs := rpslq(t, "--dump", plain, "--dump", zipped, "-P", "AS-TOP"); code != 0 || out != want {
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
		{"an unknown flag", []string{"-Q", "AS-TOP"}, 2, "unknown option -Q"},
		{"two formats", []string{"-j", "-b", "AS-TOP"}, 2, "choose one"},
		{"-t in Cisco", []string{"-t", "AS-TOP"}, 2, "writes no as-sets"},
		{"-t over a route-set", []string{"-t", "-j", "RS-TOP"}, 2, "not RS-TOP"},
		{"a filter-set", []string{"FLTR-X"}, 2, "filter-set"},
		{"not an object", []string{"x!"}, 2, "not an AS number"},
		{"AS-ANY", []string{"AS-ANY"}, 2, "whole IRR"},
		{"a missing set", []string{"AS-NOPE"}, 1, "not found"},
		{"Junos with ranges", []string{"-J", "--ranges", "RS-TOP"}, 2, "Junos"},
		{"a dump that is not there", []string{"--dump", "/nonexistent/x.db", "AS-TOP"}, 1, "no such file"},
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

// --server-expand lets the server expand an as-set: its answer is taken as it is, special
// AS numbers' routes included, as plain bgpq4 takes it.
func TestRpslqServerSide(t *testing.T) {
	addr := irrtest.New(corpus...).WithSources("TEST").IRRd(t)
	code, out, errs := rpslq(t, "-h", addr, "-S", "TEST", "--server-expand", "-P", "AS-TOP")
	if want := "100.64.0.0/24\n198.51.100.0/24\n203.0.113.0/24\n203.0.113.128/25\n"; code != 0 || out != want {
		t.Errorf("--server-expand: exit %d %q\n got %q\nwant %q", code, errs, out, want)
	}
	for _, args := range [][]string{{"--whois", "--server-expand", "AS-TOP"}, {"--dump", "x.db", "--server-expand", "AS-TOP"}} {
		if code, _, errs := rpslq(t, args...); code != 2 || !strings.Contains(errs, "needs IRRd") {
			t.Errorf("%v: exit %d %q, want a usage error", args, code, errs)
		}
	}
	// A server without "!a" is named as the cause.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					switch line := sc.Text(); {
					case line == "!!":
					case strings.HasPrefix(line, "!a"):
						fmt.Fprint(c, "F Unrecognized command\n")
					case line == "!q":
						return
					default:
						fmt.Fprint(c, "C\n")
					}
				}
			}()
		}
	}()
	if code, _, errs := rpslq(t, "-h", ln.Addr().String(), "--server-expand", "AS-TOP"); code != 1 || !strings.Contains(errs, "drop --server-expand") {
		t.Errorf("a server without !a: exit %d %q", code, errs)
	}
}

// The bgpq4 features beyond a plain list, over the same corpus.
func TestRpslqFeatures(t *testing.T) {
	addr := irrtest.New(corpus...).WithSources("TEST").IRRd(t)
	base := []string{"-h", addr, "-S", "TEST"}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"-A aggregates", []string{"-AP", "RS-TOP"}, "10.0.0.0/30^+\n192.0.2.0/24\n"},
		{"-R allows more-specifics", []string{"-R", "25", "-P", "AS2"}, "203.0.113.0/24^24-25\n"},
		{"a literal prefix and range", []string{"-P", "AS2", "198.51.100.0/24", "10.0.0.0/31^+"},
			"10.0.0.0/31\n10.0.0.0/32\n10.0.0.1/32\n198.51.100.0/24\n203.0.113.0/24\n"},
		{"EXCEPT in an as-set", []string{"-pP", "AS-TOP", "EXCEPT", "AS-INNER", "AS1"}, "203.0.113.0/24\n"},
		{"EXCEPT in a route-set", []string{"-P", "RS-TOP", "EXCEPT", "RS-GONE"},
			"10.0.0.0/30\n10.0.0.0/31\n10.0.0.0/32\n10.0.0.1/32\n10.0.0.2/31\n10.0.0.2/32\n10.0.0.3/32\n192.0.2.0/24\n"},
		{"-f", []string{"-p", "-f", "2", "AS-TOP"}, "no ip as-path access-list NN\n" +
			"ip as-path access-list NN permit ^2(_2)*$\n" +
			"ip as-path access-list NN permit ^2(_[0-9]+)*_(1|3|64500)$\n"},
		{"-w drops ASes without routes", []string{"-w", "-j", "-f", "2", "AS-TOP", "AS9"}, "{\"NN\": [\n  1,2,3\n]}\n"},
		{"-lNAME bundled", []string{"-jlLIST", "AS2"}, "{ \"LIST\": [\n    { \"prefix\": \"203.0.113.0\\/24\", \"exact\": true }\n] }\n"},
	} {
		code, out, errs := rpslq(t, append(append([]string(nil), base...), c.args...)...)
		if code != 0 || out != c.want {
			t.Errorf("%s: exit %d, stderr %q\n got %q\nwant %q", c.name, code, errs, out, c.want)
		}
	}
	for _, c := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"a prefix of the other family", []string{"-6", "192.0.2.0/24"}, 1, "not an IPv6 prefix"},
		{"a prefix longer than -m", []string{"-m", "23", "192.0.2.0/24"}, 1, "at most /23"},
		{"SOURCE::", []string{"RIPE::AS-TOP"}, 2, "SOURCE::OBJECT"},
		{"EXCEPT a prefix", []string{"AS-TOP", "EXCEPT", "192.0.2.0/24"}, 2, "EXCEPT takes"},
		{"-t over a prefix", []string{"-tj", "192.0.2.0/24"}, 2, "takes as-sets"},
		{"a former single-dash option", []string{"-whois", "AS-TOP"}, 2, "--whois"},
	} {
		code, _, errs := rpslq(t, append(append([]string(nil), base...), c.args...)...)
		if code != c.code || !strings.Contains(errs, c.msg) {
			t.Errorf("%s: exit %d, stderr %q; want %d with %q", c.name, code, errs, c.code, c.msg)
		}
	}
}
