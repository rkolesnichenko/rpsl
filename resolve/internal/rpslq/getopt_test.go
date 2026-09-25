package rpslq

import (
	"strings"
	"testing"
)

func TestGetopt(t *testing.T) {
	for _, c := range []struct {
		args     string
		opts     string
		operands string
	}{
		{"-6Ab AS-X", "6 A b", "AS-X"},
		{"-lNAME -l NAME2 AS-X", "l=NAME l=NAME2", "AS-X"},
		{"-Jl NAME AS-X", "J l=NAME", "AS-X"},
		{"-K7 -n2", "K 7 n 2", ""},
		{"-f65000 AS-X", "f=65000", "AS-X"},
		{"AS-X -l N EXCEPT AS1", "l=N", "AS-X EXCEPT AS1"},
		{"-- -j", "", "-j"},
		{"--whois --dump=a.db --dump b.db --timeout 3s AS1", "whois dump=a.db dump=b.db timeout=3s", "AS1"},
		{"-", "", "-"},
	} {
		opts, operands, err := getopt(strings.Fields(c.args))
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		var got []string
		for _, o := range opts {
			if o.arg != "" {
				got = append(got, o.name+"="+o.arg)
			} else {
				got = append(got, o.name)
			}
		}
		if strings.Join(got, " ") != c.opts || strings.Join(operands, " ") != c.operands {
			t.Errorf("%q: options %q operands %q; want %q, %q", c.args, got, operands, c.opts, c.operands)
		}
	}
	for args, msg := range map[string]string{
		"-l":          "needs an argument",
		"-Q":          "unknown option -Q",
		"-:":          "unknown option -:",
		"--nope":      "unknown option --nope",
		"--whois=1":   "takes no argument",
		"--dump":      "needs an argument",
		"-whois AS1":  "--whois",
		"-ranges AS1": "--ranges",
		"-dump x AS1": "--dump",
		"-timeout 1s": "--timeout",
		"-help":       "--help",
	} {
		if _, _, err := getopt(strings.Fields(args)); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want an error with %q", args, err, msg)
		}
	}
}

// bgpq4's rules on what goes together, as parse applies them.
func TestParseRules(t *testing.T) {
	for args, msg := range map[string]string{
		"-b -J AS1":                       "choose one vendor",
		"-E -t AS1":                       "mutually exclusive",
		"-2 AS1":                          "only be used after -n",
		"-K -2 AS1":                       "only be used after -n",
		"-7 AS1":                          "only be used after -K",
		"-4 -6 AS1":                       "mutually exclusive",
		"-6 -4 AS1":                       "mutually exclusive",
		"-JA AS1":                         "Junos prefix-lists",
		"-f 1 -6 AS1":                     "-6 makes no sense",
		"-w AS1":                          "-w is for as-path",
		"-r 24 -R 20 AS1":                 "longer than -R",
		"-R 33 AS1":                       "longer than an address",
		"-m 33 AS1":                       "longer than an address",
		"-m 0 AS1":                        "at least 1",
		"-L 0 AS1":                        "at least 1",
		"-m x AS1":                        "wants a number",
		"-a AS-TOP":                       "--server-expand",
		"-f AS-X AS1":                     "wants an AS number",
		"--ranges -A AS1":                 "--ranges",
		"-M 'a\\n' -JE AS1":               "unsupported escape",
		"-M x AS1":                        "-M",
		"-s -b AS1":                       "sequence numbers",
		"-F %q AS1":                       "unknown directive",
		"-D AS1":                          "unknown option -D",
		"EXCEPT AS1":                      "no objects",
		"--server-expand AS-X EXCEPT AS1": "cannot leave out",
	} {
		_, _, err := parse(splitArgs(args))
		if err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want an error with %q", args, err, msg)
		}
	}
	c, _, err := parse([]string{"-JE", "-M", "community a;\\\nb", "-r", "25", "-6", "AS1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.refine != 128 || c.o.Match != "community a;\nb" {
		t.Errorf("-r alone: -R %d; -M %q", c.refine, c.o.Match)
	}
	c, _, _ = parse([]string{"-Xf", "65000", "AS1"})
	if c.o.Width != 6 {
		t.Errorf("XR -f width %d, want 6", c.o.Width)
	}
	c, _, _ = parse([]string{"-Xf", "65000", "-W", "0", "AS1"})
	if c.o.Width != 0 {
		t.Errorf("-W 0 width %d, want 0", c.o.Width)
	}
}

// splitArgs splits on spaces, keeping single-quoted words whole.
func splitArgs(s string) []string {
	var out []string
	for i, part := range strings.Split(s, "'") {
		if i%2 == 1 {
			out = append(out, part)
			continue
		}
		out = append(out, strings.Fields(part)...)
	}
	return out
}

func TestVersion(t *testing.T) {
	code, out, _ := rpslq(t, "-v")
	if code != 0 || !strings.HasPrefix(out, "rpslq ") {
		t.Errorf("-v: exit %d, %q", code, out)
	}
}
