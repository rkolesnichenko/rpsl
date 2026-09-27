package nrtm4

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rkolesnichenko/rpsl"
)

func records(t *testing.T, in string, max int) ([]string, error) {
	t.Helper()
	s := newSeqReader(iotest.OneByteReader(strings.NewReader(in)), max)
	var out []string
	for {
		rec, err := s.next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, string(rec))
	}
}

func TestSeqReader(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"\n", nil},
		{"\x1e{\"a\":1}\n\x1e{\"b\":2}\n", []string{`{"a":1}`, `{"b":2}`}},
		{"\x1e{\"a\":1}\x1e{\"b\":2}", []string{`{"a":1}`, `{"b":2}`}}, // no line feeds
		{"\x1e\n\x1e{\"a\":1}\n\x1e\n", []string{`{"a":1}`}},           // empty records
		{"\n\x1e{\n \"a\": 1\n}\n", []string{"{\n \"a\": 1\n}"}},       // one record over lines
	} {
		got, err := records(t, tc.in, 1<<20)
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := records(t, "{\"a\":1}\n\x1e{\"b\":2}\n", 1<<20); err == nil {
		t.Error("data before the first separator was read")
	}
	long := "\x1e" + strings.Repeat("x", 100) + "\x1e{}"
	if _, err := records(t, long, 99); err == nil || !strings.Contains(err.Error(), "longer") {
		t.Errorf("a record over the cap: %v", err)
	}
	if got, err := records(t, long, 100); err != nil || len(got) != 2 {
		t.Errorf("a record at the cap: %q, %v", got, err)
	}
	// Records longer than the reader's buffer.
	big := strings.Repeat("y", 200<<10)
	if got, err := records(t, "\x1e"+big+"\x1e"+big, 1<<20); err != nil || len(got) != 2 || got[1] != big {
		t.Errorf("long records: %d, %v", len(got), err)
	}
}

func TestKey(t *testing.T) {
	for _, tc := range []struct{ a, b [2]string }{
		{[2]string{"route", "192.0.2.0/24AS64500"}, [2]string{"ROUTE", "192.0.2.0/24as64500"}},
		{[2]string{"route6", "2001:DB8::/32AS64500"}, [2]string{"route6", "2001:db8::/32AS64500"}},
		{[2]string{"route", "064.006.160.000/19AS1"}, [2]string{"route", "64.6.160.0/19AS1"}},
		{[2]string{"aut-num", "as65001"}, [2]string{"aut-num", "AS65001"}},
		{[2]string{"as-set", "as-foo"}, [2]string{"as-set", "AS-FOO"}},
		{[2]string{"as-set", "as1:as-foo"}, [2]string{"as-set", "AS1:AS-FOO"}},
		{[2]string{"inet-rtr", "rtr.example.net"}, [2]string{"inet-rtr", "RTR.EXAMPLE.NET"}},
		{[2]string{"person", "prsn1-example"}, [2]string{"person", "PRSN1-EXAMPLE"}},
	} {
		if ka, kb := key(tc.a[0], tc.a[1]), key(tc.b[0], tc.b[1]); ka != kb {
			t.Errorf("%v → %q, %v → %q", tc.a, ka, tc.b, kb)
		}
	}
	if key("route", "192.0.2.0/24AS1") == key("route", "192.0.2.0/24AS2") {
		t.Error("two origins share a key")
	}
	if key("route", "192.0.2.0/24AS1") == key("route6", "192.0.2.0/24AS1") {
		t.Error("two classes share a key")
	}
	for text, want := range map[string]string{
		"route:  192.0.2.0/24\norigin: as64500 # comment\nsource: X\n": key("route", "192.0.2.0/24AS64500"),
		"route6: 2001:DB8::/32\norigin: AS1\nsource: X\n":              key("route6", "2001:db8::/32AS1"),
		"as-set: as-foo\nsource: X\n":                                  key("as-set", "AS-FOO"),
	} {
		o, _ := rpsl.ParseObject(text)
		if got, ok := objectKey(o); !ok || got != want {
			t.Errorf("objectKey(%q) = %q, want %q", text, got, want)
		}
	}
	o, _ := rpsl.ParseObject("route: 192.0.2.0/24\nsource: X\n")
	if _, ok := objectKey(o); ok {
		t.Error("a route without an origin has a key")
	}
}
