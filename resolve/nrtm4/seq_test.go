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

func TestSeqReaderCapAtEOF(t *testing.T) {
	// The last record has no separator after it: the cap still holds.
	if _, err := records(t, "\x1e"+strings.Repeat("x", 101), 100); err == nil {
		t.Error("a last record over the cap was read")
	}
	if got, err := records(t, "\x1e"+strings.Repeat("x", 100), 100); err != nil || len(got) != 1 {
		t.Errorf("a last record at the cap: %d, %v", len(got), err)
	}
}

func TestHasPrimaryKey(t *testing.T) {
	for text, want := range map[string]bool{
		"route: 192.0.2.0/24\norigin: AS1\nsource: X\n": true,
		"route: 192.0.2.0/24\nsource: X\n":              false, // no origin
		"as-set: AS-FOO\nsource: X\n":                   true,
		"as-set:\nsource: X\n":                          false, // an empty key
	} {
		o, _ := rpsl.ParseObject(text)
		if got := hasPrimaryKey(o); got != want {
			t.Errorf("hasPrimaryKey(%q) = %v, want %v", text, got, want)
		}
	}
}

// skippable agrees with decoding a record in full: a record it skips is one
// objectText reads and object leaves out, and it says false when unsure.
func TestSkippable(t *testing.T) {
	c := &Client{Database: "TEST"}
	for rec, want := range map[string]bool{
		`{"object":"person: A\nnic-hdl: A1-TEST\nsource: TEST\n"}`:           true,
		`{"object":"inetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n"}`:      true,
		`{"object":"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n"}`:      false, // kept
		`{"object":"AS-SET: AS-X\nsource: TEST\n"}`:                          false, // kept, any case
		`{"object":"person: A\n"`:                                            false, // not JSON: refused in full
		`{"object":"person: A","object":"route: 192.0.2.0/24\norigin: AS1"}`: false, // the last one wins
		`{"object":"\u0070erson: A"}`:                                        false, // escaped
		`{ "object": "person: A" }`:                                          false, // another spelling
		`{"object":"person A"}`:                                              false, // no class
		`{"object":": x"}`:                                                   false,
	} {
		if got := skippable([]byte(rec)); got != want {
			t.Errorf("skippable(%s) = %v, want %v", rec, got, want)
		}
		if skippable([]byte(rec)) {
			text, err := objectText([]byte(rec))
			if err != nil || c.object(text, nil) != nil {
				t.Errorf("%s: skipped, but decoding it gives %v, %v", rec, c.object(text, nil), err)
			}
		}
	}
}
