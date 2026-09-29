package irrd

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// FuzzReadFrame feeds readFrame what a hostile server might send. It must
// never panic, never return more than max bytes, and read back exactly the
// payload of any well-formed frame.
func FuzzReadFrame(f *testing.F) {
	for _, s := range []string{"A8\nAS1 AS2\nC\n", "C\n", "D\n", "F no such source\n", "A-1\n", "A99999\nshort", "A3\nabcX\n", "A0\nC\n", "\n"} {
		f.Add([]byte(s), uint16(64))
	}
	f.Fuzz(func(t *testing.T, data []byte, max uint16) {
		got, err := readFrame(bufio.NewReader(bytes.NewReader(data)), int64(max))
		if err == nil && len(got) > int(max) {
			t.Fatalf("readFrame returned %d bytes under a cap of %d", len(got), max)
		}
		// The input as a payload, framed, reads back as itself.
		frame := fmt.Sprintf("A%d\n%sC\n", len(data), data)
		back, err := readFrame(bufio.NewReader(strings.NewReader(frame)), int64(len(data)))
		if err != nil || !bytes.Equal(back, data) {
			t.Fatalf("a frame of %q read back as %q, %v", data, back, err)
		}
	})
}

// FuzzParseMembers holds parseMembers to its contract: one member per token
// of the payload, split at ASCII whitespace, each carrying its token as Raw.
func FuzzParseMembers(f *testing.F) {
	for _, s := range []string{"AS1 AS2 AS-FOO", " 10.0.0.0/8^+\t2001:db8::/32\n", "RS-A^24-32 junk", "", " AS1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		for _, class := range []types.SetClass{types.ClassAsSet, types.ClassRouteSet} {
			got := parseMembers(payload, class)
			want := strings.FieldsFunc(payload, func(r rune) bool { return r < 0x80 && isSpace(byte(r)) })
			if len(got) != len(want) {
				t.Fatalf("parseMembers(%q) gave %d members, want %d", payload, len(got), len(want))
			}
			for i, m := range got {
				if m.Raw != want[i] {
					t.Fatalf("parseMembers(%q) member %d is %q, want %q", payload, i, m.Raw, want[i])
				}
			}
		}
	})
}

// FuzzParseRegistries: parseRegistries reads a server's answer to "!j-*", which
// is untrusted. It never panics; it returns nil or a non-empty set; each name
// it returns is a canonical source name that the answer lists on a line of its
// own, never one the answer only calls "Database unknown".
func FuzzParseRegistries(f *testing.F) {
	for _, s := range []string{
		radbSerialRange,
		"ripe:N:0-1\r\nFOO:X:Database unknown\n",
		"RIPE:X:Database unknown\nRIPE:N:0-1\n",
		"", ":", "\n\n", "RIPE", "RIPE:", ":N:-", "ɐ:N:-", "RI PE:N:-", "RIPE:N:0-1\nnot a line\n",
		strings.Repeat("A:N:-\n", 64),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		got := parseRegistries(payload)
		if got == nil {
			return
		}
		if len(got) == 0 {
			t.Fatalf("parseRegistries(%q) = an empty set; want nil", payload)
		}
		listed := map[string]bool{} // names of lines that are not "Database unknown"
		for _, line := range strings.Split(string(payload), "\n") {
			name, rest, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
			if ok && !strings.HasPrefix(rest, "X:") {
				listed[strings.ToUpper(name)] = true
			}
		}
		for name := range got {
			if canon, err := types.ParseSourceName(name); err != nil || canon != name {
				t.Fatalf("parseRegistries(%q) returned %q, not a canonical source name", payload, name)
			}
			if !listed[name] {
				t.Fatalf("parseRegistries(%q) returned %q, which no listed line names", payload, name)
			}
		}
	})
}
