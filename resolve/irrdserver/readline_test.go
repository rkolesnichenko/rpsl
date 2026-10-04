package irrdserver

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// TestReadLine: lines crossing the read buffer, arriving a byte at a time,
// held to max exactly, newline or not.
func TestReadLine(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want []string
		err  error
	}{
		{"a\nbb\n", 2, []string{"a", "bb"}, io.EOF},
		{"a\nbbb\n", 2, []string{"a"}, errLineTooLong},
		{"bbb", 2, nil, errLineTooLong},
		{"bb", 2, nil, io.EOF},
		{strings.Repeat("x", 40) + "\ny\n", 40, []string{strings.Repeat("x", 40), "y"}, io.EOF},
		{strings.Repeat("x", 41) + "\n", 40, nil, errLineTooLong},
		{strings.Repeat("x", 41), 40, nil, errLineTooLong},
	} {
		for _, dribble := range []bool{false, true} {
			var r io.Reader = strings.NewReader(c.in)
			if dribble {
				r = iotest.OneByteReader(r)
			}
			br := bufio.NewReaderSize(r, 16) // the smallest: lines cross it
			var got []string
			var err error
			for {
				var l string
				if l, err = readLine(br, c.max); err != nil {
					break
				}
				got = append(got, l)
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") || !errors.Is(err, c.err) {
				t.Errorf("%.20q (max %d, dribble %v): %q, %v; want %q, %v", c.in, c.max, dribble, got, err, c.want, c.err)
			}
		}
	}
}

// BenchmarkReadLineDribble: a 60 KiB line arriving a byte per read. Each
// byte's arrival rescans only what is new.
func BenchmarkReadLineDribble(b *testing.B) {
	line := strings.Repeat("x", 60<<10) + "\n"
	for i := 0; i < b.N; i++ {
		br := bufio.NewReaderSize(iotest.OneByteReader(strings.NewReader(line)), 64<<10)
		if _, err := readLine(br, 1<<20); err != nil {
			b.Fatal(err)
		}
	}
}
