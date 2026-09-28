package types

import "testing"

func TestParseSourceName(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"RIPE", "RIPE", true},
		{"ripe-nonauth", "RIPE-NONAUTH", true},
		{"Level3_x", "LEVEL3_X", true},
		{"", "", false},
		{"RI PE", "", false},
		{"RIPE,RADB", "", false},
		{"RIPE\n!q", "", false},
		{"ＲＩＰＥ", "", false},                   // full-width letters are not ASCII
		{string(make([]byte, 65)), "", false}, // over MaxSourceNameLen (and NULs)
	} {
		got, err := ParseSourceName(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseSourceName(%q) = %q, %v; want %q, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParseSetRef(t *testing.T) {
	for _, tc := range []struct {
		in, want, source string
		ok, scoped       bool
	}{
		{"AS-FOO", "AS-FOO", "", true, false},
		{"as-foo", "AS-FOO", "", true, false},
		{"RIPE::AS-FOO", "RIPE::AS-FOO", "RIPE", true, true},
		{"ripe::as-foo", "RIPE::AS-FOO", "RIPE", true, true},
		{"  RIPE::AS1:RS-X  ", "RIPE::AS1:RS-X", "RIPE", true, true},
		{"RIPE :: AS-FOO", "", "", false, false},
		{"RIPE:: AS-FOO", "", "", false, false},
		{"RIPE ::AS-FOO", "", "", false, false},
		{"::AS-FOO", "", "", false, false},
		{"RIPE::", "", "", false, false},
		{"RIPE::AS1", "", "", false, false}, // an AS number is not a set
		{"ＲＩＰＥ::AS-FOO", "", "", false, false},
		{"RIPE::RADB::AS-FOO", "", "", false, false},
	} {
		r, err := ParseSetRef(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseSetRef(%q) error = %v; want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if r.String() != tc.want || r.Source() != tc.source || r.IsScoped() != tc.scoped {
			t.Errorf("ParseSetRef(%q) = %q (source %q, scoped %v); want %q (%q, %v)",
				tc.in, r, r.Source(), r.IsScoped(), tc.want, tc.source, tc.scoped)
		}
	}
}

func TestSetRefIsComparable(t *testing.T) {
	a, _ := ParseSetRef("ripe::as-foo")
	b, _ := ParseSetRef("RIPE::AS-FOO")
	c, _ := ParseSetRef("AS-FOO")
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
	if a == c {
		t.Errorf("scoped %v == unscoped %v", a, c)
	}
	if c != Ref(c.Name()) {
		t.Errorf("Ref(%v) differs from the parsed unscoped ref", c.Name())
	}
	m := map[SetRef]bool{a: true}
	if !m[b] || m[c] {
		t.Error("SetRef map keys do not follow ==")
	}
}

func TestNewSetRef(t *testing.T) {
	n, _ := ParseSetName("AS-FOO")
	if r, err := NewSetRef("", n); err != nil || r.IsScoped() || r.Name() != n {
		t.Errorf(`NewSetRef("", AS-FOO) = %v, %v`, r, err)
	}
	if r, err := NewSetRef("radb", n); err != nil || r.String() != "RADB::AS-FOO" {
		t.Errorf(`NewSetRef("radb", AS-FOO) = %v, %v`, r, err)
	}
	if _, err := NewSetRef("RA DB", n); err == nil {
		t.Error(`NewSetRef("RA DB", …) accepted a bad source`)
	}
	if _, err := NewSetRef("RIPE", SetName{}); err == nil {
		t.Error("NewSetRef accepted a zero SetName")
	}
	if !(SetRef{}).IsZero() || Ref(n).IsZero() {
		t.Error("IsZero is wrong")
	}
}
