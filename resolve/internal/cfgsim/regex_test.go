package cfgsim

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestMatchDialects(t *testing.T) {
	p := func(as ...types.ASN) []types.ASN { return as }
	for _, c := range []struct {
		dialect, re string
		path        []types.ASN
		want        bool
	}{
		{"ios", "_1_", p(2, 1, 3), true},
		{"ios", "_1_", p(2, 12, 3), false},
		{"ios", "^_4(_(1|10|11|12|14))*$", p(4, 10, 1), true},
		{"ios", "^_4(_(1|10|11|12|14))*$", p(4, 13), false},
		{"ios", "^$", p(), true},
		{"ios", "^_1(_[0-9]+)*_2$", p(1, 5, 6, 2), true},
		{"junos", ".* 1 .*", p(2, 1, 3), true},
		{"junos", ".* 666 .*", p(2, 666), true},
		{"junos", ".* 666 .*", p(666), true},
		{"junos", ".*", p(), true},
		{"junos", ". .*", p(), false},
		{"junos", ".+", p(), false},
		{"junos", "1", p(1, 2), false},
		{"junos", " 4((1|10-12|14))*", p(4, 11, 14), true},
		{"junos", " 4((1|10-12|14))*", p(4, 13), false},
		{"junos", "()", p(), true},
		{"junos", "1{2,3}", p(1, 1, 1), true},
		{"bird", "[= * 1 * =]", p(2, 1, 3), true},
		{"bird", "[= 1 * 2 =]", p(1, 2), true},
		{"bird", "[= 1 [10, 20..22] =]", p(1, 21), true},
		{"bird", "[= 1 [10, 20..22] =]", p(1, 23), false},
		{"bird", "[= ? * =]", p(), false},
		{"bird", "[= =]", p(), true},
	} {
		var got bool
		var err error
		switch c.dialect {
		case "ios":
			got, err = MatchIOS(c.re, c.path)
		case "junos":
			got, err = MatchJunos(c.re, c.path)
		default:
			got, err = MatchBIRD(c.re, c.path)
		}
		if err != nil || got != c.want {
			t.Errorf("%s %q on %v = %v, %v; want %v", c.dialect, c.re, c.path, got, err, c.want)
		}
	}
}

func TestCanonCommunity(t *testing.T) {
	for in, want := range map[string]string{
		"1:2": "1:2", "no-export": "65535:65281", "NO_EXPORT": "65535:65281", "local-AS": "65535:65283",
		"no-export-subconfed": "65535:65283", "(1,2)": "1:2", "4294967041": "65535:65281",
	} {
		if got, ok := CanonCommunity(in); !ok || got != want {
			t.Errorf("CanonCommunity(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
