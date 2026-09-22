package policy

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseSetNameTemplate(t *testing.T) {
	cases := []struct {
		in    string
		class types.SetClass
		inst  string // Instantiate(AS5).String()
	}{
		{"AS8821:AS-CUSTOMERS:PeerAS", types.ClassAsSet, "AS8821:AS-CUSTOMERS:AS5"},
		{"PeerAS:AS-TO-GRNET", types.ClassAsSet, "AS5:AS-TO-GRNET"},
		{"peeras:as-x", types.ClassAsSet, "AS5:AS-X"}, // SetName is canonical
		{"AS1:RS-FOO:PeerAS", types.ClassRouteSet, "AS1:RS-FOO:AS5"},
		{"AS1:FLTR-X:PEERAS", types.ClassFilterSet, "AS1:FLTR-X:AS5"},
	}
	for _, c := range cases {
		tpl, err := ParseSetNameTemplate(c.in)
		if err != nil {
			t.Errorf("ParseSetNameTemplate(%q) unexpected err: %v", c.in, err)
			continue
		}
		if tpl.String() != c.in || tpl.Class() != c.class {
			t.Errorf("ParseSetNameTemplate(%q) = %q class %v, want class %v", c.in, tpl.String(), tpl.Class(), c.class)
		}
		if got := tpl.Instantiate(5); got.String() != c.inst || got.Class() != c.class {
			t.Errorf("%q.Instantiate(AS5) = %q (%v), want %q", c.in, got.String(), got.Class(), c.inst)
		}
	}

	a, _ := ParseSetNameTemplate("AS1:AS-X:PeerAS")
	b, _ := ParseSetNameTemplate("AS1:AS-X:PeerAS")
	if !map[SetNameTemplate]bool{a: true}[b] {
		t.Error("identical templates are not == (not usable as map keys)")
	}
}

func TestParseSetNameTemplateRejects(t *testing.T) {
	for _, in := range []string{
		"", "AS-FOO", // no PeerAS component: an ordinary set name, not a template
		"PeerAS", "PeerAS:PeerAS", "PeerAS:AS1", // no set component once instantiated
		"AS-X:RS-Y:PeerAS", // mixed set classes
		"AS-X:PeerAS^+", "AS-X: PeerAS", "PeerASX:AS-Y",
	} {
		if tpl, err := ParseSetNameTemplate(in); err == nil {
			t.Errorf("ParseSetNameTemplate(%q) = %q, want error", in, tpl.String())
		}
	}
}
