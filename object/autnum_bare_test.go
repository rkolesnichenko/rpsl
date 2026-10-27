package object

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// LACNIC's whois dump writes every aut-num's key as a bare number
// ("aut-num: 278"), where RPSL writes "AS278": it reads as that AS, with a
// Warning. Only the key: origin: and the rest still need the AS.
func TestAutNumBareNumber(t *testing.T) {
	cases := []struct {
		key  string
		as   types.ASN
		rule string // the one diagnostic, "" for none
	}{
		{"278", 278, "object/aut-num-bare-number"},
		{"0278", 278, "object/aut-num-bare-number"},
		{"4294967295", 4294967295, "object/aut-num-bare-number"},
		{"AS278", 278, ""},
		{"as278", 278, ""},
		{"4294967296", 0, "object/aut-num-as"},
		{"278.5", 0, "object/aut-num-as"},
		{"+278", 0, "object/aut-num-as"},
		{"-278", 0, "object/aut-num-as"},
		{"27 8", 0, "object/aut-num-as"},
		{"", 0, "object/empty-key"}, // reported once

	}
	for _, c := range cases {
		obj, diags := Decode(parse("aut-num: " + c.key + "\nas-name: X\n"))
		an := obj.(*AutNum)
		if an.AS != c.as {
			t.Errorf("%q: AS %v, want %v", c.key, an.AS, c.as)
		}
		switch {
		case c.rule == "" && len(diags) != 0:
			t.Errorf("%q: %v, want no diagnostic", c.key, diags)
		case c.rule != "" && (len(diags) != 1 || diags[0].Rule != c.rule):
			t.Errorf("%q: %v, want one %s", c.key, diags, c.rule)
		case c.rule == "object/aut-num-bare-number" && (diags[0].Severity.String() != "warning" || !strings.Contains(diags[0].Message, "AS"+strings.TrimLeft(c.key, "0"))):
			t.Errorf("%q: %v, want a Warning naming the AS it reads", c.key, diags[0])
		}
	}

	// origin: is not the key: a bare number there is still an Error.
	_, diags := Decode(parse("route: 192.0.2.0/24\norigin: 278\n"))
	if len(diags) != 1 || diags[0].Rule != "object/route-origin" {
		t.Errorf("route with origin: 278: %v, want one object/route-origin", diags)
	}
}
