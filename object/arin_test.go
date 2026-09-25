package object

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// ARIN's profile is IRRd's table for each of ARIN's five classes, with the
// created: and last-modified: ARIN generates, and holds no other class.
func TestARINProfileIsIRRdPlusGenerated(t *testing.T) {
	five := []string{"route", "route6", "aut-num", "as-set", "route-set"}
	for _, class := range five {
		a, ok := ARIN.Class(class)
		if !ok {
			t.Fatalf("ARIN has no %s", class)
		}
		i, _ := IRRd.Class(class)
		want := map[string]AttrSpec{}
		for name, s := range i.Attrs {
			want[name] = s
		}
		want["created"] = AttrSpec{Single: true}
		want["last-modified"] = AttrSpec{Single: true}
		if !reflect.DeepEqual(a.Attrs, want) || a.AllowUnknown != i.AllowUnknown || !reflect.DeepEqual(a.OneOf, i.OneOf) {
			t.Errorf("ARIN %s = %+v, want IRRd's %+v with created and last-modified", class, a, want)
		}
	}
	if got := ARIN.Classes(); len(got) != len(five) {
		t.Errorf("ARIN holds %v, want the five classes ARIN's IRR has", got)
	}
	// Deriving ARIN's tables must not have changed IRRd's.
	if i, _ := IRRd.Class("route"); i.Attrs["last-modified"].Single {
		t.Error("IRRd's last-modified: became single")
	} else if _, ok := i.Attrs["created"]; ok {
		t.Error("IRRd's route gained created:")
	}
}

func TestARINProfile(t *testing.T) {
	rules := func(src string) string {
		var out []string
		for _, d := range ARIN.Validate(ast.New(lexer.Tokenize(src))) {
			out = append(out, d.Rule)
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct{ name, src, want string }{
		{"a route made in ARIN Online",
			"route: 192.0.2.0/24\ndescr: X\norigin: AS1\nadmin-c: X-ARIN\ntech-c: X-ARIN\nmnt-by: MNT-X\n" +
				"created: 2024-01-01T00:00:00Z\nlast-modified: 2024-01-02T00:00:00Z\nsource: ARIN\n", ""},
		{"a legacy route, migrated in 2020",
			"route: 192.0.2.0/24\ndescr: X\norigin: AS1\nnotify: a@b.net\nmnt-by: MNT-X\nchanged: a@b.net 20100101\nsource: ARIN\n", ""},
		{"created: twice",
			"route6: 2001:db8::/32\norigin: AS1\nmnt-by: M\ncreated: 2024-01-01T00:00:00Z\ncreated: 2024-01-01T00:00:00Z\nsource: ARIN\n",
			"dict/cardinality"},
		{"last-modified: twice",
			"as-set: AS-X\nmnt-by: M\nlast-modified: 2024-01-01T00:00:00Z\nlast-modified: 2024-01-02T00:00:00Z\nsource: ARIN\n",
			"dict/cardinality"},
		{"a legacy aut-num without contacts",
			"aut-num: AS1\nas-name: X\nmnt-by: M\nsource: ARIN\n", "dict/missing-required dict/missing-required"},
		{"a class ARIN's IRR does not hold",
			"inetnum: 192.0.2.0 - 192.0.2.255\nnetname: X\ncountry: US\nadmin-c: X\ntech-c: X\nstatus: X\nmnt-by: M\nsource: ARIN\n",
			"dict/unknown-class"},
	} {
		if got := rules(c.src); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
