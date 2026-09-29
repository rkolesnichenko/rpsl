package policy

import (
	"reflect"
	"testing"
)

// String renders a regexp that parses back to the same tree, and renders the
// same text again: the canonical form a printer and a normal form rely on.
func TestASPathREStringRoundTrips(t *testing.T) {
	for _, s := range []string{
		"^AS1+ AS2*$", ".", "AS-FOO", "AS1|AS2", "(AS1 AS2)+", "^AS1 .* $",
		"[AS1 AS2 - AS5 AS-FOO]", "[^AS1 .]", "AS1~*", "(AS1 | AS2)~{2,3}",
		"AS1{2}", "AS1{2,}", "AS1{2,4}", "AS1?", "^PeerAS+ AS1:AS-X:PeerAS*$",
		"AS1 (AS2 | AS3) $", "(^AS1 | AS2$)", "[PeerAS AS1:AS-X:PeerAS]",
		"()", "AS1 () AS2", "(AS1 | ())",
	} {
		re, err := ParseASPathRegexp(s)
		if err != nil {
			t.Fatalf("ParseASPathRegexp(%q): %v", s, err)
		}
		text := re.String()
		back, err := ParseASPathRegexp(text)
		if err != nil {
			t.Fatalf("%q renders as %q, which does not parse: %v", s, text, err)
		}
		if !reflect.DeepEqual(re, back) {
			t.Errorf("%q renders as %q, which parses to a different tree", s, text)
		}
		if again := back.String(); again != text {
			t.Errorf("%q: String is not stable: %q then %q", s, text, again)
		}
	}
}

func TestASPathREBind(t *testing.T) {
	re, err := ParseASPathRegexp("^PeerAS AS1:AS-X:PeerAS [PeerAS AS2] AS-Y")
	if err != nil {
		t.Fatal(err)
	}
	before := re.String()
	if !re.UsesPeer() {
		t.Fatalf("%s: UsesPeer() = false", before)
	}
	b := re.Bind(65000)
	if got, want := b.String(), "^ AS65000 AS1:AS-X:AS65000 [AS65000 AS2] AS-Y"; got != want {
		t.Errorf("Bind(65000) = %q, want %q", got, want)
	}
	if b.UsesPeer() {
		t.Errorf("%s: still uses the peer after Bind", b)
	}
	if re.String() != before {
		t.Errorf("Bind modified its receiver: %q became %q", before, re.String())
	}
	if re.Bind(0) != re {
		t.Errorf("Bind(0) did not return its receiver")
	}
	plain, _ := ParseASPathRegexp("AS1 AS2")
	if plain.UsesPeer() {
		t.Errorf("AS1 AS2: UsesPeer() = true")
	}
}

func TestASPathRESetNames(t *testing.T) {
	re, err := ParseASPathRegexp("AS-B AS-A (AS-B | [AS-C AS1]) AS1:AS-D:PeerAS")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range re.Bind(7).SetNames() {
		got = append(got, n.String())
	}
	want := []string{"AS-A", "AS-B", "AS-C", "AS1:AS-D:AS7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SetNames() = %v, want %v", got, want)
	}
	var none *ASPathRE
	if none.String() != "" || none.UsesPeer() || none.SetNames() != nil || none.Bind(1) != nil {
		t.Errorf("a nil regexp is not inert")
	}
}
