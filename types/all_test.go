package types

import (
	"net/netip"
	"reflect"
	"testing"
)

// All yields exactly what Materialize returns, in the same order.
func TestPrefixRangeAllMatchesMaterialize(t *testing.T) {
	for _, s := range []string{
		"192.0.2.0/24", "192.0.2.0/24^26", "192.0.2.0/24^25-26", "192.0.2.1/32^-",
		"10.0.0.0/30^+", "10.0.0.0/30^-", "2001:db8::/126^+", "2001:db8::/32^34",
	} {
		r, err := ParsePrefixRange(s)
		if err != nil {
			t.Fatal(err)
		}
		want, err := r.Materialize(1000)
		if err != nil {
			t.Fatalf("Materialize(%s): %v", s, err)
		}
		var got []netip.Prefix
		for p := range r.All() {
			got = append(got, p)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: All() = %v, want %v", s, got, want)
		}
	}
}

// All is lazy: a consumer can stop after a few prefixes of a range far too
// large to enumerate (2^129-1 prefixes for ::/0^+).
func TestPrefixRangeAllStopsEarly(t *testing.T) {
	for s, want := range map[string][]string{
		"0.0.0.0/0^+": {"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"},
		"::/0^+":      {"::/0", "::/1", "8000::/1"},
	} {
		r, _ := ParsePrefixRange(s)
		var got []string
		for p := range r.All() {
			got = append(got, p.String())
			if len(got) == 3 {
				break
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: first three = %v, want %v", s, got, want)
		}
	}
}

// The zero PrefixRange denotes nothing (it used to materialize to [::/0 ::/0]).
func TestZeroPrefixRangeIsEmpty(t *testing.T) {
	var r PrefixRange
	for p := range r.All() {
		t.Fatalf("zero PrefixRange yielded %v", p)
	}
	if got, err := r.Materialize(10); err != nil || len(got) != 0 {
		t.Errorf("zero PrefixRange Materialize = %v, %v; want empty", got, err)
	}
}
