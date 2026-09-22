package types

import (
	"encoding"
	"encoding/json"
	"reflect"
	"testing"
)

// Every value type has a text form: MarshalText writes what the parser reads,
// so values round-trip through JSON, YAML, flags and map keys.
func TestTextRoundTrip(t *testing.T) {
	asn, _ := ParseASN("AS65001")
	set, _ := ParseSetName("as1:as-foo")
	pr, _ := ParsePrefixRange("192.0.2.0/24^25-26")
	op, _ := ParseRangeOperator("24-32")
	af, _ := ParseAddrFamily("ipv6.unicast")
	nic, _ := ParseNICHandle("EX1-RIPE")
	cases := []struct {
		v    encoding.TextMarshaler
		ptr  encoding.TextUnmarshaler
		text string
	}{
		{asn, new(ASN), "AS65001"},
		{set, new(SetName), "AS1:AS-FOO"},
		{pr, new(PrefixRange), "192.0.2.0/24^25-26"},
		{op, new(RangeOperator), "^24-32"},
		{af, new(AddrFamily), "ipv6.unicast"},
		{nic, new(NICHandle), "EX1-RIPE"},
	}
	for _, c := range cases {
		b, err := c.v.MarshalText()
		if err != nil || string(b) != c.text {
			t.Errorf("%T.MarshalText() = %q, %v; want %q", c.v, b, err, c.text)
			continue
		}
		if err := c.ptr.UnmarshalText(b); err != nil {
			t.Errorf("%T.UnmarshalText(%q): %v", c.ptr, b, err)
			continue
		}
		if got := reflect.ValueOf(c.ptr).Elem().Interface(); got != c.v {
			t.Errorf("%T round-trip = %v, want %v", c.v, got, c.v)
		}
		if err := c.ptr.UnmarshalText([]byte("not valid!")); err == nil {
			t.Errorf("%T.UnmarshalText accepted garbage", c.ptr)
		}
	}
}

// JSON uses the text forms. An ASN also decodes from a JSON number, as RDAP
// and many APIs write it.
func TestJSON(t *testing.T) {
	type doc struct {
		AS    ASN
		Set   SetName
		Range PrefixRange
	}
	in := doc{}
	in.AS, _ = ParseASN("AS3333")
	in.Set, _ = ParseSetName("AS-RIPENCC")
	in.Range, _ = ParsePrefixRange("193.0.0.0/21^+")
	b, err := json.Marshal(in)
	if want := `{"AS":"AS3333","Set":"AS-RIPENCC","Range":"193.0.0.0/21^+"}`; err != nil || string(b) != want {
		t.Fatalf("json.Marshal = %s, %v; want %s", b, err, want)
	}
	var out doc
	if err := json.Unmarshal(b, &out); err != nil || out != in {
		t.Errorf("json round-trip = %+v, %v; want %+v", out, err, in)
	}
	var n struct{ AS ASN }
	if err := json.Unmarshal([]byte(`{"AS":3333}`), &n); err != nil || n.AS != 3333 {
		t.Errorf("ASN from a JSON number = %v, %v", n.AS, err)
	}
	if err := json.Unmarshal([]byte(`{"AS":-1}`), &n); err == nil {
		t.Error("ASN accepted -1")
	}
	if err := json.Unmarshal([]byte(`{"AS":4294967296}`), &n); err == nil {
		t.Error("ASN accepted 2^32")
	}
}
