package ast

import "testing"

func TestAttributeValueWithComments(t *testing.T) {
	o := parse("inetnum: 10.0.0.0 - 10.0.0.255\nnetname: DATA#LIMITED\ndescr: Shaw Tower # 16-02/03\n more\nmnt-by: MNT-A\n")
	for _, c := range []struct{ name, value, with string }{
		{"netname", "DATA", "DATA#LIMITED"},
		{"descr", "Shaw Tower\nmore", "Shaw Tower # 16-02/03\nmore"},
		{"mnt-by", "MNT-A", "MNT-A"},
	} {
		a, _ := o.GetFirst(c.name)
		if a.Value != c.value || a.ValueWithComments() != c.with {
			t.Errorf("%s: Value %q, ValueWithComments %q; want %q, %q", c.name, a.Value, a.ValueWithComments(), c.value, c.with)
		}
	}

	// A value written by Append or the Builder cannot hold '#'.
	if err := o.Append("remarks", "line one\nline two"); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder("route", "192.0.2.0/24").Add("descr", "built").Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range append(o.GetAll("remarks"), b.GetAll("descr")...) {
		if a.ValueWithComments() != a.Value {
			t.Errorf("%s: ValueWithComments %q, Value %q", a.Name, a.ValueWithComments(), a.Value)
		}
	}
	if (Attribute{}).ValueWithComments() != "" {
		t.Error("zero Attribute: want an empty value")
	}
}

// Most attributes hold no '#': for them it is Value, at no cost.
func TestAttributeValueWithCommentsNoAlloc(t *testing.T) {
	a, _ := parse("descr: first\n second\n").GetFirst("descr")
	if n := testing.AllocsPerRun(100, func() { _ = a.ValueWithComments() }); n != 0 {
		t.Errorf("%v allocations, want 0", n)
	}
}
