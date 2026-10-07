package policy

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// TestOptionsMPAndVia: MP marks a policy multiprotocol; Via reads the via
// grammar and implies MP, set or not.
func TestOptionsMPAndVia(t *testing.T) {
	const via = "AS6777 from AS15562 action pref = 2; accept AS-SNIJDERS"
	for _, o := range []Options{{Via: true}, {Via: true, MP: true}} {
		imp, ds := ParseImportWith(via, o)
		if len(ds) != 0 || !imp.MP {
			t.Errorf("ParseImportWith(%q, %+v): MP=%v %v; want MP, clean", via, o, imp.MP, ds)
		}
	}
	if imp, ds := ParseImportWith("from AS1 accept ANY", Options{MP: true}); len(ds) != 0 || !imp.MP {
		t.Errorf("MP import: MP=%v %v", imp.MP, ds)
	}
	if imp, _ := ParseImport("from AS1 accept ANY"); imp.MP {
		t.Error("plain import is MP")
	}
	if exp, ds := ParseExportWith("AS6777 195.69.144.255 to AS-AMS-IX-RS announce AS-SNIJDERS", Options{Via: true}); len(ds) != 0 || !exp.MP {
		t.Errorf("via export: MP=%v %v", exp.MP, ds)
	}
}

// TestDefaultHasNoVia: RFC 2622 has no default-via:. With Via, the value is
// read as mp-default: and one Error spanning the whole value comes first.
func TestDefaultHasNoVia(t *testing.T) {
	const s = "to AS1 action pref = 10; networks ANY"
	got, ds := ParseDefaultWith(s, Options{Via: true})
	want, wantDs := ParseDefaultWith(s, Options{MP: true})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Via default = %+v, want the MP parse %+v", got, want)
	}
	if len(ds) != len(wantDs)+1 {
		t.Fatalf("diagnostics %v, want one more than %v", ds, wantDs)
	}
	d := ds[0]
	if d.Rule != "policy/no-default-via" || d.Severity != ast.Error ||
		d.Span.StartByte != 0 || d.Span.EndByte != len(s) {
		t.Errorf("first diagnostic %+v, want an Error policy/no-default-via over bytes 0..%d", d, len(s))
	}
}

// TestPlainEqualsZeroOptions: X(s) is XWith(s, Options{}) for every input of
// the grammar tables and FuzzParseImport's seeds (the root testdata/ holds
// only 8 policy lines, too few to stand alone).
func TestPlainEqualsZeroOptions(t *testing.T) {
	for _, s := range policyInputs() {
		i1, d1 := ParseImport(s)
		i2, d2 := ParseImportWith(s, Options{})
		e1, f1 := ParseExport(s)
		e2, f2 := ParseExportWith(s, Options{})
		g1, h1 := ParseDefault(s)
		g2, h2 := ParseDefaultWith(s, Options{})
		if !reflect.DeepEqual(i1, i2) || !reflect.DeepEqual(d1, d2) ||
			!reflect.DeepEqual(e1, e2) || !reflect.DeepEqual(f1, f2) ||
			!reflect.DeepEqual(g1, g2) || !reflect.DeepEqual(h1, h2) {
			t.Errorf("%q: the plain parse differs from the zero-options parse", s)
		}
	}
}
