package object

import "testing"

// import-via: and export-via: decode into policies of their own, apart from
// Imports and Exports, and their diagnostics point at their own lines.
func TestAutNumVia(t *testing.T) {
	o := parse("aut-num:    AS15562\n" +
		"import:     from AS1 accept ANY\n" +
		"import-via: AS6777\n" +
		"            from AS15562\n" +
		"            action pref = 2;\n" +
		"            accept AS-SNIJDERS\n" +
		"export-via: AS6777 to AS15562 announce AS-SNIJDERS\n" +
		"import-via: from AS1 accept ANY\n" +
		"source:     RIPE\n")
	obj, diags := Decode(o)
	a, ok := obj.(AutNum)
	if !ok {
		t.Fatalf("decoded %T, want AutNum", obj)
	}
	if len(a.Imports) != 1 || len(a.Exports) != 0 {
		t.Errorf("Imports %d, Exports %d: via policies must not join them", len(a.Imports), len(a.Exports))
	}
	if len(a.ImportVia) != 2 || len(a.ExportVia) != 1 {
		t.Fatalf("ImportVia %d, ExportVia %d, want 2 and 1", len(a.ImportVia), len(a.ExportVia))
	}
	if got := a.ImportVia[0].String(); got != "AS6777 from AS15562 action pref = 2; accept AS-SNIJDERS" {
		t.Errorf("ImportVia[0] = %q", got)
	}
	if got := a.ExportVia[0].String(); got != "AS6777 to AS15562 announce AS-SNIJDERS" {
		t.Errorf("ExportVia[0] = %q", got)
	}
	if !a.ImportVia[0].MP || !a.ExportVia[0].MP {
		t.Error("via policies are RFC 4012 syntax, so MP must be set")
	}
	if len(diags) != 1 || diags[0].Rule != "policy/via" || diags[0].Span.StartLine != 8 {
		t.Fatalf("diagnostics %+v, want one policy/via on line 8", diags)
	}
}
