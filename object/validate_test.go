package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// ruleSet collects the diagnostic rules present, for order-independent assertions.
func ruleSet(diags []ast.Diagnostic) map[string]bool {
	out := map[string]bool{}
	for _, d := range diags {
		out[d.Rule] = true
	}
	return out
}

func TestValidateCleanObject(t *testing.T) {
	o := parse(`route:   192.0.2.0/24
origin:  AS65000
mnt-by:  MAINT-EX
source:  RIPE
`)
	if d := RFCStrict.Validate(o); len(d) != 0 {
		t.Errorf("RFCStrict.Validate clean route = %+v, want none", d)
	}
	if d := RIPE.Validate(o); len(d) != 0 {
		t.Errorf("RIPE.Validate clean route = %+v, want none", d)
	}
}

func TestValidateUnknownAttr(t *testing.T) {
	// changed: is a legacy RIPE attribute: RFC-strict flags it, RIPE tolerates it.
	o := parse(`route:   192.0.2.0/24
origin:  AS65000
changed: ex@example.net 20200101
mnt-by:  MAINT-EX
source:  RIPE
`)
	strict := RFCStrict.Validate(o)
	if !ruleSet(strict)["dict/unknown-attr"] {
		t.Errorf("RFCStrict missed changed:, diags = %+v", strict)
	}
	if ripe := RIPE.Validate(o); len(ripe) != 0 {
		t.Errorf("RIPE flagged changed:, diags = %+v", ripe)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	o := parse(`route:  192.0.2.0/24
origin: AS65000
mnt-by: MAINT-EX
`) // no source:
	d := RFCStrict.Validate(o)
	if !ruleSet(d)["dict/missing-required"] {
		t.Errorf("missing source: not reported, diags = %+v", d)
	}
}

func TestValidateCardinality(t *testing.T) {
	o := parse(`route:  192.0.2.0/24
origin: AS65000
origin: AS65001
mnt-by: MAINT-EX
source: RIPE
`) // origin is single-valued
	d := RFCStrict.Validate(o)
	if !ruleSet(d)["dict/cardinality"] {
		t.Errorf("duplicate origin: not reported, diags = %+v", d)
	}
}

func TestValidateUnknownClass(t *testing.T) {
	o := parse("frobnicate: whatever\nsource: RIPE\n")
	d := RIPE.Validate(o)
	if len(d) != 1 || d[0].Rule != "dict/unknown-class" {
		t.Errorf("unknown class diags = %+v, want one dict/unknown-class", d)
	}
}
