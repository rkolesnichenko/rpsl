package rpsl_test

import (
	"fmt"
	"strings"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
)

// ExampleParseObject parses a single object losslessly: String reproduces the
// input byte-for-byte, so the library is safe for editing objects, not just
// reading them.
func ExampleParseObject() {
	src := "aut-num:        AS65001\n" +
		"as-name:        EXAMPLE-AS\n" +
		"import:         from AS65002 accept ANY\n" +
		"mnt-by:         EXAMPLE-MNT\n" +
		"source:         RIPE\n"

	obj, diags := rpsl.ParseObject(src)

	fmt.Println("class:", obj.Class())
	fmt.Println("key:", obj.Key())
	fmt.Println("roundtrip:", obj.String() == src)
	fmt.Println("diagnostics:", len(diags))
	// Output:
	// class: aut-num
	// key: AS65001
	// roundtrip: true
	// diagnostics: 0
}

// ExampleParse streams a blank-line-separated dump one object at a time, holding
// only the current object in memory (suitable for multi-gigabyte IRR dumps).
func ExampleParse() {
	dump := "person:  Jane Doe\n" +
		"nic-hdl: JD1-RIPE\n" +
		"source:  RIPE\n" +
		"\n" +
		"mntner:  EXAMPLE-MNT\n" +
		"source:  RIPE\n"

	for obj, _ := range rpsl.Parse(strings.NewReader(dump)) {
		fmt.Printf("%s %s\n", obj.Class(), obj.Key())
	}
	// Output:
	// person Jane Doe
	// mntner EXAMPLE-MNT
}

// ExampleDecode upgrades a generic object to its typed form. Decoding is fallible
// per attribute, so a malformed line yields a diagnostic rather than aborting.
func ExampleDecode() {
	src := "aut-num: AS65001\n" +
		"as-name: EXAMPLE-AS\n" +
		"import:  from AS65002 accept ANY\n" +
		"mnt-by:  EXAMPLE-MNT\n" +
		"source:  RIPE\n"

	obj, _ := rpsl.ParseObject(src)
	decoded, diags := object.Decode(obj)

	an := decoded.(object.AutNum)
	fmt.Println("as:", an.AS)
	fmt.Println("as-name:", an.AsName)
	fmt.Println("imports:", len(an.Imports))
	fmt.Println("mnt-by:", an.MntBy)
	fmt.Println("diagnostics:", len(diags))
	// Output:
	// as: AS65001
	// as-name: EXAMPLE-AS
	// imports: 1
	// mnt-by: [EXAMPLE-MNT]
	// diagnostics: 0
}

// ExampleValidate checks an object against a dictionary profile. The RFC-strict
// profile flags RIPE's legacy changed: attribute; the RIPE profile tolerates it.
func ExampleValidate() {
	src := "route:   192.0.2.0/24\n" +
		"origin:  AS65000\n" +
		"changed: ops@example.net 20200101\n" +
		"mnt-by:  EXAMPLE-MNT\n" +
		"source:  RIPE\n"

	obj, _ := rpsl.ParseObject(src)

	// Decode and Validate are both reachable from the top-level façade.
	decoded, _ := rpsl.Decode(obj)
	fmt.Println("class:", decoded.Class())
	fmt.Println("ripe diagnostics:", len(rpsl.Validate(obj, rpsl.RIPE)))
	fmt.Println("rfc-strict diagnostics:", len(rpsl.Validate(obj, rpsl.RFCStrict)))
	// Output:
	// class: route
	// ripe diagnostics: 0
	// rfc-strict diagnostics: 1
}

// ExampleParseImport parses an import: policy value into the AST and walks it via
// the sealed-interface type switches that model the grammar's sum types.
func ExampleParseImport() {
	imp, diags := policy.ParseImport("from AS65002 accept AS65002")
	if len(diags) != 0 {
		fmt.Println("unexpected diagnostics:", len(diags))
	}

	factor := imp.Expr.(policy.Factor)

	if p, ok := factor.Peers[0].Peering.(policy.PeeringAS); ok {
		if as, ok := p.AS.(policy.ASNum); ok {
			fmt.Println("peer:", as.AS)
		}
	}
	if f, ok := factor.Filter.(policy.FilterASExpr); ok {
		if as, ok := f.AS.(policy.ASNum); ok {
			fmt.Println("accept:", as.AS)
		}
	}
	// Output:
	// peer: AS65002
	// accept: AS65002
}
