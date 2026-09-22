package rpsl_test

import (
	"fmt"
	"strings"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
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

// ExampleValidate checks an object against a dictionary profile. This route
// mixes eras: tech-c: and changed: are RFC 2622 attributes the RIPE Database no
// longer has on a route, and created: is one RIPE generates that no RFC
// defines, so each profile flags what the other accepts.
func ExampleValidate() {
	src := "route:   192.0.2.0/24\n" +
		"descr:   Example route\n" +
		"origin:  AS65000\n" +
		"tech-c:  EX1-RIPE\n" +
		"mnt-by:  EXAMPLE-MNT\n" +
		"changed: ops@example.net 20200101\n" +
		"created: 2020-01-01T00:00:00Z\n" +
		"source:  RIPE\n"

	obj, _ := rpsl.ParseObject(src)

	// Decode and Validate are both reachable from the top-level façade.
	decoded, _ := rpsl.Decode(obj)
	fmt.Println("class:", decoded.Class())
	for _, p := range []rpsl.Profile{rpsl.RIPE, rpsl.RFCStrict} {
		for _, d := range rpsl.Validate(obj, p) {
			fmt.Printf("%s: line %d: %s\n", p.Name(), d.Span.StartLine, d.Rule)
		}
	}
	// Output:
	// class: route
	// RIPE: line 4: dict/unknown-attr
	// RIPE: line 6: dict/unknown-attr
	// RFC-strict: line 7: dict/unknown-attr
}
