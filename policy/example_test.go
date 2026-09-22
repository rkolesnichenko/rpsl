package policy_test

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/policy"
)

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

// ExampleParseFilter parses a filter-set's filter. "x y" is "x OR y", AND binds
// tighter than OR, and a {…}^op prefix list has the operator composed into each
// range.
func ExampleParseFilter() {
	f, diags := policy.ParseFilter("AS-FOO AS65001 AND NOT {192.0.2.0/24}^25")
	fmt.Println("diagnostics:", len(diags))

	or := f.(policy.FilterOr)
	fmt.Printf("%d alternatives\n", len(or.Terms))
	and := or.Terms[1].(policy.FilterAnd)
	not := and.Terms[1].(policy.FilterNot)
	fmt.Println("excluded:", not.Inner.(policy.FilterPrefixList).Ranges)
	// Output:
	// diagnostics: 0
	// 2 alternatives
	// excluded: [192.0.2.0/24^25]
}
