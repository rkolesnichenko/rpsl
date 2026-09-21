package types_test

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/types"
)

// ExampleParseASN accepts both plain "AS65001" and legacy asdot "AS1.10".
func ExampleParseASN() {
	a, _ := types.ParseASN("AS65001")
	b, _ := types.ParseASN("AS1.10") // asdot: 1*65536 + 10

	fmt.Println(a)         // canonical plain form
	fmt.Println(b)         // asdot is normalized on output
	fmt.Println(uint32(b)) // the numeric value
	// Output:
	// AS65001
	// AS65546
	// 65546
}

// ExamplePrefixRange_Materialize enumerates the concrete prefixes a range
// operator denotes, bounded by a hard cap (passing a too-small cap returns
// ErrTooManyPrefixes instead of allocating).
func ExamplePrefixRange_Materialize() {
	r, _ := types.ParsePrefixRange("192.0.2.0/24^25-26")

	prefixes, err := r.Materialize(100)
	fmt.Println("range:", r)             // round-trips to canonical text
	fmt.Println("count:", len(prefixes)) // two /25s + four /26s
	fmt.Println("err:", err)
	// Output:
	// range: 192.0.2.0/24^25-26
	// count: 6
	// err: <nil>
}
