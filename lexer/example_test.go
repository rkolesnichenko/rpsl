package lexer_test

import (
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// ExampleTokenize shows the total-partition invariant: concatenating every
// token's Raw reproduces the source byte-for-byte, and a folded attribute
// already carries its comment-stripped logical Value.
func ExampleTokenize() {
	src := "as-set:  AS-EXAMPLE\n" +
		"members: AS1, AS2  # two members\n" +
		"source:  TEST\n"

	toks := lexer.Tokenize(src)

	var rebuilt strings.Builder
	for _, t := range toks {
		rebuilt.WriteString(t.Raw)
	}

	members := toks[1]
	fmt.Printf("name=%q value=%q\n", members.Name, members.Value)
	fmt.Println("lossless:", rebuilt.String() == src)
	// Output:
	// name="members" value="AS1, AS2"
	// lossless: true
}
