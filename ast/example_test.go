package ast_test

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// ExampleObject reads, edits, and re-serializes a generic object. Attributes
// from the source round-trip byte-for-byte; Append adds a new one in canonical
// "name: value" form.
func ExampleObject() {
	src := "person:  Jane Doe\n" +
		"nic-hdl: JD1-RIPE\n" +
		"source:  TEST\n"

	obj := ast.New(lexer.Tokenize(src))

	nh, _ := obj.GetFirst("nic-hdl")
	fmt.Println("class:", obj.Class())
	fmt.Println("nic-hdl:", nh.Value)

	if err := obj.Append("remarks", "added by tool"); err != nil {
		fmt.Println(err) // a name or value RPSL cannot represent
	}
	fmt.Print(obj.String())
	// Output:
	// class: person
	// nic-hdl: JD1-RIPE
	// person:  Jane Doe
	// nic-hdl: JD1-RIPE
	// source:  TEST
	// remarks: added by tool
}
