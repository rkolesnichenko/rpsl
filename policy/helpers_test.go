package policy

import "github.com/rkolesnichenko/rpsl/ast"

// The table tests name a parse function per row; these are the option sets
// they use, as functions.

func mpImport(s string) (Import, []ast.Diagnostic)   { return ParseImportWith(s, Options{MP: true}) }
func mpExport(s string) (Export, []ast.Diagnostic)   { return ParseExportWith(s, Options{MP: true}) }
func mpDefault(s string) (Default, []ast.Diagnostic) { return ParseDefaultWith(s, Options{MP: true}) }
func viaImport(s string) (Import, []ast.Diagnostic)  { return ParseImportWith(s, Options{Via: true}) }
func viaExport(s string) (Export, []ast.Diagnostic)  { return ParseExportWith(s, Options{Via: true}) }

// policyInputs is every policy value the grammar tables and FuzzParseImport's
// seeds hold, for properties that must hold of all of them.
func policyInputs() []string {
	var out []string
	for _, c := range grammarCases {
		out = append(out, c.in)
	}
	return append(out, importSeeds...)
}
