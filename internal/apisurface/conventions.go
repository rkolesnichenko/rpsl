package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"unicode"
)

// conventions checks the API conventions (CLAUDE.md, "Go conventions") over
// pkgs and returns each violation as "file:line: Cn: message", file relative
// to root, in declaration order.
func conventions(root string, pkgs []*pkg) []string {
	var out []string
	for _, p := range pkgs {
		report := func(pos token.Pos, msg string) {
			at := p.fset.Position(pos)
			name, err := filepath.Rel(root, at.Filename)
			if err != nil {
				name = at.Filename
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(name), at.Line, msg))
		}
		for _, f := range p.files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					checkParseBool(d, report)
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						checkSentinels(d, report)
					}
				}
			}
		}
	}
	return out
}

// checkParseBool is C2: no exported Parse function or method returns bool as
// its last result. Malformed input is an error; comma-ok is for an expected
// false, such as a lookup miss or an empty result.
func checkParseBool(d *ast.FuncDecl, report func(token.Pos, string)) {
	if !d.Name.IsExported() || !strings.HasPrefix(d.Name.Name, "Parse") || d.Type.Results == nil {
		return
	}
	rs := d.Type.Results.List
	if id, ok := rs[len(rs)-1].Type.(*ast.Ident); ok && id.Name == "bool" {
		report(d.Pos(), "C2: "+d.Name.Name+" returns bool as its last result; malformed input is an error")
	}
}

// checkSentinels is C3: every exported ErrX var is declared with errors.New.
func checkSentinels(d *ast.GenDecl, report func(token.Pos, string)) {
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if !n.IsExported() || !isSentinelName(n.Name) {
				continue
			}
			if i < len(vs.Values) && isErrorsNew(vs.Values[i]) {
				continue
			}
			report(n.Pos(), "C3: "+n.Name+" is not declared with errors.New")
		}
	}
}

// isSentinelName reports whether name reads as a sentinel error: "Err" and a
// capital (ErrNotFound, not Errors).
func isSentinelName(name string) bool {
	return len(name) > 3 && strings.HasPrefix(name, "Err") && unicode.IsUpper(rune(name[3]))
}

// isErrorsNew reports whether e is a call of errors.New.
func isErrorsNew(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}
