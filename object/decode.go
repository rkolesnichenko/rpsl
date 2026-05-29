package object

import "github.com/rkolesnichenko/rpsl/ast"

// registry maps a class name to its typed decoder. A class absent here decodes
// to Generic with no diagnostics.
var registry = map[string]func(*decoder) Object{
	"mntner":    func(d *decoder) Object { return decodeMntner(d) },
	"person":    func(d *decoder) Object { return decodePerson(d) },
	"role":      func(d *decoder) Object { return decodeRole(d) },
	"route":     func(d *decoder) Object { return decodeRoute(d) },
	"route6":    func(d *decoder) Object { return decodeRoute6(d) },
	"as-set":    func(d *decoder) Object { return decodeAsSet(d) },
	"route-set": func(d *decoder) Object { return decodeRouteSet(d) },
}

// Decode upgrades a generic ast.Object to its typed form via the class registry,
// returning best-effort diagnostics. Unknown classes degrade to Generic with no
// diagnostics. The returned object's Raw() is always byte-exact with the source.
func Decode(o *ast.Object) (Object, []ast.Diagnostic) {
	fn, ok := registry[o.Class()]
	if !ok {
		return Generic{raw: o}, nil
	}
	d := newDecoder(o)
	return fn(d), d.diags
}
