package object

import "github.com/rkolesnichenko/rpsl/ast"

// registry maps a class name to its typed decoder. A class absent here decodes
// to Generic with no diagnostics.
var registry = map[string]func(*decoder) Object{
	"aut-num":      func(d *decoder) Object { return decodeAutNum(d) },
	"mntner":       func(d *decoder) Object { return decodeMntner(d) },
	"person":       func(d *decoder) Object { return decodePerson(d) },
	"role":         func(d *decoder) Object { return decodeRole(d) },
	"route":        func(d *decoder) Object { return decodeRoute(d) },
	"route6":       func(d *decoder) Object { return decodeRoute6(d) },
	"as-set":       func(d *decoder) Object { return decodeAsSet(d) },
	"route-set":    func(d *decoder) Object { return decodeRouteSet(d) },
	"peering-set":  func(d *decoder) Object { return decodePeeringSet(d) },
	"filter-set":   func(d *decoder) Object { return decodeFilterSet(d) },
	"rtr-set":      func(d *decoder) Object { return decodeRtrSet(d) },
	"inetnum":      func(d *decoder) Object { return decodeInetnum(d) },
	"inet6num":     func(d *decoder) Object { return decodeInet6num(d) },
	"as-block":     func(d *decoder) Object { return decodeAsBlock(d) },
	"inet-rtr":     func(d *decoder) Object { return decodeInetRtr(d) },
	"irt":          func(d *decoder) Object { return decodeIrt(d) },
	"domain":       func(d *decoder) Object { return decodeDomain(d) },
	"organisation": func(d *decoder) Object { return decodeOrganisation(d) },
	"key-cert":     func(d *decoder) Object { return decodeKeyCert(d) },
	"dictionary":   func(d *decoder) Object { return decodeDictionary(d) },
	"poem":         func(d *decoder) Object { return decodePoem(d) },
	"poetic-form":  func(d *decoder) Object { return decodePoeticForm(d) },
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
