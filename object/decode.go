package object

import "github.com/rkolesnichenko/rpsl/ast"

// registry maps a class name to its typed decoder. A class absent here decodes
// to Generic with no diagnostics.
var registry = map[string]func(*decoder) Object{
	"aut-num":      func(d *decoder) Object { v := decodeAutNum(d); return &v },
	"mntner":       func(d *decoder) Object { v := decodeMntner(d); return &v },
	"person":       func(d *decoder) Object { v := decodePerson(d); return &v },
	"role":         func(d *decoder) Object { v := decodeRole(d); return &v },
	"route":        func(d *decoder) Object { v := decodeRoute(d); return &v },
	"route6":       func(d *decoder) Object { v := decodeRoute6(d); return &v },
	"as-set":       func(d *decoder) Object { v := decodeAsSet(d); return &v },
	"route-set":    func(d *decoder) Object { v := decodeRouteSet(d); return &v },
	"peering-set":  func(d *decoder) Object { v := decodePeeringSet(d); return &v },
	"filter-set":   func(d *decoder) Object { v := decodeFilterSet(d); return &v },
	"rtr-set":      func(d *decoder) Object { v := decodeRtrSet(d); return &v },
	"inetnum":      func(d *decoder) Object { v := decodeInetnum(d); return &v },
	"inet6num":     func(d *decoder) Object { v := decodeInet6num(d); return &v },
	"as-block":     func(d *decoder) Object { v := decodeAsBlock(d); return &v },
	"inet-rtr":     func(d *decoder) Object { v := decodeInetRtr(d); return &v },
	"irt":          func(d *decoder) Object { v := decodeIrt(d); return &v },
	"domain":       func(d *decoder) Object { v := decodeDomain(d); return &v },
	"organisation": func(d *decoder) Object { v := decodeOrganisation(d); return &v },
	"key-cert":     func(d *decoder) Object { v := decodeKeyCert(d); return &v },
	"dictionary":   func(d *decoder) Object { v := decodeDictionary(d); return &v },
	"poem":         func(d *decoder) Object { v := decodePoem(d); return &v },
	"poetic-form":  func(d *decoder) Object { v := decodePoeticForm(d); return &v },
}

// Decode upgrades a generic ast.Object to its typed form via the class registry,
// returning best-effort diagnostics. Unknown classes degrade to Generic with no
// diagnostics. The returned object's Raw() is always byte-exact with the source.
func Decode(o *ast.Object) (Object, []ast.Diagnostic) {
	fn, ok := registry[o.Class()]
	if !ok {
		return &Generic{raw: o}, nil
	}
	d := newDecoder(o)
	return fn(d), d.diags
}
