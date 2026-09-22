package object

import (
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// The classes that carry no routing policy of their own: the key-cert of
// RFC 2726, the RP-attribute dictionary of RFC 2622 §9, and RIPE's poem and
// poetic-form.

// KeyCert is a key-cert object (RFC 2726): a public key or certificate a
// mntner's auth: line refers to.
//
// Certif keeps the armoured certificate exactly as written, one entry per
// certif: attribute. The certificate is not decoded and no signature is ever
// verified: that needs a cryptography library, and this module has no
// dependencies. A consumer that wants to verify supplies its own verifier.
type KeyCert struct {
	Common
	Registry
	Name     string   // the key-cert: handle, e.g. "PGPKEY-1234ABCD" or "X509-1"
	Method   string   // "PGP" or "X509", as written
	Owner    []string // the key's owners, as the registry renders them
	Fingerpr string   // the key fingerprint, as written
	Certif   []string // the armoured certificate, verbatim
	raw      *ast.Object
}

// Class returns "key-cert".
func (k KeyCert) Class() string { return "key-cert" }

// Raw returns the generic object the key-cert was decoded from.
func (k KeyCert) Raw() *ast.Object { return k.raw }

func decodeKeyCert(d *decoder) KeyCert {
	return KeyCert{
		Common:   d.common("key-cert"),
		Registry: d.registry("key-cert"),
		Name:     d.key("key-cert"),
		Method:   d.str("method"),
		Owner:    d.all("owner"),
		Fingerpr: d.str("fingerpr"),
		Certif:   d.all("certif"),
		raw:      d.o,
	}
}

// Dictionary is a dictionary object (RFC 2622 §9): the RP-attributes an action
// may set, the types they take, and the routing protocols a peering may name.
// Build a policy.Dictionary from it with Dict to check policies against it.
type Dictionary struct {
	Common
	Registry
	Name        string
	RPAttribute []policy.RPAttr
	Typedef     []policy.Typedef
	Protocol    []policy.Protocol
	raw         *ast.Object
}

// Class returns "dictionary".
func (d Dictionary) Class() string { return "dictionary" }

// Raw returns the generic object the dictionary was decoded from.
func (d Dictionary) Raw() *ast.Object { return d.raw }

// Dict returns the object's declarations as a policy.Dictionary, ready to pass
// as policy.Options.Dict.
func (d Dictionary) Dict() policy.Dictionary {
	return policy.NewDictionary(d.RPAttribute, d.Typedef, d.Protocol)
}

func decodeDictionary(d *decoder) Dictionary {
	dict := Dictionary{
		Common:   d.common("dictionary"),
		Registry: d.registry("dictionary"),
		Name:     d.key("dictionary"),
		raw:      d.o,
	}
	for _, a := range d.o.Attributes() {
		switch a.Name {
		case "rp-attribute":
			v, ds := policy.ParseRPAttribute(a.Value)
			dict.RPAttribute = append(dict.RPAttribute, v)
			d.rebase(a, ds)
		case "typedef":
			v, ds := policy.ParseTypedef(a.Value)
			dict.Typedef = append(dict.Typedef, v)
			d.rebase(a, ds)
		case "protocol":
			v, ds := policy.ParseProtocol(a.Value)
			dict.Protocol = append(dict.Protocol, v)
			d.rebase(a, ds)
		}
	}
	return dict
}

// Poem is a poem object: RIPE's tradition of storing verse in the registry.
// Form names the poetic-form it follows.
type Poem struct {
	Common
	Registry
	Name   string
	Form   string            // the poetic-form: object this poem follows
	Text   []string          // the verse, one entry per text: attribute
	Author []types.NICHandle // the authors' NIC handles
	raw    *ast.Object
}

// Class returns "poem".
func (p Poem) Class() string { return "poem" }

// Raw returns the generic object the poem was decoded from.
func (p Poem) Raw() *ast.Object { return p.raw }

func decodePoem(d *decoder) Poem {
	return Poem{
		Common:   d.common("poem"),
		Registry: d.registry("poem"),
		Name:     d.key("poem"),
		Form:     d.str("form"),
		Text:     d.all("text"),
		Author:   d.nicHandles("author", "object/poem-author"),
		raw:      d.o,
	}
}

// PoeticForm is a poetic-form object: the form a poem: may declare. RIPE's
// template gives it no text of its own; the form is described in remarks.
type PoeticForm struct {
	Common
	Registry
	Name string
	raw  *ast.Object
}

// Class returns "poetic-form".
func (p PoeticForm) Class() string { return "poetic-form" }

// Raw returns the generic object the poetic-form was decoded from.
func (p PoeticForm) Raw() *ast.Object { return p.raw }

func decodePoeticForm(d *decoder) PoeticForm {
	return PoeticForm{
		Common:   d.common("poetic-form"),
		Registry: d.registry("poetic-form"),
		Name:     d.key("poetic-form"),
		raw:      d.o,
	}
}
