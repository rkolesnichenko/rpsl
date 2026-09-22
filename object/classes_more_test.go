package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

func TestDecodeKeyCert(t *testing.T) {
	o := parse(`key-cert:       PGPKEY-1234ABCD
method:         PGP
owner:          Example Person <ex@example.net>
fingerpr:       AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89
certif:         -----BEGIN PGP PUBLIC KEY BLOCK-----
certif:
certif:         mQENBF1234567890
certif:         -----END PGP PUBLIC KEY BLOCK-----
mnt-by:         EXAMPLE-MNT
source:         RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	k, ok := obj.(KeyCert)
	if !ok {
		t.Fatalf("Decode = %T, want KeyCert", obj)
	}
	if k.Name != "PGPKEY-1234ABCD" || k.Method != "PGP" {
		t.Errorf("Name/Method = %q/%q", k.Name, k.Method)
	}
	if len(k.Owner) != 1 || k.Owner[0] != "Example Person <ex@example.net>" {
		t.Errorf("Owner = %q", k.Owner)
	}
	if k.Fingerpr != "AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89" {
		t.Errorf("Fingerpr = %q", k.Fingerpr)
	}
	// The armour is kept verbatim, one entry per attribute, blank line included.
	if len(k.Certif) != 4 || k.Certif[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" {
		t.Fatalf("Certif = %q", k.Certif)
	}
	if k.Certif[1] != "" {
		t.Errorf("Certif[1] = %q, want the empty line kept", k.Certif[1])
	}
	if k.Certif[3] != "-----END PGP PUBLIC KEY BLOCK-----" {
		t.Errorf("Certif[3] = %q", k.Certif[3])
	}
	if k.Class() != "key-cert" || k.Raw() != o {
		t.Errorf("Class/Raw = %q/%p", k.Class(), k.Raw())
	}
}

func TestDecodeDictionary(t *testing.T) {
	o := parse(`dictionary:     RPSL
rp-attribute:   pref operator=(integer[0, 65535])
rp-attribute:   aspath prepend(list of as_number)
typedef:        as_number integer[1, 4294967295]
protocol:       BGP4 MANDATORY asno(as_number) OPTIONAL flap_damp()
protocol:       OSPF
descr:          the standard dictionary
tech-c:         EX1-RIPE
mnt-by:         EXAMPLE-MNT
changed:        ex@example.net 20200101
source:         RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	d, ok := obj.(Dictionary)
	if !ok {
		t.Fatalf("Decode = %T, want Dictionary", obj)
	}
	if d.Name != "RPSL" {
		t.Errorf("Name = %q", d.Name)
	}
	if len(d.RPAttribute) != 2 || d.RPAttribute[0].Name != "pref" || d.RPAttribute[1].Name != "aspath" {
		t.Fatalf("RPAttribute = %+v", d.RPAttribute)
	}
	if len(d.Typedef) != 1 || d.Typedef[0].Name != "as_number" {
		t.Errorf("Typedef = %+v", d.Typedef)
	}
	if len(d.Protocol) != 2 || d.Protocol[0].Name != "bgp4" || d.Protocol[1].Name != "ospf" {
		t.Errorf("Protocol = %+v", d.Protocol)
	}
	// Dict hands the declarations to the policy layer ready to check against.
	pd := d.Dict()
	if _, ok := pd.Attr("pref"); !ok {
		t.Error("Dict() lost the pref attribute")
	}
	if _, ok := pd.Protocol("OSPF"); !ok {
		t.Error("Dict() lost the OSPF protocol")
	}
}

// A malformed declaration is diagnosed against its own attribute's span, not
// the whole object, and the rest of the dictionary still decodes.
func TestDecodeDictionaryDiagnostics(t *testing.T) {
	src := `dictionary:     RPSL
rp-attribute:   pref operator=(integer)
rp-attribute:   broken
descr:          d
tech-c:         EX1-RIPE
mnt-by:         M
changed:        e@e.net 20200101
source:         RIPE
`
	o := parse(src)
	obj, diags := Decode(o)
	if len(diags) != 1 || diags[0].Rule != "policy/rp-attribute" {
		t.Fatalf("diags = %+v, want one policy/rp-attribute", diags)
	}
	if got := diags[0].Span.StartLine; got != 3 {
		t.Errorf("diagnostic on line %d, want 3", got)
	}
	if d := obj.(Dictionary); len(d.RPAttribute) != 2 || d.RPAttribute[0].Name != "pref" {
		t.Errorf("the good declaration was lost: %+v", d.RPAttribute)
	}
}

func TestDecodePoemAndPoeticForm(t *testing.T) {
	o := parse(`poem:           POEM-EXAMPLE
form:           FORM-HAIKU
text:           a registry hums
text:           objects in ordered silence
text:           the round trip returns
author:         EX1-RIPE
mnt-by:         EXAMPLE-MNT
source:         RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	p, ok := obj.(Poem)
	if !ok {
		t.Fatalf("Decode = %T, want Poem", obj)
	}
	if p.Name != "POEM-EXAMPLE" || p.Form != "FORM-HAIKU" {
		t.Errorf("Name/Form = %q/%q", p.Name, p.Form)
	}
	if len(p.Text) != 3 || p.Text[0] != "a registry hums" {
		t.Errorf("Text = %q", p.Text)
	}
	if len(p.Author) != 1 || p.Author[0].String() != "EX1-RIPE" {
		t.Errorf("Author = %v", p.Author)
	}

	o = parse("poetic-form:    FORM-HAIKU\nadmin-c:        EX1-RIPE\nmnt-by:         M\nsource:         RIPE\n")
	obj, diags = Decode(o)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	f, ok := obj.(PoeticForm)
	if !ok {
		t.Fatalf("Decode = %T, want PoeticForm", obj)
	}
	if f.Name != "FORM-HAIKU" || f.Class() != "poetic-form" {
		t.Errorf("Name/Class = %q/%q", f.Name, f.Class())
	}
}

// A bad author handle is an Error on that attribute and nothing else.
func TestDecodePoemBadAuthor(t *testing.T) {
	o := parse("poem: POEM-X\nform: FORM-X\ntext: t\nauthor: not a handle!\nmnt-by: M\nsource: RIPE\n")
	obj, diags := Decode(o)
	if len(diags) != 1 || diags[0].Severity != ast.Error || diags[0].Rule != "object/poem-author" {
		t.Fatalf("diags = %+v, want one object/poem-author error", diags)
	}
	if p := obj.(Poem); len(p.Author) != 0 || p.Name != "POEM-X" {
		t.Errorf("Poem = %+v", p)
	}
}
