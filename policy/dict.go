package policy

import (
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
)

// The RP-attribute dictionary of RFC 2622 §9: the open-ended set of route
// attributes an action may assign, the methods each one offers, the type names
// those methods take, and the routing protocols a peering may name.
//
// Parsing keeps the *structure* — which attributes, methods and protocols
// exist, and with what arity — and leaves each type expression as written. The
// type language (union, "list of", ranges, enums) is not interpreted: actions
// round-trip faithfully either way, and interpreting it would buy a consumer
// nothing the raw text does not already give.

// RPMethod is one method of an rp-attribute, as a dictionary declares it:
// "operator=(integer[0, 65535])", "prepend(list of as_number)".
type RPMethod struct {
	Name string // lower-cased: "operator=", "operator.=", "prepend", "append", …
	Args string // the parenthesized signature, as written, without the parentheses
	Raw  string // the method as written
}

// RPAttr is one rp-attribute declaration: a name and the methods it offers.
type RPAttr struct {
	Name    string // lower-cased
	Methods []RPMethod
	Raw     string
}

// Method returns the named method of the attribute; ok is false when the
// attribute does not declare it.
func (a RPAttr) Method(name string) (RPMethod, bool) {
	for _, m := range a.Methods {
		if m.Name == sigName(name) {
			return m, true
		}
	}
	return RPMethod{}, false
}

// Typedef is one typedef: declaration, naming a type expression.
type Typedef struct {
	Name       string // lower-cased
	Definition string // the type expression, as written
	Raw        string
}

// Protocol is one protocol: declaration: a routing protocol and its peering
// options, each MANDATORY or OPTIONAL.
type Protocol struct {
	Name    string // lower-cased
	Options []ProtocolOption
	Raw     string
}

// Option returns the named peering option; ok is false when the protocol does
// not declare it.
func (p Protocol) Option(name string) (ProtocolOption, bool) {
	for _, o := range p.Options {
		if o.Name == sigName(name) {
			return o, true
		}
	}
	return ProtocolOption{}, false
}

// ProtocolOption is one peering option of a protocol: declaration.
type ProtocolOption struct {
	Mandatory bool   // MANDATORY rather than OPTIONAL
	Name      string // lower-cased
	Args      string // the parenthesized signature, as written, without the parentheses
	Raw       string
}

// Dictionary is a set of rp-attribute, typedef and protocol declarations —
// the contents of one dictionary object (RFC 2622 §9). The zero Dictionary is
// empty and knows nothing; pass it nowhere rather than using it to check.
type Dictionary struct {
	attrs     map[string]RPAttr
	typedefs  map[string]Typedef
	protocols map[string]Protocol
}

// NewDictionary builds a Dictionary. Later declarations of a name win, as a
// later attribute line in one object overrides an earlier one.
func NewDictionary(attrs []RPAttr, typedefs []Typedef, protos []Protocol) Dictionary {
	d := Dictionary{
		attrs:     make(map[string]RPAttr, len(attrs)),
		typedefs:  make(map[string]Typedef, len(typedefs)),
		protocols: make(map[string]Protocol, len(protos)),
	}
	for _, a := range attrs {
		d.attrs[normAttr(a.Name)] = a
	}
	for _, t := range typedefs {
		d.typedefs[normAttr(t.Name)] = t
	}
	for _, p := range protos {
		d.protocols[normAttr(p.Name)] = p
	}
	return d
}

// IsZero reports whether d declares nothing.
func (d Dictionary) IsZero() bool {
	return len(d.attrs) == 0 && len(d.typedefs) == 0 && len(d.protocols) == 0
}

// Attr returns the named rp-attribute; ok is false when d does not declare it.
func (d Dictionary) Attr(name string) (RPAttr, bool) {
	a, ok := d.attrs[normAttr(name)]
	return a, ok
}

// Typedef returns the named type; ok is false when d does not declare it.
func (d Dictionary) Typedef(name string) (Typedef, bool) {
	t, ok := d.typedefs[normAttr(name)]
	return t, ok
}

// Protocol returns the named protocol; ok is false when d does not declare it.
func (d Dictionary) Protocol(name string) (Protocol, bool) {
	p, ok := d.protocols[normAttr(name)]
	return p, ok
}

// AttrNames returns the declared rp-attribute names, sorted.
func (d Dictionary) AttrNames() []string { return sortedKeys(d.attrs) }

// ProtocolNames returns the declared protocol names, sorted.
func (d Dictionary) ProtocolNames() []string { return sortedKeys(d.protocols) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MethodName returns the dictionary method name an action invokes: an
// assignment is "operator=", an append "operator.=", and every other form
// names its method directly ("prepend", "operator+=").
func MethodName(a Action) string {
	switch a.Op {
	case ActionAssign:
		return "operator="
	case ActionAppend:
		return "operator.="
	}
	return a.Method
}

// Options configures a policy parse. A nil Dict — the zero Options, and what
// the plain Parse functions use — means actions and protocol names are checked
// for syntax only, as the RP-attribute set is open-ended by design.
type Options struct {
	Dict *Dictionary
}

// ParseImportWith is ParseImport with options; MP selects mp-import: syntax.
func ParseImportWith(s string, mp bool, o Options) (Import, []ast.Diagnostic) {
	p := newParser(s)
	p.mp, p.dict = mp, o.Dict
	imp := Import{MP: mp}
	if p.empty() {
		return imp, p.diags
	}
	imp.Protocol, imp.IntoProtocol = p.parseProtocols()
	imp.AFIs = p.parseAFIs()
	imp.Expr = p.parseExpr("from", "accept")
	p.finish()
	return imp, p.diags
}

// ParseExportWith is ParseExport with options; MP selects mp-export: syntax.
func ParseExportWith(s string, mp bool, o Options) (Export, []ast.Diagnostic) {
	p := newParser(s)
	p.mp, p.dict = mp, o.Dict
	exp := Export{MP: mp}
	if p.empty() {
		return exp, p.diags
	}
	exp.Protocol, exp.IntoProtocol = p.parseProtocols()
	exp.AFIs = p.parseAFIs()
	exp.Expr = p.parseExpr("to", "announce")
	p.finish()
	return exp, p.diags
}

// ParseDefaultWith is ParseDefault with options; MP selects mp-default: syntax.
func ParseDefaultWith(s string, mp bool, o Options) (Default, []ast.Diagnostic) {
	p := newParser(s)
	p.mp, p.dict = mp, o.Dict
	d := Default{MP: mp}
	if p.empty() {
		return d, p.diags
	}
	d.AFIs = p.parseAFIs()
	if !p.cur().kw("to") {
		p.errf(p.cur(), "policy/default-to", "expected 'to' in a default policy")
		return d, p.diags
	}
	p.advance()
	d.Peering = p.parsePeering()
	if p.cur().kw("action") {
		p.advance()
		d.Actions = p.parseActions()
	}
	if p.cur().kw("networks") {
		p.advance()
		d.Networks = p.parseFilter()
	}
	p.finish()
	return d, p.diags
}

// checkAction reports an action that the parser's dictionary does not declare.
// Both diagnostics are warnings: the action is kept and round-trips either way,
// and a registry may legitimately use a dictionary this caller does not have.
func (p *parser) checkAction(a Action, t token) {
	if p.dict == nil {
		return
	}
	attr, ok := p.dict.Attr(a.Attr)
	if !ok {
		p.warnf(t, "policy/rp-attribute",
			quote(a.Attr)+" is not an rp-attribute of the dictionary")
		return
	}
	if m := MethodName(a); m != "" {
		if _, ok := attr.Method(m); !ok {
			p.warnf(t, "policy/rp-method",
				quote(a.Attr)+" has no method "+quote(m)+" in the dictionary")
		}
	}
}

// checkProtocol reports a protocol name the parser's dictionary does not
// declare. A warning, for the same reason as checkAction.
func (p *parser) checkProtocol(name string, t token) {
	if p.dict == nil || name == "" {
		return
	}
	if _, ok := p.dict.Protocol(name); !ok {
		p.warnf(t, "policy/rp-protocol", quote(name)+" is not a protocol of the dictionary")
	}
}

// ParseRPAttribute parses an rp-attribute: value of a dictionary object.
func ParseRPAttribute(s string) (RPAttr, []ast.Diagnostic) {
	a, p := parseRPAttributeValue(s)
	return a, p.diags
}

func parseRPAttributeValue(s string) (RPAttr, *parser) {
	p := newParser(s)
	a := RPAttr{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return a, p
	}
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/rp-attribute", "expected an rp-attribute name")
		return a, p
	}
	a.Name = normAttr(t.text)
	p.advance()
	a.Methods = p.parseSignatures("policy/rp-attribute")
	if len(a.Methods) == 0 && len(p.diags) == 0 {
		// An attribute with no method declares something no action can set.
		p.errf(t, "policy/rp-attribute", "rp-attribute "+quote(t.text)+" declares no method")
	}
	p.finish()
	return a, p
}

// parseSignatures reads a comma- or whitespace-separated list of "name(args)"
// signatures, the shape both rp-attribute: and protocol: use. A method name may
// carry an operator spelling ("operator=", "operator.=", "operator<<="), which
// the tokenizer splits apart, so the name is read from the source up to the '('.
func (p *parser) parseSignatures(rule string) []RPMethod {
	var out []RPMethod
	for !p.atEOF() && p.cur().kind != tSemi {
		t := p.cur()
		if t.kind == tComma {
			p.advance()
			continue
		}
		if p.isStop(t) {
			return out // the next MANDATORY/OPTIONAL group
		}
		if t.kind != tWord {
			p.errf(t, rule, "expected a method name")
			return out
		}
		start := t.start
		for !p.atEOF() && p.cur().kind != tLParen && p.cur().kind != tComma &&
			p.cur().kind != tSemi && !p.isStop(p.cur()) {
			p.advance()
		}
		name := sigName(p.src[start:p.cur().start])
		if p.cur().kind != tLParen {
			p.errf(t, rule, "expected '(' after method "+quote(name))
			return out
		}
		args, end, ok := p.signatureArgs()
		if !ok {
			p.errf(t, rule, "unterminated '(' in method "+quote(name))
			return out
		}
		out = append(out, RPMethod{Name: name, Args: args, Raw: strings.TrimSpace(p.src[start:end])})
	}
	return out
}

// sigName canonicalizes a method name: lower-cased with all whitespace removed,
// so "operator =" and "operator=" are one name.
func sigName(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

// signatureArgs consumes a parenthesized signature at the cursor and returns
// its text plus the source offset just past the ')'.
func (p *parser) signatureArgs() (args string, end int, ok bool) {
	depth, start := 0, p.cur().end
	for !p.atEOF() {
		switch p.cur().kind {
		case tLParen:
			depth++
		case tRParen:
			depth--
			if depth == 0 {
				inner, after := p.cur().start, p.cur().end
				p.advance()
				return strings.TrimSpace(p.src[start:inner]), after, true
			}
		}
		p.advance()
	}
	return "", 0, false
}

// ParseTypedef parses a typedef: value of a dictionary object.
func ParseTypedef(s string) (Typedef, []ast.Diagnostic) {
	td, p := parseTypedefValue(s)
	return td, p.diags
}

func parseTypedefValue(s string) (Typedef, *parser) {
	p := newParser(s)
	td := Typedef{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return td, p
	}
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/typedef", "expected a type name")
		return td, p
	}
	td.Name = normAttr(t.text)
	p.advance()
	if p.atEOF() {
		p.errf(t, "policy/typedef", "expected a type definition after "+quote(t.text))
		return td, p
	}
	// The type language is kept as written; consume the rest of the value.
	start := p.cur().start
	end := start
	for !p.atEOF() {
		end = p.cur().end
		p.advance()
	}
	td.Definition = strings.TrimSpace(p.src[start:end])
	return td, p
}

// ParseProtocol parses a protocol: value of a dictionary object.
func ParseProtocol(s string) (Protocol, []ast.Diagnostic) {
	pr, p := parseProtocolValue(s)
	return pr, p.diags
}

func parseProtocolValue(s string) (Protocol, *parser) {
	p := newParser(s)
	pr := Protocol{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return pr, p
	}
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/rp-protocol", "expected a protocol name")
		return pr, p
	}
	pr.Name = normAttr(t.text)
	p.advance()
	p.stops = []string{"mandatory", "optional"}
	for !p.atEOF() && p.cur().kind != tSemi {
		kw := p.cur()
		mandatory := kw.kw("mandatory")
		if !mandatory && !kw.kw("optional") {
			p.errf(kw, "policy/rp-protocol", "expected MANDATORY or OPTIONAL, found "+quote(kw.text))
			return pr, p
		}
		p.advance()
		sigs := p.parseSignatures("policy/rp-protocol")
		if len(sigs) == 0 {
			break
		}
		for _, m := range sigs {
			pr.Options = append(pr.Options, ProtocolOption{
				Mandatory: mandatory, Name: m.Name, Args: m.Args, Raw: m.Raw,
			})
		}
	}
	p.finish()
	return pr, p
}

// The standard dictionary of RFC 2622 §9, written as the dictionary object's
// own attribute values and parsed once at start-up. Keeping it in RPSL rather
// than in Go literals means the shipped data exercises the same parsers a
// registry's dictionary object goes through; TestRFCDictionaryParsesCleanly
// asserts it does so without a diagnostic.
//
// Figure 25's assignment operators are listed on every attribute of an ordered
// type, so that checking a legal "med += 5" against this dictionary does not
// warn. The community "operator()" form is left out: RFC 2622 §7's
// "community(…)" tests a route, so this library parses it as a filter, never as
// an action.
var (
	rfcRPAttributes = []string{
		"pref " + orderedOps("integer[0, 65535]"),
		"med " + orderedOps("union integer[0, 65535], enum[igp_cost]"),
		"dpa " + orderedOps("integer[0, 65535]"),
		"cost " + orderedOps("integer[0, 65535]"),
		"next-hop operator=(union ipv4_address, enum[self])",
		"aspath prepend(list of as_number)",
		"community operator=(community_list) operator.=(community_list) " +
			"append(community_list) delete(community_list) contains(community_list)",
	}
	rfcTypedefs = []string{
		"community_list list of union integer[1, 4294967295], " +
			"enum[internet, no_export, no_advertise, local_as]",
		"as_number integer[1, 4294967295]",
	}
	rfcProtocols = []string{
		"BGP4 MANDATORY asno(as_number) OPTIONAL flap_damp() " +
			"OPTIONAL flap_damp(integer[0, 65535], integer[0, 65535], integer[0, 65535], " +
			"integer[0, 65535], integer[0, 65535], integer[0, 65535])",
		"OSPF", "RIP", "RIPng", "IGRP", "IS-IS", "STATIC",
		"DVMRP", "PIM-DM", "PIM-SM", "CBT", "MOSPF",
	}
)

// orderedOps spells the assignment operators RFC 2622 Figure 25 allows on an
// attribute of an ordered type, each taking the same argument type.
func orderedOps(typ string) string {
	var b strings.Builder
	for _, op := range []string{"=", "+=", "-=", "*=", "/=", "<<=", ">>="} {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("operator" + op + "(" + typ + ")")
	}
	return b.String()
}

// RFCDictionary is the standard RP-attribute dictionary of RFC 2622 §9: the
// attributes pref, med, dpa, cost, next-hop, aspath and community, and the
// routing protocols a peering may name. Pass it as Options.Dict to check a
// policy's actions and protocol names against the standard set.
var RFCDictionary = rfcDictionary()

func rfcDictionary() Dictionary {
	attrs := make([]RPAttr, 0, len(rfcRPAttributes))
	for _, s := range rfcRPAttributes {
		a, _ := ParseRPAttribute(s)
		attrs = append(attrs, a)
	}
	tds := make([]Typedef, 0, len(rfcTypedefs))
	for _, s := range rfcTypedefs {
		td, _ := ParseTypedef(s)
		tds = append(tds, td)
	}
	prots := make([]Protocol, 0, len(rfcProtocols))
	for _, s := range rfcProtocols {
		pr, _ := ParseProtocol(s)
		prots = append(prots, pr)
	}
	return NewDictionary(attrs, tds, prots)
}
