package policy

import (
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// import-via: and export-via: (draft-ietf-grow-rpsl-via, as the RIPE Database
// implements it) are mp-import: and mp-export: with one addition: every clause
// names, before its "from" or "to", the peering its routes pass through — an
// Internet exchange's route server, say:
//
//	import-via: [protocol P1] [into P2] [afi <afi-list>]
//	            <via-peering> from <peering> [action <action>; …]
//	            … accept <filter>
//
// The via peering is PeerAction.Via. Everything else is the mp-* grammar, so a
// via policy has the same Import and Export types, renders with String and
// flattens with Flatten.

// ParseImportVia parses an import-via: value ("AS6777 from AS15562 action
// pref = 2; accept AS-SNIJDERS"). The result is marked MP: without an afi
// clause it applies to every address family, as an mp-import: does.
func ParseImportVia(s string) (Import, []ast.Diagnostic) {
	imp, p := parseImportVia(s, Options{})
	return imp, p.diags
}

// ParseImportViaWith is ParseImportVia with options.
func ParseImportViaWith(s string, o Options) (Import, []ast.Diagnostic) {
	imp, p := parseImportVia(s, o)
	return imp, p.diags
}

// ParseExportVia parses an export-via: value ("AS6777 to AS15562 announce
// AS-SNIJDERS"); see ParseImportVia.
func ParseExportVia(s string) (Export, []ast.Diagnostic) {
	exp, p := parseExportVia(s, Options{})
	return exp, p.diags
}

// ParseExportViaWith is ParseExportVia with options.
func ParseExportViaWith(s string, o Options) (Export, []ast.Diagnostic) {
	exp, p := parseExportVia(s, o)
	return exp, p.diags
}

func parseImportVia(s string, o Options) (Import, *parser) {
	p := newParser(s)
	p.mp, p.via, p.dict = true, "from", o.Dict
	imp := Import{MP: true}
	if p.empty() {
		return imp, p
	}
	imp.Protocol, imp.IntoProtocol = p.parseProtocols()
	imp.AFIs = p.parseAFIs()
	imp.Expr = p.parseExpr("from", "accept")
	p.finish()
	return imp, p
}

func parseExportVia(s string, o Options) (Export, *parser) {
	p := newParser(s)
	p.mp, p.via, p.dict = true, "to", o.Dict
	exp := Export{MP: true}
	if p.empty() {
		return exp, p
	}
	exp.Protocol, exp.IntoProtocol = p.parseProtocols()
	exp.AFIs = p.parseAFIs()
	exp.Expr = p.parseExpr("to", "announce")
	p.finish()
	return exp, p
}

// parseViaFactor parses one or more "<via-peering> <peerKw> <peering> [action
// …]" clauses followed by "<filterKw> <filter>". A clause without its via
// peering is diagnosed and dropped; the rest of the factor is still read.
func (p *parser) parseViaFactor(peerKw, filterKw string) Factor {
	var f Factor
	clauses := 0
	for p.startsViaClause(p.cur(), peerKw, filterKw) {
		clauses++
		var pa PeerAction
		if p.cur().kw(peerKw) {
			p.errf(p.cur(), "policy/via", "expected the peering routes pass through before '"+peerKw+"'")
		} else {
			pa.Via = p.parsePeering()
			if !p.cur().kw(peerKw) {
				p.errf(p.cur(), "policy/expect-peering", "expected '"+peerKw+"' after the via peering")
				if p.cur().kw(filterKw) {
					break
				}
				p.sync()
				return f
			}
		}
		p.advance() // peerKw
		pa.Peering = p.parsePeering()
		if p.cur().kw("action") {
			p.advance()
			pa.Actions = p.parseActions()
		}
		if pa.Via != nil {
			f.Peers = append(f.Peers, pa)
		}
	}
	if clauses == 0 {
		p.errf(p.cur(), "policy/expect-peering", "expected '<via-peering> "+peerKw+" <peering>' clause")
		if !p.cur().kw(filterKw) {
			p.sync()
			return f
		}
	}
	if !p.cur().kw(filterKw) {
		p.errf(p.cur(), "policy/expect-filter", "expected '"+filterKw+"' clause")
		p.sync()
		return f
	}
	p.advance()
	f.Filter = p.parseFilter()
	return f
}

// startsViaClause reports whether t begins a via clause: its via peering, or
// the peer keyword of a clause that lacks one.
func (p *parser) startsViaClause(t token, peerKw, filterKw string) bool {
	switch {
	case t.kw(peerKw):
		return true
	case t.kw(filterKw), t.kw("at"):
		return false
	}
	switch t.kind {
	case tRegex, tLParen:
		return true
	case tWord:
		return !p.peeringStop(t)
	}
	return false
}

// startsNextVia reports whether, in a via policy, t begins the next clause's
// via peering rather than continuing the current peering: an AS number, an
// as-set or peering-set name, or an AS-path regexp. None of them can be a
// router, so "from AS-ANY AS6777 from …" reads as two clauses.
func (p *parser) startsNextVia(t token) bool {
	if p.via == "" {
		return false
	}
	switch t.kind {
	case tRegex:
		return true
	case tWord:
		if _, err := types.ParseASN(t.text); err == nil {
			return true
		}
		if sn, err := types.ParseSetName(t.text); err == nil {
			return sn.Class() == types.ClassAsSet || sn.Class() == types.ClassPeeringSet
		}
	}
	return false
}

// actionsEndBeforeVia reports whether, in a via policy, the action segment
// starting at the current token runs up to the peer keyword: it is then the
// next clause's via peering ("action pref=200; AS6777 from …"), not an action.
func (p *parser) actionsEndBeforeVia() bool {
	if p.via == "" {
		return false
	}
	depth := 0
	for i := p.pos; i < len(p.toks); i++ {
		t := p.toks[i]
		switch {
		case t.kind == tEOF:
			return false
		case p.clauseKw(t):
			return t.kw(p.via)
		case depth == 0 && (t.kind == tSemi || t.kind == tRBrace):
			return false
		case t.kind == tLBrace:
			depth++
		case t.kind == tRBrace:
			depth--
		}
	}
	return false
}
