package policy

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// MntRoutes is a parsed mnt-routes: value (RFC 2725, and RIPE's rendering of
// it): a maintainer, and the address space it may authorise route objects in.
//
//	mnt-routes: EXAMPLE-MNT
//	mnt-routes: EXAMPLE-MNT ANY
//	mnt-routes: EXAMPLE-MNT {192.0.2.0/24^+, 198.51.100.0/24}
//
// A value with no scope means the whole space, so Any is true for both of the
// first two spellings; Raw keeps which one was written.
type MntRoutes struct {
	Mntner string
	Any    bool
	Ranges []types.PrefixRange
	Raw    string
}

// String renders the value in canonical form.
func (m MntRoutes) String() string {
	switch {
	case m.Mntner == "":
		return ""
	case len(m.Ranges) > 0:
		return m.Mntner + " " + rangesString(m.Ranges)
	case m.Any:
		return m.Mntner + " ANY"
	}
	return m.Mntner
}

// ParseMntRoutes parses an mnt-routes: value. It returns a best-effort
// MntRoutes plus diagnostics; it never panics.
func ParseMntRoutes(s string) (MntRoutes, []ast.Diagnostic) {
	m, p := parseMntRoutesValue(s)
	return m, p.diags
}

func parseMntRoutesValue(s string) (MntRoutes, *parser) {
	p := newParser(s)
	m := MntRoutes{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return m, p
	}
	t := p.cur()
	if t.kind != tWord {
		p.errf(t, "policy/mnt-routes", "expected a maintainer name")
		p.sync()
		p.finish()
		return m, p
	}
	m.Mntner = t.text
	p.advance()
	switch {
	case p.atEOF() || p.cur().kind == tSemi:
		m.Any = true // no scope given: the maintainer may authorise anything
	case p.cur().kw("any"):
		m.Any = true
		p.advance()
	case p.cur().kind == tLBrace:
		list, _ := p.parsePrefixList().(FilterPrefixList)
		m.Ranges = list.Ranges
	default:
		p.errf(p.cur(), "policy/mnt-routes",
			"expected ANY or a prefix list after "+quote(m.Mntner))
	}
	p.finish()
	return m, p
}
