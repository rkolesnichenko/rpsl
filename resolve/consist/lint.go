package consist

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The rules Lint reports (docs/diagnostics.md).
const (
	RuleShadowed      = "lint/shadowed"       // every route a term accepts, an earlier decided term accepts
	RuleEmpty         = "lint/empty"          // a term's filter, or a default's networks, accepts no route
	RuleMissingSet    = "lint/missing-set"    // a filter or peering names a set the Source does not have
	RuleMissingRouter = "lint/missing-router" // a peering names an inet-rtr the Source does not have
	RuleNoAutNum      = "lint/no-aut-num"     // a peering names an AS whose aut-num the Source does not have
	RuleUndecided     = "lint/undecided"      // a term peval cannot decide; the message gives the reason
	RuleLimit         = "lint/limit"          // a session's evaluation hit a limit
)

var ruleSeverity = map[string]ast.Severity{
	RuleShadowed: ast.Warning, RuleEmpty: ast.Info, RuleMissingSet: ast.Warning, RuleMissingRouter: ast.Warning,
	RuleNoAutNum: ast.Warning, RuleUndecided: ast.Info, RuleLimit: ast.Warning,
}

// Rules returns every rule Lint reports, in documentation order.
func Rules() []string {
	return []string{RuleShadowed, RuleEmpty, RuleMissingSet, RuleMissingRouter, RuleNoAutNum, RuleUndecided, RuleLimit}
}

// Issue is a Diagnostic — Rule, Severity, Message, and the Span of the
// attribute inside the aut-num's text — plus where it applies. Identical
// issues across sessions are merged: Peers and AFs list every session that
// has it, ascending. An issue no one attribute carries (a peering's missing
// set, a limit, a peer's missing aut-num) has Attr "" and Index -1.
type Issue struct {
	ast.Diagnostic
	Attr  string // the attribute as written: "import", "mp-import", "export", …
	Index int    // the attribute's position, as peval's Clause.Index; -1: none
	Peers []types.ASN
	AFs   []types.AddrFamily
}

var lintFamilies = []types.AddrFamily{{AFI: types.AFIv4, SAFI: types.SAFIUnicast}, {AFI: types.AFIv6, SAFI: types.SAFIUnicast}}

// Lint evaluates as's import, export and default policies toward each peer
// in Peers' Forward list (as's own policies name nothing toward the others),
// in ipv4.unicast and ipv6.unicast, with no routers given, and reports what
// is wrong or dead in them. It returns an error wrapping resolve.ErrNotFound
// when as's own aut-num is not in the Source. A limit hit in one session is
// a lint/limit issue; the other sessions are still linted.
func (c *Checker) Lint(ctx context.Context, as types.ASN) ([]Issue, error) {
	ev := c.eval()
	an, err := ev.Src.AutNum(ctx, as, ev.Source)
	if err != nil {
		return nil, fmt.Errorf("consist: %w", err)
	}
	peers, err := c.Peers(ctx, as)
	if isLimit(err) {
		l := newLinter(an)
		l.add(RuleLimit, "", -1, err.Error(), 0, nil)
		return l.issues(), nil
	}
	if err != nil {
		return nil, err
	}
	l := newLinter(an)
	if err := l.routers(ctx, c); err != nil {
		return nil, err
	}
	for _, peer := range peers.Forward {
		if _, err := ev.Src.AutNum(ctx, peer, ""); errors.Is(err, resolve.ErrNotFound) {
			l.add(RuleNoAutNum, "", -1, fmt.Sprintf("%s's aut-num is not in the source", peer), peer, nil)
		} else if err != nil {
			return nil, err
		}
		for _, af := range lintFamilies {
			s := peval.Session{Local: as, Peer: peer, AF: af}
			for _, kind := range []string{"import", "export"} {
				var p peval.Policy
				if kind == "import" {
					p, err = ev.Import(ctx, s)
				} else {
					p, err = ev.Export(ctx, s)
				}
				if isLimit(err) {
					l.add(RuleLimit, "", -1, err.Error(), peer, &af)
					continue
				}
				if err != nil {
					return nil, err
				}
				l.policy(kind, p, peer, af)
			}
			d, err := ev.Default(ctx, s)
			if isLimit(err) {
				l.add(RuleLimit, "", -1, err.Error(), peer, &af)
				continue
			}
			if err != nil {
				return nil, err
			}
			l.defaults(d, peer, af)
		}
	}
	return l.issues(), nil
}

func isLimit(err error) bool {
	var tl *resolve.SetTooLargeError
	return errors.As(err, &tl) || errors.Is(err, policy.ErrFlattenTooLarge)
}

// linter collects one aut-num's issues.
type linter struct {
	an    object.AutNum
	attrs map[string][]ast.Attribute // "import", "export", "default" -> those attributes (and their mp- forms), in order
	m     map[issueKey]*Issue
}

type issueKey struct {
	rule, attr string
	index      int
	msg        string
}

func newLinter(an object.AutNum) *linter {
	l := &linter{an: an, attrs: map[string][]ast.Attribute{}, m: map[issueKey]*Issue{}}
	if raw := an.Raw(); raw != nil {
		for _, a := range raw.Attributes() {
			switch a.Name {
			case "import", "mp-import":
				l.attrs["import"] = append(l.attrs["import"], a)
			case "export", "mp-export":
				l.attrs["export"] = append(l.attrs["export"], a)
			case "default", "mp-default":
				l.attrs["default"] = append(l.attrs["default"], a)
			}
		}
	}
	return l
}

// add records an issue of kind's attribute index (-1: none) for a session
// with peer (0: none) in af (nil: none).
func (l *linter) add(rule, kind string, index int, msg string, peer types.ASN, af *types.AddrFamily) {
	var name string
	span := ast.Attribute{}.Span // a lexer.Span; lexer is only an indirect requirement of this module
	if index >= 0 && index < len(l.attrs[kind]) {
		name, span = l.attrs[kind][index].Name, l.attrs[kind][index].Span
	} else if index >= 0 {
		name = kind // built by hand: no text to point at
	}
	k := issueKey{rule, name, index, msg}
	is, ok := l.m[k]
	if !ok {
		is = &Issue{Diagnostic: ast.Diagnostic{Severity: ruleSeverity[rule], Message: msg, Span: span, Rule: rule}, Attr: name, Index: index}
		l.m[k] = is
	}
	if peer != 0 && !slices.Contains(is.Peers, peer) {
		is.Peers = append(is.Peers, peer)
	}
	if af != nil && !slices.Contains(is.AFs, *af) {
		is.AFs = append(is.AFs, *af)
	}
}

// policy lints one evaluated import or export policy.
func (l *linter) policy(kind string, p peval.Policy, peer types.ASN, af types.AddrFamily) {
	for _, u := range p.Undecided {
		l.add(RuleUndecided, kind, u.Index, fmt.Sprintf("%s term cannot be decided: %s", kind, u.Why), peer, &af)
	}
	inClause := map[string]bool{}
	for _, cl := range p.Clauses {
		for _, m := range cl.Filter.Missing() {
			inClause[m.String()] = true
			l.add(RuleMissingSet, kind, cl.Index, fmt.Sprintf("the filter names %s, which is not in the source", m), peer, &af)
		}
	}
	for _, m := range p.Missing() {
		if !inClause[m.String()] {
			l.add(RuleMissingSet, "", -1, fmt.Sprintf("an %s peering names %s, which is not in the source", kind, m), peer, &af)
		}
	}
	var earlier []conj
	for _, cl := range p.Clauses {
		cs := sideOf(peval.Policy{Clauses: []peval.Clause{cl}}).conjs
		if union(cs).IsEmpty() { // no conjunct, or none whose prefixes hold anything
			l.add(RuleEmpty, kind, cl.Index, fmt.Sprintf("%s term %s accepts no route", kind, cl.Term), peer, &af)
			continue
		}
		if shadowed(cs, earlier) {
			l.add(RuleShadowed, kind, cl.Index, fmt.Sprintf("%s term %s never decides: earlier terms accept every route it accepts", kind, cl.Term), peer, &af)
		}
		earlier = append(earlier, cs...)
	}
}

// shadowed reports whether every route cs accepts is accepted by earlier:
// per signature T of cs, its space lies in the union of the earlier
// conjuncts whose tests are a subset of T (a route passing T passes them).
func shadowed(cs, earlier []conj) bool {
	bySig := map[string][]conj{}
	for _, cj := range cs {
		k := fmt.Sprint(cj.sig)
		bySig[k] = append(bySig[k], cj)
	}
	for _, g := range bySig {
		var cover []conj
		for _, e := range earlier {
			if subset(e.sig, g[0].sig) {
				cover = append(cover, e)
			}
		}
		if !union(g).Subset(union(cover)) {
			return false
		}
	}
	return true
}

// defaults lints one evaluated default policy.
func (l *linter) defaults(d peval.Defaults, peer types.ASN, af types.AddrFamily) {
	for _, u := range d.Undecided {
		l.add(RuleUndecided, "default", u.Index, fmt.Sprintf("default term cannot be decided: %s", u.Why), peer, &af)
	}
	inClause := map[string]bool{}
	for _, dc := range d.Clauses {
		if dc.Networks == nil {
			continue
		}
		for _, m := range dc.Networks.Missing() {
			inClause[m.String()] = true
			l.add(RuleMissingSet, "default", dc.Index, fmt.Sprintf("the networks filter names %s, which is not in the source", m), peer, &af)
		}
		if union(sideOf(peval.Policy{Clauses: []peval.Clause{{Filter: *dc.Networks}}}).conjs).IsEmpty() {
			l.add(RuleEmpty, "default", dc.Index, "the networks filter accepts no route", peer, &af)
		}
	}
	for _, m := range d.Missing() {
		if !inClause[m.String()] {
			l.add(RuleMissingSet, "", -1, fmt.Sprintf("a default peering names %s, which is not in the source", m), peer, &af)
		}
	}
}

// routers looks up every inet-rtr and rtr-set the aut-num's peerings name,
// statically: Lint gives peval no routers, so peval never does.
func (l *linter) routers(ctx context.Context, c *Checker) error {
	ev := c.eval()
	e := ev.Expander
	e.Src = ev.Src
	var walk func(kind string, i int, r policy.RouterExpr) error
	walk = func(kind string, i int, r policy.RouterExpr) error {
		switch x := r.(type) {
		case policy.RouterName:
			_, err := ev.Src.InetRtr(ctx, x.Name, "")
			switch {
			case errors.Is(err, resolve.ErrNotFound):
				l.add(RuleMissingRouter, kind, i, fmt.Sprintf("the peering names inet-rtr %s, which is not in the source", x.Name), 0, nil)
			case err != nil:
				return err
			}
		case policy.RouterSetRef:
			_, err := e.ExpandRouters(ctx, types.Ref(x.Name))
			switch {
			case errors.Is(err, resolve.ErrNotFound):
				l.add(RuleMissingSet, kind, i, fmt.Sprintf("the peering names %s, which is not in the source", x.Name), 0, nil)
			case err != nil && !isLimit(err):
				return err
			}
		case policy.RouterExprBinary:
			if err := walk(kind, i, x.L); err != nil {
				return err
			}
			return walk(kind, i, x.R)
		}
		return nil
	}
	peering := func(kind string, i int, p policy.Peering) error {
		x, ok := p.(policy.PeeringAS)
		if !ok {
			return nil
		}
		for _, r := range []policy.RouterExpr{x.Router, x.AtRouter} {
			if r != nil {
				if err := walk(kind, i, r); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for kind, exprs := range map[string][]policy.Expr{"import": importExprs(l.an), "export": exportExprs(l.an)} {
		for i, ex := range exprs {
			for _, p := range exprPeerings(ex) {
				if err := peering(kind, i, p); err != nil {
					return err
				}
			}
		}
	}
	for i, d := range l.an.Defaults {
		if err := peering("default", i, d.Peering); err != nil {
			return err
		}
	}
	return nil
}

// issues returns the merged issues: those no attribute carries first, then
// by line, attribute index, rule and message; Peers and AFs sorted.
func (l *linter) issues() []Issue {
	out := make([]Issue, 0, len(l.m))
	for _, is := range l.m {
		slices.Sort(is.Peers)
		slices.SortFunc(is.AFs, func(a, b types.AddrFamily) int {
			if c := cmp.Compare(a.AFI, b.AFI); c != 0 {
				return c
			}
			return cmp.Compare(a.SAFI, b.SAFI)
		})
		out = append(out, *is)
	}
	slices.SortFunc(out, func(a, b Issue) int {
		if c := cmp.Compare(a.Span.StartLine, b.Span.StartLine); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Index, b.Index); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
			return c
		}
		return cmp.Compare(a.Message, b.Message)
	})
	return out
}
