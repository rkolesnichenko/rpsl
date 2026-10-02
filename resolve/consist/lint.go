package consist

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
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
// attribute inside the aut-num's text, relative to the object (its first
// attribute is line 1 and starts at byte 0, however the Source decoded it)
// — plus where it applies. Identical
// issues across sessions are merged: Peers and AFs list every session that
// has it, ascending. An issue no one attribute carries (a peering's missing
// set, a limit, a session's filter that cannot be evaluated, a peer's
// missing aut-num) has Attr "" and Index -1.
type Issue struct {
	ast.Diagnostic
	Attr  string // the attribute as written: "import", "mp-import", "export", …
	Index int    // the attribute's position, as peval's Clause.Index; -1: none
	Peers []types.ASN
	AFs   []types.AddrFamily
}

var lintFamilies = []types.AddrFamily{{AFI: types.AFIv4, SAFI: types.SAFIUnicast}, {AFI: types.AFIv6, SAFI: types.SAFIUnicast}}

// Lint evaluates as's import, export and default policies toward each peer
// in Peers' Forward and Reverse lists, in ipv4.unicast and ipv6.unicast,
// with no routers given, and reports what is wrong or dead in them. A policy
// toward AS-ANY is linted through a session with the reserved AS4294967295
// (RFC 7300), never a real peer: its issues list no peer, and a term that
// depends on the peer is left out of that session's lint/empty and
// lint/shadowed, since it means nothing without one — a term whose filter
// names PeerAS or a set template (directly, in an AS-path regexp, or inside
// a filter-set it names, at any depth), or whose normal form differs when
// the session is evaluated again toward AS65535, RFC 7300's other reserved
// AS. Every
// set a policy names directly is looked up statically, so a missing one is
// reported even when no session reaches it; the sessions add the sets
// missing deeper, inside one that exists. It returns an error wrapping
// resolve.ErrNotFound when as's own aut-num is not in the Source. A limit hit
// in one session is a lint/limit issue, and a filter that cannot be
// evaluated for a session (a set reaching AS-ANY inside it, or no normal
// form: *resolve.AnySetError, *resolve.NotEnumerableError) a lint/undecided
// issue with the error as its message; the other sessions are still linted.
func (c *Checker) Lint(ctx context.Context, as types.ASN) ([]Issue, error) {
	ev := c.eval()
	an, err := ev.Src.AutNum(ctx, as, ev.Source)
	if err != nil {
		return nil, fmt.Errorf("consist: %w", err)
	}
	peers, err := c.Peers(ctx, as)
	if isLimit(err) {
		l := newLinter(ctx, ev, an)
		l.add(RuleLimit, "", -1, err.Error(), 0, nil)
		return l.issues(), nil
	}
	if err != nil {
		return nil, err
	}
	l := newLinter(ctx, ev, an)
	if err := l.sets(ctx, c); err != nil {
		return nil, err
	}
	if err := l.routers(ctx, c); err != nil {
		return nil, err
	}
	all := slices.Concat(peers.Forward, peers.Reverse)
	slices.Sort(all)
	all = slices.DeleteFunc(slices.Compact(all), func(a types.ASN) bool { return a == as || a == anyPeer })
	for _, peer := range all {
		if _, err := ev.Src.AutNum(ctx, peer, ev.Source); errors.Is(err, resolve.ErrNotFound) {
			l.add(RuleNoAutNum, "", -1, fmt.Sprintf("%s's aut-num is not in the source", peer), peer, nil)
		} else if err != nil {
			return nil, err
		}
		if err := l.session(ctx, ev, as, peer); err != nil {
			return nil, err
		}
	}
	if namesAny(peers.Skipped) {
		if err := l.session(ctx, ev, as, anyPeer); err != nil {
			return nil, err
		}
	}
	if l.err != nil {
		return nil, l.err
	}
	return l.issues(), nil
}

// anyPeer is the peer of the session through which a policy toward AS-ANY is
// linted: AS4294967295, reserved by RFC 7300, so no policy names it but
// through AS-ANY. An issue of that session lists no peer.
const anyPeer types.ASN = 4294967295

// namesAny reports whether a peering reaches AS-ANY: Peers skips a set whose
// expansion meets it under the set's name, while the other entries it skips,
// set templates and regexps, are not set names.
func namesAny(skipped []string) bool {
	for _, s := range skipped {
		if _, err := types.ParseSetName(s); err == nil {
			return true
		}
	}
	return false
}

// session lints as's policies toward peer, in each family. A limit is a
// lint/limit issue and a filter that cannot be evaluated for the session a
// lint/undecided one, neither attributed to an attribute; the session's
// other policies are still linted. Toward the sentinel (anyPeer), each
// policy is evaluated a second time toward anyPeer2, and a clause that
// differs between the two depends on the peer (PeerAS at any depth, inside
// a filter-set too): it is left out of lint/empty and lint/shadowed.
func (l *linter) session(ctx context.Context, ev *peval.Evaluator, as, peer types.ASN) error {
	for _, af := range lintFamilies {
		s := peval.Session{Local: as, Peer: peer, AF: af}
		for _, kind := range []string{"import", "export"} {
			eval := func(s peval.Session) (peval.Policy, error) {
				if kind == "import" {
					return ev.Import(ctx, s)
				}
				return ev.Export(ctx, s)
			}
			p, err := eval(s)
			if ok, err := l.failed(err, peer, af); ok || err != nil {
				if err != nil {
					return err
				}
				continue
			}
			var dep map[string]bool
			if peer == anyPeer {
				s2 := s
				s2.Peer = anyPeer2
				p2, err := eval(s2)
				if err != nil && !isLimit(err) && !notDecidable(err) {
					return err
				}
				dep = dependent(p.Clauses, p2.Clauses, err != nil)
			}
			l.policy(kind, p, peer, af, dep)
		}
		d, err := ev.Default(ctx, s)
		if ok, err := l.failed(err, peer, af); ok || err != nil {
			if err != nil {
				return err
			}
			continue
		}
		var dep map[string]bool
		if peer == anyPeer {
			s2 := s
			s2.Peer = anyPeer2
			d2, err := ev.Default(ctx, s2)
			if err != nil && !isLimit(err) && !notDecidable(err) {
				return err
			}
			dep = dependent(networks(d.Clauses), networks(d2.Clauses), err != nil)
		}
		l.defaults(d, peer, af, dep)
	}
	return nil
}

// anyPeer2 is the second peer the sentinel session is evaluated toward:
// AS65535, reserved by RFC 7300 as AS4294967295 is.
const anyPeer2 types.ASN = 65535

// clauseKey identifies a clause across two evaluations of one policy.
func clauseKey(c peval.Clause) string { return fmt.Sprintf("%d %s", c.Index, c.Term) }

// dependent returns the keys of the clauses of a (toward anyPeer) whose
// normal form differs in b (toward anyPeer2), or that b lacks: they depend
// on the peer. failed (b's evaluation failed) makes every clause dependent.
func dependent(a, b []peval.Clause, failed bool) map[string]bool {
	other := map[string][]conj{}
	for _, cl := range b {
		other[clauseKey(cl)] = append(other[clauseKey(cl)], sideOf(peval.Policy{Clauses: []peval.Clause{cl}}).conjs...)
	}
	dep := map[string]bool{}
	for _, cl := range a {
		k := clauseKey(cl)
		cs, ok := other[k]
		if failed || !ok || !sameConjs(sideOf(peval.Policy{Clauses: []peval.Clause{cl}}).conjs, cs) {
			dep[k] = true
		}
	}
	return dep
}

// sameConjs reports whether two conjunct lists are the same, in order:
// signatures and spaces.
func sameConjs(a, b []conj) bool {
	return slices.EqualFunc(a, b, func(x, y conj) bool { return slices.Equal(x.sig, y.sig) && x.space.Equal(y.space) })
}

// networks returns default clauses as peval clauses of their networks
// filters (a default without one is left out), for dependent.
func networks(ds []peval.DefaultClause) []peval.Clause {
	var out []peval.Clause
	for _, dc := range ds {
		if dc.Networks != nil {
			out = append(out, peval.Clause{Index: dc.Index, Filter: *dc.Networks})
		}
	}
	return out
}

// failed reports whether a session's evaluation failed in a way that is an
// issue — a limit (lint/limit) or a filter that cannot be evaluated for the
// session (lint/undecided) — and records it; any other error is returned.
func (l *linter) failed(err error, peer types.ASN, af types.AddrFamily) (bool, error) {
	switch {
	case err == nil:
		return false, nil
	case isLimit(err):
		l.add(RuleLimit, "", -1, err.Error(), peer, &af)
		return true, nil
	case notDecidable(err):
		l.add(RuleUndecided, "", -1, err.Error(), peer, &af)
		return true, nil
	}
	return false, err
}

// notDecidable reports whether err is a session's filter that cannot be
// evaluated for it: one naming a set that reaches AS-ANY
// (*resolve.AnySetError), or one with no normal form
// (*resolve.NotEnumerableError), such as a cycle of filter-sets through an
// AS-path regexp. Lint reports such a session as lint/undecided; Check
// returns the error.
func notDecidable(err error) bool {
	var anyErr *resolve.AnySetError
	var ne *resolve.NotEnumerableError
	return errors.As(err, &anyErr) || errors.As(err, &ne)
}

func isLimit(err error) bool {
	var tl *resolve.SetTooLargeError
	return errors.As(err, &tl) || errors.Is(err, policy.ErrFlattenTooLarge)
}

// linter collects one aut-num's issues.
type linter struct {
	an    object.AutNum
	attrs map[string][]ast.Attribute // "import", "export", "default" -> those attributes (and their mp- forms), in order
	first lexer.Span                 // the object's first attribute: spans are made relative to it
	m     map[issueKey]*Issue
	// For filterSetDependent: the lookups' context and Evaluator, each
	// filter-set fetched at most once (fltrObj), and the first Source
	// failure met. Dependence itself is not memoized across top-level
	// queries — see filterSetDependent.
	ctx     context.Context
	ev      *peval.Evaluator
	fltrObj map[string]fltrObjEntry
	err     error
	// reported holds the sets the static walk (sets) found missing, per
	// attribute; a session reports a missing set for an attribute only when
	// the walk did not report it for that attribute — so a set missing inside
	// one that exists is still reported for every other attribute reaching it.
	reported map[setKey]bool
}

// setKey is a set the static walk reported missing for the attribute kind's
// index; index -1 stands for any attribute of the kind, which is how a
// session's peering-level report (no attribute) is matched.
type setKey struct {
	kind  string
	index int
	name  string
}

type issueKey struct {
	rule, attr string
	index      int
	msg        string
}

func newLinter(ctx context.Context, ev *peval.Evaluator, an object.AutNum) *linter {
	l := &linter{an: an, attrs: map[string][]ast.Attribute{}, m: map[issueKey]*Issue{}, reported: map[setKey]bool{},
		ctx: ctx, ev: ev, fltrObj: map[string]fltrObjEntry{}}
	if raw := an.Raw(); raw != nil {
		for i, a := range raw.Attributes() {
			if i == 0 {
				l.first = a.Span
			}
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
// with peer (0 or anyPeer: none) in af (nil: none).
func (l *linter) add(rule, kind string, index int, msg string, peer types.ASN, af *types.AddrFamily) {
	var name string
	var span lexer.Span
	if index >= 0 && index < len(l.attrs[kind]) {
		name, span = l.attrs[kind][index].Name, objectSpan(l.attrs[kind][index].Span, l.first)
	} else if index >= 0 {
		name = kind // built by hand: no text to point at
	}
	k := issueKey{rule, name, index, msg}
	is, ok := l.m[k]
	if !ok {
		is = &Issue{Diagnostic: ast.Diagnostic{Severity: ruleSeverity[rule], Message: msg, Span: span, Rule: rule}, Attr: name, Index: index}
		l.m[k] = is
	}
	if peer != 0 && peer != anyPeer && !slices.Contains(is.Peers, peer) {
		is.Peers = append(is.Peers, peer)
	}
	if af != nil && !slices.Contains(is.AFs, *af) {
		is.AFs = append(is.AFs, *af)
	}
}

// objectSpan returns sp, a span inside an object whose first attribute
// spans first, relative to the object: lines counted from the first
// attribute's (line 1), byte offsets from its first byte; columns are kept.
// An object decoded from a dump or a mirror, as a Corpus keeps a member-of:
// claimant, carries the stream's positions; one from irrd or whois, or kept
// as text, its own already, and is returned unchanged.
func objectSpan(sp, first lexer.Span) lexer.Span {
	if first.StartLine == 0 {
		return sp
	}
	sp.StartLine -= first.StartLine - 1
	sp.EndLine -= first.StartLine - 1
	sp.StartByte -= first.StartByte
	sp.EndByte -= first.StartByte
	return sp
}

// policy lints one evaluated import or export policy; dep holds the keys of
// clauses that depend on the peer (toward the sentinel only).
func (l *linter) policy(kind string, p peval.Policy, peer types.ASN, af types.AddrFamily, dep map[string]bool) {
	for _, u := range p.Undecided {
		l.add(RuleUndecided, kind, u.Index, fmt.Sprintf("%s term cannot be decided: %s", kind, u.Why), peer, &af)
	}
	inClause := map[string]bool{}
	for _, cl := range p.Clauses {
		for _, m := range cl.Filter.Missing() {
			inClause[m.String()] = true
			if l.deeper(m, peer, kind, cl.Index) {
				l.add(RuleMissingSet, kind, cl.Index, fmt.Sprintf("the filter names %s, which is not in the source", m), peer, &af)
			}
		}
	}
	for _, m := range p.Missing() {
		if !inClause[m.String()] && l.deeper(m, peer, kind, -1) {
			l.add(RuleMissingSet, "", -1, fmt.Sprintf("an %s peering names %s, which is not in the source", kind, m), peer, &af)
		}
	}
	var earlier []conj
	for _, cl := range p.Clauses {
		if peer == anyPeer && (l.peerDependent(cl.Term.Filter) || dep[clauseKey(cl)]) {
			continue // PeerAS toward the sentinel is no AS: the term's routes are unknown
		}
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
		k := strings.Join(cj.sig, "\x00")
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

// defaults lints one evaluated default policy; dep as for policy.
func (l *linter) defaults(d peval.Defaults, peer types.ASN, af types.AddrFamily, dep map[string]bool) {
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
			if l.deeper(m, peer, "default", dc.Index) {
				l.add(RuleMissingSet, "default", dc.Index, fmt.Sprintf("the networks filter names %s, which is not in the source", m), peer, &af)
			}
		}
		if peer == anyPeer && (dc.Index >= 0 && dc.Index < len(l.an.Defaults) && l.peerDependent(l.an.Defaults[dc.Index].Networks) ||
			dep[clauseKey(peval.Clause{Index: dc.Index, Filter: *dc.Networks})]) {
			continue
		}
		if union(sideOf(peval.Policy{Clauses: []peval.Clause{{Filter: *dc.Networks}}}).conjs).IsEmpty() {
			l.add(RuleEmpty, "default", dc.Index, "the networks filter accepts no route", peer, &af)
		}
	}
	for _, m := range d.Missing() {
		if !inClause[m.String()] && l.deeper(m, peer, "default", -1) {
			l.add(RuleMissingSet, "", -1, fmt.Sprintf("a default peering names %s, which is not in the source", m), peer, &af)
		}
	}
}

// deeper reports whether a session's missing set m, found for kind's
// attribute index (-1: a peering, no attribute), is one to report: not one
// the static walk already reported for that attribute (for -1, for any
// attribute of the kind), and, toward the sentinel, not a set template
// filled in with it (AS1:AS-CUST:AS4294967295 names no real set).
func (l *linter) deeper(m types.SetRef, peer types.ASN, kind string, index int) bool {
	if l.reported[setKey{kind, index, m.String()}] {
		return false
	}
	if peer == anyPeer && slices.Contains(m.Name().Components(), anyPeer.String()) {
		return false
	}
	return true
}

// peerDependent reports whether a filter names PeerAS or a set template,
// directly, in an AS-path regexp, or inside a filter-set it names (at any
// depth): what it accepts depends on who the peer is. The two evaluations
// toward the sentinel cannot see PeerAS as a prefix filter, since neither
// reserved AS originates a route.
//
// It is a plain reachability walk, fresh for this one call: visited records
// every filter-set looked into and is never un-marked, so a cycle back to an
// ancestor and a diamond of two paths into the same descendant are the same
// case — the set holds nothing new to find the second time, whichever shape
// led there — and the walk fetches and scans each reachable filter-set at
// most once (linear in the sets reachable from f, not in the number of paths
// through them).
func (l *linter) peerDependent(f policy.Filter) bool {
	return l.peerDependentOn(f, map[string]bool{})
}

// peerDependentOn is peerDependent threaded with visited, the filter-sets
// already looked into by this call (see filterSetDependent).
func (l *linter) peerDependentOn(f policy.Filter, visited map[string]bool) bool {
	switch x := f.(type) {
	case policy.FilterPeerAS, policy.FilterSetTemplate:
		return true
	case policy.FilterASExpr:
		return asExprTemplate(x.AS)
	case policy.FilterPathRE:
		return x.Regexp != nil && pathPeerDependent(x.Regexp.Body)
	case policy.FilterSetRef:
		return l.filterSetDependent(x.Name, visited)
	case policy.FilterAnd:
		return slices.ContainsFunc(x.Terms, func(t policy.Filter) bool { return l.peerDependentOn(t, visited) })
	case policy.FilterOr:
		return slices.ContainsFunc(x.Terms, func(t policy.Filter) bool { return l.peerDependentOn(t, visited) })
	case policy.FilterNot:
		return l.peerDependentOn(x.Inner, visited)
	}
	return false
}

// fltrObjEntry caches one filterSetObject fetch: a filter-set's object is
// looked up at most once per Lint call, however many times a cycle or
// several clauses reach it.
type fltrObjEntry struct {
	fs  object.FilterSet
	ok  bool // false: missing (or not a filter-set) — fs is unset
	err error
}

// filterSetObject fetches the filter-set n's object, caching the fetch (not
// the dependence it implies — see filterSetDependent) across the whole Lint
// call. A Source failure other than ErrNotFound is kept for Lint to return.
// A context already cancelled or past its deadline is reported as the fetch's
// error without a call to the Source, so a walk over many filter-sets stops
// promptly once the caller gives up rather than running every fetch out.
func (l *linter) filterSetObject(n types.SetName) (fs object.FilterSet, ok bool, err error) {
	k := n.String()
	if e, cached := l.fltrObj[k]; cached {
		return e.fs, e.ok, e.err
	}
	if cerr := l.ctx.Err(); cerr != nil {
		return object.FilterSet{}, false, cerr
	}
	var e fltrObjEntry
	set, ferr := l.ev.Src.GetSet(l.ctx, types.Ref(n))
	switch {
	case errors.Is(ferr, resolve.ErrNotFound):
		// e stays the zero value: not found, no error.
	case ferr != nil:
		e.err = ferr
	default:
		switch x := set.(type) {
		case object.FilterSet:
			e.fs, e.ok = x, true
		case *object.FilterSet:
			e.fs, e.ok = *x, true
		}
	}
	l.fltrObj[k] = e
	return e.fs, e.ok, e.err
}

// filterSetDependent reports whether the filter-set n's filters depend on
// the peer, at any depth, as one step of peerDependentOn's reachability
// walk: n is marked in visited before it is scanned and never un-marked, so
// a second reference to n within the same call — by a cycle back to an
// ancestor or by a second, independent path (a diamond) — is answered
// immediately as "nothing new here" without being fetched or scanned again.
// That is sound for reachability (unlike memoizing a final true/false per
// set across separate calls, which is what let a cycle hide a PeerAS before
// this fix): what n itself and everything reachable from it can show was
// already being discovered, by this same walk, the first time n was
// reached, and dependence is only ever an OR over the whole reachable set,
// never conditioned on which path a set was reached by. A missing set, or
// one whose class is not filter-set, does not depend on the peer; a Source
// failure — including the walk's own context expiring mid-fetch — is kept
// for Lint to return, and counts as dependent, so lint stays silent about a
// term rather than risk a wrong shadowed or empty finding.
func (l *linter) filterSetDependent(n types.SetName, visited map[string]bool) bool {
	if n.Class() != types.ClassFilterSet {
		return false
	}
	k := n.String()
	if visited[k] {
		return false
	}
	visited[k] = true
	fs, ok, err := l.filterSetObject(n)
	if err != nil {
		if l.err == nil {
			l.err = err
		}
		return true
	}
	if !ok {
		return false
	}
	return fs.Filter != nil && l.peerDependentOn(fs.Filter, visited) || fs.MpFilter != nil && l.peerDependentOn(fs.MpFilter, visited)
}

func asExprTemplate(e policy.ASExpr) bool {
	switch x := e.(type) {
	case policy.ASSetTemplate:
		return true
	case policy.ASExprBinary:
		return asExprTemplate(x.L) || asExprTemplate(x.R)
	}
	return false
}

func pathPeerDependent(e policy.ASPathExpr) bool {
	switch x := e.(type) {
	case policy.ASPathPeerAS, policy.ASPathSetTemplate:
		return true
	case policy.ASPathAlt:
		return slices.ContainsFunc(x.Alts, pathPeerDependent)
	case policy.ASPathSeq:
		return slices.ContainsFunc(x.Terms, pathPeerDependent)
	case policy.ASPathRepeat:
		return pathPeerDependent(x.Inner)
	case policy.ASPathClass:
		return slices.ContainsFunc(x.Items, pathPeerDependent)
	}
	return false
}

// anySets are the names that denote the whole IRR: no lookup finds them.
var anySets = map[string]bool{"AS-ANY": true, "RS-ANY": true, "RTRS-ANY": true, "PRNG-ANY": true, "FLTR-ANY": true}

// sets looks up, once each, every set an import, export or default attribute
// names directly — as-sets and peering-sets in its peerings, sets and as-sets
// in its filters — and reports the missing ones against the attribute, with
// no session: Lint finds them even when no session reaches the attribute.
// rtr-sets are routers' (below). AS-ANY and the like, and set templates, are
// not looked up.
func (l *linter) sets(ctx context.Context, c *Checker) error {
	ev := c.eval()
	missing := map[types.SetName]bool{}
	check := func(kind string, i int, names []types.SetName) error {
		for _, n := range names {
			miss, seen := missing[n]
			if !seen {
				set, err := ev.Src.GetSet(ctx, types.Ref(n))
				switch {
				case errors.Is(err, resolve.ErrNotFound):
					miss = true
				case err != nil:
					return err
				default:
					// A set whose class is not its name's is missing, as the
					// engine treats it (route-set: AS-EVIL answering AS-EVIL).
					miss = set == nil || set.Class() != n.Class().String()
				}
				missing[n] = miss
			}
			if miss {
				l.reported[setKey{kind, i, n.String()}] = true
				l.reported[setKey{kind, -1, n.String()}] = true
				l.add(RuleMissingSet, kind, i, fmt.Sprintf("the policy names %s, which is not in the source", n), 0, nil)
			}
		}
		return nil
	}
	for kind, exprs := range map[string][]policy.Expr{"import": importExprs(l.an), "export": exportExprs(l.an)} {
		for i, ex := range exprs {
			var names []types.SetName
			var walk func(policy.Expr)
			walk = func(e policy.Expr) {
				switch x := e.(type) {
				case policy.Factor:
					for _, pa := range x.Peers {
						names = peeringSets(names, pa.Peering)
					}
					names = filterSets(names, x.Filter)
				case policy.ExprList:
					for _, s := range x.Exprs {
						walk(s)
					}
				case policy.Except:
					walk(x.Left)
					walk(x.Right)
				case policy.Refine:
					walk(x.Left)
					walk(x.Right)
				}
			}
			walk(ex)
			if err := check(kind, i, names); err != nil {
				return err
			}
		}
	}
	for i, d := range l.an.Defaults {
		names := filterSets(peeringSets(nil, d.Peering), d.Networks)
		if err := check("default", i, names); err != nil {
			return err
		}
	}
	return nil
}

// peeringSets appends the as-sets and peering-set a peering names directly.
func peeringSets(out []types.SetName, p policy.Peering) []types.SetName {
	switch x := p.(type) {
	case policy.PeeringAS:
		return asExprSets(out, x.AS)
	case policy.PeeringSetRef:
		return addSet(out, x.Name)
	}
	return out
}

func asExprSets(out []types.SetName, e policy.ASExpr) []types.SetName {
	switch x := e.(type) {
	case policy.ASSetRef:
		return addSet(out, x.Name)
	case policy.ASExprBinary:
		return asExprSets(asExprSets(out, x.L), x.R)
	}
	return out
}

// filterSets appends the sets a filter names directly, outside regexps.
func filterSets(out []types.SetName, f policy.Filter) []types.SetName {
	switch x := f.(type) {
	case policy.FilterSetRef:
		return addSet(out, x.Name)
	case policy.FilterASExpr:
		return asExprSets(out, x.AS)
	case policy.FilterAnd:
		for _, t := range x.Terms {
			out = filterSets(out, t)
		}
	case policy.FilterOr:
		for _, t := range x.Terms {
			out = filterSets(out, t)
		}
	case policy.FilterNot:
		return filterSets(out, x.Inner)
	}
	return out
}

func addSet(out []types.SetName, n types.SetName) []types.SetName {
	if anySets[n.String()] || slices.Contains(out, n) {
		return out
	}
	return append(out, n)
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
