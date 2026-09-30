package rtconfig

import (
	"errors"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// plan is one session direction's policy in vendor-neutral form: one entry
// per conjunct of each clause, in specification order, each with what the
// clause sets. A route takes the first entry it matches; one matching none is
// refused.
type plan struct {
	family  types.AFI
	entries []entry
}

type entry struct {
	clause int         // the clause's index in the Policy
	term   string      // the clause's term, for comments
	prefix *prefixCond // nil: no prefix condition
	paths  []pathCond
	comm   commCond
	ops    setOps
}

// prefixCond: the route lies in no deny range, and in a permit range — any
// prefix of the family when any.
type prefixCond struct {
	deny   []types.PrefixRange
	permit []types.PrefixRange
	any    bool
}

// pathCond is one AS-path test, in the vendor's dialect.
type pathCond struct {
	negated bool
	re      string
}

// commCond is a conjunct's community tests. all: the route carries every one
// (the positive community(…) tests, merged). none: for each negated one, the
// route does not carry all of its values. equal (when hasEqual): the route
// carries exactly these. notEqual: for each, the route does not carry exactly
// these.
type commCond struct {
	all      []community
	none     [][]community
	equal    []community
	hasEqual bool
	notEqual [][]community
}

func (c commCond) empty() bool {
	return len(c.all) == 0 && len(c.none) == 0 && !c.hasEqual && len(c.notEqual) == 0
}

var errFamily = errors.New("rtconfig: a session's family is ipv4 or ipv6")

// compile turns a session's Policy into a plan for g.Vendor, refusing — before
// anything is written — whatever the vendor cannot express.
func (g *Generator) compile(s peval.Session, p peval.Policy) (plan, error) {
	pl := plan{family: s.AF.AFI}
	if s.AF.SAFI == types.SAFIMulticast {
		return pl, unsupported(g.Vendor, CauseSAFI, s.AF.String())
	}
	if pl.family != types.AFIv4 && pl.family != types.AFIv6 {
		return pl, errFamily
	}
	for i, c := range p.Clauses {
		term := c.Term.String()
		if c.Remote != nil {
			return pl, unsupported(g.Vendor, CauseVia, term)
		}
		ops, err := g.compileActions(c.Actions, term)
		if err != nil {
			return pl, err
		}
		for _, conj := range c.Filter.Conjuncts {
			e, err := g.compileConjunct(conj, term)
			if err != nil {
				return pl, err
			}
			e.clause, e.term, e.ops = i, term, ops
			pl.entries = append(pl.entries, e)
		}
	}
	return pl, nil
}

// compileConjunct turns one conjunct into an entry's conditions.
func (g *Generator) compileConjunct(c resolve.Conjunct, term string) (entry, error) {
	var e entry
	if !c.AnyPrefix() || c.NotPrefixes.Len() > 0 {
		pc := &prefixCond{deny: c.NotPrefixes.List(), any: c.AnyPrefix()}
		if !pc.any {
			pc.permit = c.Prefixes.List()
		}
		e.prefix = pc
	}
	positive := 0
	for _, m := range c.Paths {
		re, err := g.translatePath(m, m.RE.String())
		if err != nil {
			return e, err
		}
		if !m.Negated {
			positive++
		}
		e.paths = append(e.paths, pathCond{negated: m.Negated, re: re})
	}
	if positive > 1 && !g.supports(FeatureTwoPaths) {
		return e, unsupported(g.Vendor, CauseTwoPaths, term)
	}
	for _, m := range c.Communities {
		cs, err := g.parseCommunities(m.Test.Values, m.Test.String())
		if err != nil {
			return e, err
		}
		switch {
		case m.Test.Op == policy.CommunityContains && !m.Negated:
			e.comm.all = union(e.comm.all, cs)
		case m.Test.Op == policy.CommunityContains:
			e.comm.none = append(e.comm.none, cs)
		case m.Negated:
			e.comm.notEqual = append(e.comm.notEqual, cs)
		case e.comm.hasEqual:
			return e, unsupported(g.Vendor, CauseCommunityEquals, term) // two exact matches
		default:
			e.comm.equal, e.comm.hasEqual = cs, true
		}
	}
	mixed := len(e.comm.notEqual) > 0 || e.comm.hasEqual && (len(e.comm.all) > 0 || len(e.comm.none) > 0) ||
		e.comm.hasEqual && len(e.comm.equal) == 0 // "community == {}": no community at all
	switch {
	case e.comm.hasEqual && !g.supports(FeatureCommunityEquals),
		mixed && !g.supports(FeatureCommunityEqualsMixed):
		return e, unsupported(g.Vendor, CauseCommunityEquals, term)
	}
	return e, nil
}
