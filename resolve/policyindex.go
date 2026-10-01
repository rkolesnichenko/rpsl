package resolve

import (
	"errors"
	"iter"
	"slices"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// PolicyIndex is a PolicySource that can list its aut-nums and, for an AS,
// the aut-nums whose import, export or default peerings name it directly —
// "who names me", which no IRR query answers. A MemSource built from a
// Corpus with IndexPeers, or by NewMemSource, keeps one.
type PolicyIndex interface {
	PolicySource
	// AutNums yields every aut-num the Source serves, ascending. It is
	// ErrNoPolicy when the Source holds only some (a Corpus without
	// KeepPolicy).
	AutNums() (iter.Seq[types.ASN], error)
	// NamedBy returns the aut-nums naming as, ascending. A peering through
	// an as-set, a set template, a peering-set or a regexp is not indexed.
	// It is ErrNoIndex when the Source keeps no index (a Corpus without
	// IndexPeers).
	NamedBy(as types.ASN) ([]types.ASN, error)
}

// ErrNoIndex is a PolicyIndex's answer when it keeps no peer index.
var ErrNoIndex = errors.New("resolve: the source keeps no peer index")

var _ PolicyIndex = (*MemSource)(nil)

// peeringASNs returns the AS numbers an's import, export and default
// peerings name directly (an ASNum anywhere in a PeeringAS's AS expression,
// either side of OR, AND and EXCEPT), ascending, without an's own AS. It is
// never nil, so a caller can tell "names nothing" from "not computed".
func peeringASNs(an object.AutNum) []types.ASN {
	out := []types.ASN{}
	var asExpr func(policy.ASExpr)
	asExpr = func(e policy.ASExpr) {
		switch x := e.(type) {
		case policy.ASNum:
			if x.AS != an.AS {
				out = append(out, x.AS)
			}
		case policy.ASExprBinary:
			asExpr(x.L)
			asExpr(x.R)
		}
	}
	peering := func(p policy.Peering) {
		if x, ok := p.(policy.PeeringAS); ok {
			asExpr(x.AS)
		}
	}
	var expr func(policy.Expr)
	expr = func(e policy.Expr) {
		switch x := e.(type) {
		case policy.Factor:
			for _, pa := range x.Peers {
				peering(pa.Peering)
			}
		case policy.ExprList:
			for _, s := range x.Exprs {
				expr(s)
			}
		case policy.Except:
			expr(x.Left)
			expr(x.Right)
		case policy.Refine:
			expr(x.Left)
			expr(x.Right)
		}
	}
	for _, i := range an.Imports {
		expr(i.Expr)
	}
	for _, x := range an.Exports {
		expr(x.Expr)
	}
	for _, d := range an.Defaults {
		peering(d.Peering)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// namedFromText is peeringASNs of an aut-num kept as text.
func namedFromText(text string) []types.ASN {
	raw, _ := rpsl.ParseObject(text)
	o, _ := object.Decode(raw)
	if an, ok := value(o).(object.AutNum); ok {
		return peeringASNs(an)
	}
	return []types.ASN{}
}

// AutNums yields every aut-num s serves (a copy in a source unscoped
// lookups see), ascending; ErrNoPolicy when s serves none.
func (s *MemSource) AutNums() (iter.Seq[types.ASN], error) {
	if !s.policy {
		return nil, ErrNoPolicy
	}
	return slices.Values(s.autnumList), nil
}

// NamedBy returns the aut-nums naming as, ascending; ErrNoIndex when s keeps
// no index. Only the copy of each aut-num an unscoped lookup would return
// is read.
func (s *MemSource) NamedBy(as types.ASN) ([]types.ASN, error) {
	if !s.index {
		return nil, ErrNoIndex
	}
	return slices.Clone(s.namedBy[as]), nil
}

// buildIndex fills autnumList and, when s keeps an index, namedBy, from the
// winning copy of each aut-num. It runs in finish, after precedence order.
func (s *MemSource) buildIndex() {
	s.autnumList = s.autnumList[:0]
	if s.index {
		s.namedBy = map[types.ASN][]types.ASN{}
	} else {
		s.namedBy = nil // leave no stale index behind a second, unindexed finish
	}
	for as, es := range s.autnums {
		e, err := s.pick(es, "")
		if err != nil {
			continue
		}
		s.autnumList = append(s.autnumList, as)
		if !s.index {
			continue
		}
		named := e.named
		if named == nil {
			if an, ok := value(e.obj).(object.AutNum); ok {
				named = peeringASNs(an)
			} else if e.text != "" {
				named = namedFromText(e.text)
			}
		}
		for _, x := range named {
			s.namedBy[x] = append(s.namedBy[x], as)
		}
	}
	slices.Sort(s.autnumList)
	for x := range s.namedBy {
		slices.Sort(s.namedBy[x])
	}
}
