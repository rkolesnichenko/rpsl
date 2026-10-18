package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/types"
)

var fuzzTexts = []string{
	"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
	"route: 10.2.0.0/16\norigin: AS65002\nsource: TEST\n",
	"route6: 2001:db8:1::/48\norigin: AS65001\nsource: TEST\n",
	"as-set: AS-A\nmembers: AS65001, AS65002\nsource: TEST\n",
	"route-set: RS-B\nmembers: 10.9.0.0/16^+, AS-A\nsource: TEST\n",
	"filter-set: FLTR-RE\nfilter: AS-A AND <^AS65001>\nsource: TEST\n",
	"filter-set: FLTR-LOOP\nfilter: <AS65001> OR FLTR-LOOP\nsource: TEST\n",
	"as-set: AS-REACH\nmembers: AS-A, AS-ANY\nsource: TEST\n",
	"route-set: RS-REACH\nmembers: AS-REACH^24, 10.9.0.0/16\nsource: TEST\n",
}

var fuzzRoutes = func() []routemodel.Route {
	var out []routemodel.Route
	for _, p := range []string{"10.1.0.0/16", "10.1.2.0/24", "10.2.0.0/16", "10.9.1.0/24", "192.0.2.0/24", "2001:db8:1::/48", "0.0.0.0/0"} {
		for _, path := range [][]types.ASN{{65001}, {65002, 65001}, {65003, 65002}, {65001, 65001, 65003}} {
			for _, cs := range [][]string{nil, {"1:1"}, {"1:1", "no_export"}} {
				out = append(out, routemodel.Route{Prefix: netip.MustParsePrefix(p), Path: path, Communities: cs})
			}
		}
	}
	return out
}()

// FuzzNormalizeFilter: NormalizeFilter never panics, keeps within its caps,
// and its String() reads back to a filter accepting the same routes. A filter
// that names sets only inside AS-path regexps is never an *AnySetError: there
// a set reaching AS-ANY (AS-REACH) is every AS.
func FuzzNormalizeFilter(f *testing.F) {
	for _, s := range []string{
		"ANY", "NOT ANY", "AS65001 AND <^AS65001 .* $>", "(<AS-A> OR community(1:1)) AND NOT {10.0.0.0/8^+}",
		"FLTR-RE", "FLTR-LOOP", "PeerAS^+", "NOT (AS-A OR RS-B)", "<[AS65001 - AS65003]~* $>",
		"community == {1:1, 1:2}", "RS-B^24-32 AND NOT <AS65002>", "AS-ANY",
		"<[^AS65001 AS65002]>", "<AS65001~+ AS65002~{1,2}>",
		"CommunitY(>)", // an error: its recovered test's argument holds a stray '>'
		"<AS-REACH>", "NOT <AS-REACH>", "<[^AS-REACH]>", "AS-REACH", "RS-REACH AND {10.0.0.0/8^+}",
	} {
		f.Add(s)
	}
	var objs []object.Object
	for _, s := range fuzzTexts {
		raw, _ := rpsl.ParseObject(s)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	src := resolve.NewMemSource(objs)
	memo := resolve.NewFilterMemo(1 << 14)
	f.Fuzz(func(t *testing.T, s string) {
		pf, parsed := policy.ParseFilter(s)
		// The memo answers as NormalizeFilter does, for any parse, clean or
		// not, with answers stored from earlier inputs.
		for _, peer := range []types.ASN{0, 65002} {
			plain := resolve.Expander{Src: src, Peer: peer, MaxConjuncts: 64, MaxPrefixes: 1 << 12, MaxVisited: 1 << 12}
			withMemo := plain
			withMemo.Memo = memo
			mctx, mcancel := context.WithTimeout(context.Background(), 2*time.Second)
			want, werr := plain.NormalizeFilter(mctx, pf)
			got, gerr := withMemo.NormalizeFilter(mctx, pf)
			late := mctx.Err() != nil
			mcancel()
			if !late && (fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String()) {
				t.Fatalf("%q peer %d: memo %q %v, plain %q %v", s, peer, got, gerr, want, werr)
			}
		}
		for _, d := range parsed {
			if d.Severity >= ast.Error {
				return // only clean parses have a meaning to preserve
			}
		}
		e := &resolve.Expander{Src: src, Peer: 65002, MaxConjuncts: 64, MaxPrefixes: 1 << 12, MaxVisited: 1 << 12}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		nf, err := e.NormalizeFilter(ctx, pf)
		var anyErr *resolve.AnySetError
		if errors.As(err, &anyErr) && !setRefOutsideRegexp(pf) {
			t.Fatalf("%q: %v, though it names sets only in AS-path regexps", s, err)
		}
		if err != nil {
			return
		}
		if len(nf.Conjuncts) > 64 {
			t.Fatalf("%q: %d conjuncts, over MaxConjuncts", s, len(nf.Conjuncts))
		}
		back, diags := policy.ParseFilter(nf.String())
		for _, d := range diags {
			if d.Severity >= ast.Error {
				t.Fatalf("%q: normal form %q does not parse: %v", s, nf, d)
			}
		}
		again, err := e.NormalizeFilter(ctx, back)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			t.Fatalf("%q: normal form %q does not normalize: %v", s, nf, err)
		}
		for _, rt := range fuzzRoutes {
			a, err1 := routemodel.Match(nf, rt)
			b, err2 := routemodel.Match(again, rt)
			// routemodel declines rather than guesses on two constructs with no
			// modelable meaning: a repetition count Go's regexp can't compile,
			// and a same-AS repetition ("~*"/"~+"/"~{m,n}") whose inner atom is
			// itself already a repeat (e.g. a quantifier chained onto another,
			// "AS1*~{2}") — RFC 2622 §5.4's "same AS" only means something when
			// every repetition fills in one AS number.
			if errors.Is(err1, routemodel.ErrTooComplex) || errors.Is(err2, routemodel.ErrTooComplex) ||
				errors.Is(err1, routemodel.ErrNotSingleAS) || errors.Is(err2, routemodel.ErrNotSingleAS) {
				return
			}
			if err1 != nil || err2 != nil || a != b {
				t.Fatalf("%q: route %v: %s accepts %v (%v), read back %v (%v)", s, rt, nf, a, err1, b, err2)
			}
		}
	})
}

// setRefOutsideRegexp reports whether f names a set — an as-set, route-set or
// filter-set, or a template of one — anywhere but inside an AS-path regexp, or
// holds a node it does not know.
func setRefOutsideRegexp(f policy.Filter) bool {
	switch x := f.(type) {
	case nil, policy.FilterAny, policy.FilterPeerAS, policy.FilterPrefixList,
		policy.FilterPathRE, policy.FilterCommunity:
		return false
	case policy.FilterASExpr:
		return asExprNamesSet(x.AS)
	case policy.FilterAnd:
		for _, t := range x.Terms {
			if setRefOutsideRegexp(t) {
				return true
			}
		}
		return false
	case policy.FilterOr:
		for _, t := range x.Terms {
			if setRefOutsideRegexp(t) {
				return true
			}
		}
		return false
	case policy.FilterNot:
		return setRefOutsideRegexp(x.Inner)
	}
	return true // FilterSetRef, FilterSetTemplate, or a node unknown here
}

// asExprNamesSet reports whether an AS expression names an as-set or a
// template of one, or holds a node it does not know.
func asExprNamesSet(e policy.ASExpr) bool {
	switch x := e.(type) {
	case nil, policy.ASNum:
		return false
	case policy.ASExprBinary:
		return asExprNamesSet(x.L) || asExprNamesSet(x.R)
	}
	return true
}
