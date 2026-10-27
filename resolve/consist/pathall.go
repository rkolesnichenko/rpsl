package consist

import (
	"slices"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// rejectsEveryPath reports whether the AS-path test p, read as the filter
// "NOT p", rejects every route with a non-empty path: p matches every such
// path. The answer comes from the syntax tree alone; no path is ever matched.
//
// An unanchored regexp matches every non-empty path exactly when it is
// nullable (it matches the empty string anywhere) or matches every path of one
// AS (every longer path contains a one-AS window). The same holds with one
// anchor: ^R matches a path when some prefix of it is in R, every non-empty
// path has the empty prefix and its first AS alone, and a one-AS path has no
// other prefix; R$ is the mirror case. A regexp anchored at both ends asks
// whether the whole path is in R, which this does not decide, so it is not
// counted, nor is one with an anchor anywhere else. A top-level alternation
// rejects every path when one of its branches, read as a regexp, does.
func rejectsEveryPath(p resolve.PathMatch) bool {
	if p.RE == nil || p.RE.Body == nil {
		return false
	}
	if alt, ok := p.RE.Body.(policy.ASPathAlt); ok {
		return slices.ContainsFunc(alt.Alts, func(b policy.ASPathExpr) bool { return everyPath(b, p.Sets) })
	}
	return everyPath(p.RE.Body, p.Sets)
}

// everyPath reports whether e, read as a whole regexp, matches every non-empty
// path: one leading '^' and one trailing '$' are taken off its terms, and what
// is left must hold no anchor and be nullable or match every one-AS path.
func everyPath(e policy.ASPathExpr, sets map[types.SetName]resolve.ASNSet) bool {
	ts := []policy.ASPathExpr{e}
	if seq, ok := e.(policy.ASPathSeq); ok {
		ts = seq.Terms
	}
	left := len(ts) > 0 && ts[0] == policy.ASPathExpr(policy.ASPathStart{})
	if left {
		ts = ts[1:]
	}
	right := len(ts) > 0 && ts[len(ts)-1] == policy.ASPathExpr(policy.ASPathEnd{})
	if right {
		ts = ts[:len(ts)-1]
	}
	if left && right {
		return false
	}
	var rest policy.ASPathExpr = policy.ASPathSeq{Terms: ts}
	if len(ts) == 1 {
		rest = ts[0]
	}
	// This check never changes an answer, since nullable and onesAll treat an
	// anchor as an atom that matches nothing; it keeps the safety argument local.
	if hasAnchor(rest) {
		return false
	}
	return nullable(rest) || onesAll(rest, sets)
}

// hasAnchor reports whether e holds a '^' or '$' anywhere.
func hasAnchor(e policy.ASPathExpr) bool {
	switch e := e.(type) {
	case policy.ASPathStart, policy.ASPathEnd:
		return true
	case policy.ASPathAlt:
		for _, a := range e.Alts {
			if hasAnchor(a) {
				return true
			}
		}
	case policy.ASPathSeq:
		for _, t := range e.Terms {
			if hasAnchor(t) {
				return true
			}
		}
	case policy.ASPathRepeat:
		return hasAnchor(e.Inner)
	case policy.ASPathClass:
		for _, it := range e.Items {
			if hasAnchor(it) {
				return true
			}
		}
	case policy.ASPathAny, policy.ASPathASN, policy.ASPathSet, policy.ASPathSetTemplate,
		policy.ASPathPeerAS, policy.ASPathASNRange:
	}
	return false
}

// nullable reports whether e matches the empty string.
func nullable(e policy.ASPathExpr) bool {
	switch e := e.(type) {
	case policy.ASPathAlt:
		for _, a := range e.Alts {
			if nullable(a) {
				return true
			}
		}
		return false
	case policy.ASPathSeq:
		for _, t := range e.Terms {
			if !nullable(t) {
				return false
			}
		}
		return true
	case policy.ASPathRepeat:
		return e.Min == 0 || nullable(e.Inner)
	case policy.ASPathAny, policy.ASPathASN, policy.ASPathSet, policy.ASPathSetTemplate,
		policy.ASPathPeerAS, policy.ASPathASNRange, policy.ASPathClass,
		policy.ASPathStart, policy.ASPathEnd:
		return false
	}
	return false
}

// onesAll reports whether e matches every path of exactly one AS.
func onesAll(e policy.ASPathExpr, sets map[types.SetName]resolve.ASNSet) bool {
	switch e := e.(type) {
	case policy.ASPathAny:
		return true
	case policy.ASPathSet:
		if e.Name.IsAny() {
			return true
		}
		s, ok := sets[e.Name]
		return ok && s.Any()
	case policy.ASPathClass:
		if e.Negated {
			return false
		}
		for _, it := range e.Items {
			if onesAll(it, sets) {
				return true
			}
		}
		return false
	case policy.ASPathAlt:
		for _, a := range e.Alts {
			if onesAll(a, sets) {
				return true
			}
		}
		return false
	case policy.ASPathSeq:
		// One term matches the single AS and every other term can match the empty path.
		for i, t := range e.Terms {
			if !onesAll(t, sets) {
				continue
			}
			rest := true
			for j, u := range e.Terms {
				if j != i && !nullable(u) {
					rest = false
					break
				}
			}
			if rest {
				return true
			}
		}
		return false
	case policy.ASPathRepeat:
		return e.Min <= 1 && (e.Max == -1 || e.Max >= 1) && onesAll(e.Inner, sets)
	case policy.ASPathASN, policy.ASPathASNRange, policy.ASPathSetTemplate, policy.ASPathPeerAS,
		policy.ASPathStart, policy.ASPathEnd:
		return false
	}
	return false
}
