package consist

import (
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
// AS (every longer path contains a one-AS window). Anchors make the match
// depend on position, so any regexp holding one is not counted.
func rejectsEveryPath(p resolve.PathMatch) bool {
	if p.RE == nil || p.RE.Body == nil || hasAnchor(p.RE.Body) {
		return false
	}
	return nullable(p.RE.Body) || onesAll(p.RE.Body, p.Sets)
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
