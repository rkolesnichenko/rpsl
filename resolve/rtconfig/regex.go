package rtconfig

import (
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Translating an AS-path regexp (RFC 2622 §5.4) into a vendor's syntax. The
// regexp is rewritten, never matched against a path (design §13).

const (
	maxRepeat     = 32   // the most repetitions IOS's expansion of {m,n} writes
	maxClassRange = 1024 // the most ASes a class range may list
)

// translatePath renders m's regexp in g.Vendor's dialect. term names the
// regexp in errors.
func (g *Generator) translatePath(m resolve.PathMatch, term string) (string, error) {
	t := translator{v: g.Vendor, sets: m.Sets, term: term}
	switch g.Vendor {
	case Junos:
		return t.junos(m.RE.Body)
	case BIRD2:
		return t.bird(m.RE.Body)
	}
	s, err := t.ios(m.RE.Body)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(s, "$") {
		s += "_" // the last AS needs a boundary after it too
	}
	return s, nil
}

type translator struct {
	v    Vendor
	sets map[types.SetName]resolve.ASNSet
	term string
}

func (t translator) refuse(cause string) error { return unsupported(t.v, cause, "<"+t.term+">") }

// members is what one position may hold: AS numbers, or any AS (all true).
func (t translator) members(e policy.ASPathExpr) (asns []types.ASN, all bool, err error) {
	switch x := e.(type) {
	case policy.ASPathASN:
		return []types.ASN{x.AS}, false, nil
	case policy.ASPathAny:
		return nil, true, nil
	case policy.ASPathSet:
		if strings.EqualFold(x.Name.String(), "AS-ANY") {
			return nil, true, nil
		}
		s := t.sets[x.Name]
		return s.List(), false, nil
	case policy.ASPathClass:
		if x.Negated {
			return nil, false, t.refuse(CauseNegatedClass)
		}
		seen := map[types.ASN]bool{}
		for _, it := range x.Items {
			var got []types.ASN
			if r, ok := it.(policy.ASPathASNRange); ok {
				if r.Hi < r.Lo || r.Hi-r.Lo >= maxClassRange {
					return nil, false, t.refuse(CausePathShape)
				}
				for a := r.Lo; ; a++ {
					got = append(got, a)
					if a == r.Hi {
						break
					}
				}
			} else {
				as, any, err := t.members(it)
				if err != nil {
					return nil, false, err
				}
				if any {
					return nil, true, nil
				}
				got = as
			}
			for _, a := range got {
				if !seen[a] {
					seen[a] = true
					asns = append(asns, a)
				}
			}
		}
		sortASNs(asns)
		return asns, false, nil
	}
	return nil, false, t.refuse(CausePathShape)
}

func sortASNs(as []types.ASN) {
	for i := 1; i < len(as); i++ {
		for j := i; j > 0 && as[j] < as[j-1]; j-- {
			as[j], as[j-1] = as[j-1], as[j]
		}
	}
}

func num(a types.ASN) string { return strconv.FormatUint(uint64(a), 10) }

// runs groups sorted, deduplicated asns into inclusive runs: three or more
// consecutive numbers collapse into one [lo, hi] run, everything else comes
// out as a run of one (lo == hi). Junos and BIRD 2 both write a run of three
// or more as a range and everything else as a single number; they differ
// only in the range and join tokens, so both renderers share this grouping.
func runs(asns []types.ASN) [][2]types.ASN {
	var out [][2]types.ASN
	for i := 0; i < len(asns); {
		j := i
		for j+1 < len(asns) && asns[j+1] == asns[j]+1 {
			j++
		}
		if j-i >= 2 {
			out = append(out, [2]types.ASN{asns[i], asns[j]})
			i = j + 1
			continue
		}
		out = append(out, [2]types.ASN{asns[i], asns[i]})
		i++
	}
	return out
}

// singleAtom reports whether e names one position (an AS, a set, a class or
// any AS).
func singleAtom(e policy.ASPathExpr) bool {
	switch e.(type) {
	case policy.ASPathASN, policy.ASPathAny, policy.ASPathSet, policy.ASPathClass:
		return true
	}
	return false
}

// ---- IOS and IOS-XR ----

func (t translator) ios(e policy.ASPathExpr) (string, error) {
	switch x := e.(type) {
	case policy.ASPathStart:
		return "^", nil
	case policy.ASPathEnd:
		return "$", nil
	case policy.ASPathSeq:
		var b strings.Builder
		for _, term := range x.Terms {
			s, err := t.ios(term)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		return b.String(), nil
	case policy.ASPathAlt:
		parts := make([]string, len(x.Alts))
		for i, a := range x.Alts {
			s, err := t.ios(a)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "(" + strings.Join(parts, "|") + ")", nil
	case policy.ASPathRepeat:
		inner, err := t.repeatInner(x)
		if err != nil {
			return "", err
		}
		inner2, err := t.ios(inner)
		if err != nil {
			return "", err
		}
		return iosRepeat(inner2, x, t)
	}
	asns, all, err := t.members(e)
	if err != nil {
		return "", err
	}
	if all {
		return "_[0-9]+", nil
	}
	switch len(asns) {
	case 0:
		return "_0", nil
	case 1:
		return "_" + num(asns[0]), nil
	}
	parts := make([]string, len(asns))
	for i, a := range asns {
		parts[i] = num(a)
	}
	return "_(" + strings.Join(parts, "|") + ")", nil
}

// repeatInner returns what a repetition repeats, refusing same-AS repetition
// of anything but one AS number (for which ~* is plain *).
func (t translator) repeatInner(x policy.ASPathRepeat) (policy.ASPathExpr, error) {
	if x.Same {
		if _, ok := x.Inner.(policy.ASPathASN); !ok {
			return nil, t.refuse(CauseSameAS)
		}
	}
	return x.Inner, nil
}

// iosRepeat writes a repetition; IOS has *, + and ? but no {m,n}, which is
// expanded.
func iosRepeat(inner string, x policy.ASPathRepeat, t translator) (string, error) {
	g := "(" + inner + ")"
	switch x.Op {
	case policy.RepeatStar:
		return g + "*", nil
	case policy.RepeatPlus:
		return g + "+", nil
	case policy.RepeatQuest:
		return g + "?", nil
	}
	if x.Min > maxRepeat || x.Max > maxRepeat {
		return "", t.refuse(CausePathShape)
	}
	var b strings.Builder
	for i := 0; i < x.Min; i++ {
		b.WriteString(inner)
	}
	switch {
	case x.Max < 0:
		b.WriteString(g + "*")
	default:
		for i := x.Min; i < x.Max; i++ {
			b.WriteString(g + "?")
		}
	}
	return b.String(), nil
}

// ---- Junos ----

// junos renders a Junos as-path regular expression. Junos anchors it at both
// ends, so an unanchored side gets ".*", and ^ and $ may stand only at the
// ends of the top-level sequence.
func (t translator) junos(body policy.ASPathExpr) (string, error) {
	terms, start, end := topLevel(body)
	var parts []string
	for _, term := range terms {
		s, err := t.junosExpr(term)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	if !start {
		parts = append([]string{".*"}, parts...)
	}
	if !end {
		parts = append(parts, ".*")
	}
	if len(parts) == 0 {
		return "()", nil
	}
	return strings.Join(parts, " "), nil
}

// topLevel splits a regexp into its top-level terms and whether it is
// anchored at the start and at the end.
func topLevel(body policy.ASPathExpr) (terms []policy.ASPathExpr, start, end bool) {
	if seq, ok := body.(policy.ASPathSeq); ok {
		terms = append(terms, seq.Terms...)
	} else {
		terms = []policy.ASPathExpr{body}
	}
	if len(terms) > 0 {
		if _, ok := terms[0].(policy.ASPathStart); ok {
			start, terms = true, terms[1:]
		}
	}
	if len(terms) > 0 {
		if _, ok := terms[len(terms)-1].(policy.ASPathEnd); ok {
			end, terms = true, terms[:len(terms)-1]
		}
	}
	return terms, start, end
}

func (t translator) junosExpr(e policy.ASPathExpr) (string, error) {
	switch x := e.(type) {
	case policy.ASPathStart, policy.ASPathEnd:
		return "", t.refuse(CausePathShape)
	case policy.ASPathSeq:
		var parts []string
		for _, term := range x.Terms {
			s, err := t.junosExpr(term)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, " ") + ")", nil
	case policy.ASPathAlt:
		parts := make([]string, len(x.Alts))
		for i, a := range x.Alts {
			s, err := t.junosExpr(a)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "(" + strings.Join(parts, "|") + ")", nil
	case policy.ASPathRepeat:
		inner, err := t.repeatInner(x)
		if err != nil {
			return "", err
		}
		s, err := t.junosExpr(inner)
		if err != nil {
			return "", err
		}
		if strings.Contains(s, " ") && !(strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")")) {
			s = "(" + s + ")" // a quantifier binds to one atom; group anything longer
		}
		return s + quantifier(x), nil
	}
	asns, all, err := t.members(e)
	if err != nil {
		return "", err
	}
	if all {
		return ".", nil
	}
	return junosAlt(asns), nil
}

// junosAlt writes one position holding asns, runs of consecutive numbers as
// ranges.
func junosAlt(asns []types.ASN) string {
	if len(asns) == 0 {
		return "0"
	}
	var parts []string
	for _, r := range runs(asns) {
		if r[0] == r[1] {
			parts = append(parts, num(r[0]))
			continue
		}
		parts = append(parts, num(r[0])+"-"+num(r[1]))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "|") + ")"
}

func quantifier(x policy.ASPathRepeat) string {
	switch x.Op {
	case policy.RepeatStar:
		return "*"
	case policy.RepeatPlus:
		return "+"
	case policy.RepeatQuest:
		return "?"
	}
	switch {
	case x.Max < 0:
		return "{" + strconv.Itoa(x.Min) + ",}"
	case x.Max == x.Min:
		return "{" + strconv.Itoa(x.Min) + "}"
	}
	return "{" + strconv.Itoa(x.Min) + "," + strconv.Itoa(x.Max) + "}"
}

// ---- BIRD ----

// bird renders a BIRD 2 path mask: numbers, int sets, ? and *, implicitly
// anchored at both ends.
func (t translator) bird(body policy.ASPathExpr) (string, error) {
	terms, start, end := topLevel(body)
	var parts []string
	if !start {
		parts = append(parts, "*")
	}
	for _, term := range terms {
		s, err := t.birdTerm(term)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	if !end {
		parts = append(parts, "*")
	}
	if len(parts) == 0 {
		return "[= =]", nil
	}
	return "[= " + strings.Join(parts, " ") + " =]", nil
}

func (t translator) birdTerm(e policy.ASPathExpr) (string, error) {
	switch x := e.(type) {
	case policy.ASPathRepeat:
		if _, any := x.Inner.(policy.ASPathAny); any && !x.Same {
			switch x.Op {
			case policy.RepeatStar:
				return "*", nil
			case policy.RepeatPlus:
				return "? *", nil
			}
		}
		return "", t.refuse(CausePathShape)
	case policy.ASPathSeq:
		var parts []string
		for _, term := range x.Terms {
			s, err := t.birdTerm(term)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), nil
	}
	if !singleAtom(e) {
		return "", t.refuse(CausePathShape)
	}
	asns, all, err := t.members(e)
	if err != nil {
		return "", err
	}
	if all {
		return "?", nil
	}
	switch len(asns) {
	case 0:
		return "0", nil
	case 1:
		return num(asns[0]), nil
	}
	var parts []string
	for _, r := range runs(asns) {
		if r[0] == r[1] {
			parts = append(parts, num(r[0]))
			continue
		}
		parts = append(parts, num(r[0])+".."+num(r[1]))
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}
