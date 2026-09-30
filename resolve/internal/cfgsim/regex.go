package cfgsim

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/types"
)

var compiled sync.Map // Go expression → *regexp.Regexp

func compile(expr string) (*regexp.Regexp, error) {
	if re, ok := compiled.Load(expr); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	compiled.Store(expr, re)
	return re, nil
}

// MatchIOS reports whether a Cisco regexp (IOS, and IOS-XR's ios-regex)
// matches the path, written as AS numbers separated by spaces. "_" matches the
// start, the end, a space, a comma or a brace.
func MatchIOS(re string, path []types.ASN) (bool, error) {
	r, err := compile(strings.ReplaceAll(re, "_", `(?:^|$|[ ,{}])`))
	if err != nil {
		return false, err
	}
	return r.MatchString(pathString(path)), nil
}

// MatchJunos reports whether a Junos AS-path regular expression matches the
// path. Junos anchors it at both ends; its atoms are AS numbers, ranges a-b
// and ".", separated by spaces.
func MatchJunos(re string, path []types.ASN) (bool, error) {
	var b strings.Builder
	b.WriteString("^(?:")
	for i := 0; i < len(re); {
		c := re[i]
		switch {
		case c == ' ' || c == '^' || c == '$':
			i++
		case c >= '0' && c <= '9':
			j := i
			for j < len(re) && re[j] >= '0' && re[j] <= '9' {
				j++
			}
			lo, _ := strconv.ParseUint(re[i:j], 10, 32)
			hi := lo
			if j+1 < len(re) && re[j] == '-' && re[j+1] >= '0' && re[j+1] <= '9' {
				k := j + 1
				for k < len(re) && re[k] >= '0' && re[k] <= '9' {
					k++
				}
				hi, _ = strconv.ParseUint(re[j+1:k], 10, 32)
				j = k
			}
			if hi < lo {
				return false, fmt.Errorf("cfgsim: Junos range %d-%d", lo, hi)
			}
			// A range is one term matching any AS from lo through hi
			// (Junos OS Routing Policies, "AS Path Regular Expressions":
			// "term1-term2", as in "(0-65003|65005-4294967294)*", which
			// rtconfig writes). It can only ever match an AS on this path,
			// so it is the alternation of those — "<none>", which no path
			// string holds, when none is in range.
			alts := []string{"<none>"}
			for _, a := range path {
				if uint64(a) >= lo && uint64(a) <= hi {
					alts = append(alts, fmt.Sprintf("<%d>", uint32(a)))
				}
			}
			b.WriteString("(?:" + strings.Join(alts, "|") + ")")
			i = j
		case c == '.':
			b.WriteString(`(?:<[0-9]+>)`)
			i++
		case c == '(':
			b.WriteString("(?:")
			i++
		case c == '{':
			j := strings.IndexByte(re[i:], '}')
			if j < 0 {
				return false, fmt.Errorf("cfgsim: Junos %q: unclosed {", re)
			}
			b.WriteString(re[i : i+j+1])
			i += j + 1
		case strings.IndexByte(")|*+?", c) >= 0:
			b.WriteByte(c)
			i++
		default:
			return false, fmt.Errorf("cfgsim: Junos %q: unexpected %q", re, c)
		}
	}
	b.WriteString(")$")
	r, err := compile(b.String())
	if err != nil {
		return false, err
	}
	var p strings.Builder
	for _, a := range path {
		fmt.Fprintf(&p, "<%d>", uint32(a))
	}
	return r.MatchString(p.String()), nil
}

// birdToken is one element of a BIRD path mask: any run (*), any one AS (?),
// or one AS from the listed ranges.
type birdToken struct {
	star, any bool
	ranges    [][2]uint64
}

// MatchBIRD reports whether a BIRD path mask "[= … =]" matches the path. The
// mask covers the whole path.
func MatchBIRD(mask string, path []types.ASN) (bool, error) {
	m := strings.TrimSpace(mask)
	if !strings.HasPrefix(m, "[=") || !strings.HasSuffix(m, "=]") {
		return false, fmt.Errorf("cfgsim: BIRD mask %q", mask)
	}
	body := strings.TrimSpace(m[2 : len(m)-2])
	var toks []birdToken
	for body != "" {
		var tok birdToken
		switch {
		case body[0] == '*':
			tok.star, body = true, body[1:]
		case body[0] == '?':
			tok.any, body = true, body[1:]
		case body[0] == '[':
			end := strings.IndexByte(body, ']')
			if end < 0 {
				return false, fmt.Errorf("cfgsim: BIRD mask %q: unclosed set", mask)
			}
			for _, el := range strings.Split(body[1:end], ",") {
				r, err := birdRange(strings.TrimSpace(el))
				if err != nil {
					return false, err
				}
				tok.ranges = append(tok.ranges, r)
			}
			body = body[end+1:]
		default:
			end := strings.IndexByte(body, ' ')
			if end < 0 {
				end = len(body)
			}
			r, err := birdRange(body[:end])
			if err != nil {
				return false, err
			}
			tok.ranges, body = [][2]uint64{r}, body[end:]
		}
		toks = append(toks, tok)
		body = strings.TrimSpace(body)
	}
	// memo[i][j]: tokens from i match path from j.
	memo := map[[2]int]bool{}
	var match func(i, j int) bool
	match = func(i, j int) bool {
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v
		}
		var v bool
		switch {
		case i == len(toks):
			v = j == len(path)
		case toks[i].star:
			v = match(i+1, j) || j < len(path) && match(i, j+1)
		case j == len(path):
			v = false
		case toks[i].any:
			v = match(i+1, j+1)
		default:
			a := uint64(path[j])
			for _, r := range toks[i].ranges {
				if a >= r[0] && a <= r[1] {
					v = match(i+1, j+1)
					break
				}
			}
		}
		memo[key] = v
		return v
	}
	return match(0, 0), nil
}

func birdRange(s string) ([2]uint64, error) {
	lo, hi, isRange := strings.Cut(s, "..")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
	if err != nil {
		return [2]uint64{}, fmt.Errorf("cfgsim: BIRD mask element %q", s)
	}
	if !isRange {
		return [2]uint64{a, a}, nil
	}
	b, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
	if err != nil || b < a {
		return [2]uint64{}, fmt.Errorf("cfgsim: BIRD mask element %q", s)
	}
	return [2]uint64{a, b}, nil
}
