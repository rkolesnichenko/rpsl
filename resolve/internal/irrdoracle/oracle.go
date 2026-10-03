// Package irrdoracle holds what a real IRRd 4.5.3 answered on a fixed fixture
// (resolve/testdata/irrd): the cases, their recorded answers (goldens), and
// how to compare another server's answer with one. TestRecord re-records the
// goldens from IRRd in Docker when RPSL_IRRD_DOCKER=1; every other test reads
// them, so CI holds irrtest (Task 3) and irrdq (Tasks 4-7) to IRRd without
// running it.
//
// It is a test helper: only _test.go files import it, and it imports neither
// irrdq nor irrtest, so it can judge both.
package irrdoracle

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/types"
)

// Kind is how an answer is compared.
type Kind int

const (
	Exact   Kind = iota // the bytes must be equal
	Words               // each A-frame's payload compared as a multiset of words
	Objects             // each reply compared as a multiset of objects (Normalize)
)

func (k Kind) String() string {
	switch k {
	case Exact:
		return "exact"
	case Words:
		return "words"
	case Objects:
		return "objects"
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// Case is one exchange: what is sent on a fresh connection, under which
// IRRd configuration ("plain" or "rpki"), and how its answer is compared.
type Case struct {
	Name   string
	Config string
	Send   string
	Kind   Kind
}

// Golden is a case with what IRRd answered: every byte it wrote until it
// closed the connection, or until two seconds passed without a byte.
type Golden struct {
	Case
	Got string
}

// Fixture returns the fixture directory, resolve/testdata/irrd.
func Fixture(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("irrdoracle: no caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "irrd")
}

// The golden file format, one record per case:
//
//	=== <name> <kind>    (a name may hold spaces; the kind is the last word)
//	>>> <Send, strconv.Quote>
//	<<< <Got, strconv.Quote>

// Load reads golden/<config>.txt.
func Load(t testing.TB, config string) []Golden {
	t.Helper()
	path := filepath.Join(Fixture(t), "golden", config+".txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Golden
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var g Golden
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "=== "):
			rest := line[4:]
			sp := strings.LastIndexByte(rest, ' ')
			if sp < 0 {
				t.Fatalf("%s: %q: no kind", path, line)
			}
			name, kind := rest[:sp], rest[sp+1:]
			g = Golden{Case: Case{Name: name, Config: config}}
			switch kind {
			case "exact":
				g.Kind = Exact
			case "words":
				g.Kind = Words
			case "objects":
				g.Kind = Objects
			default:
				t.Fatalf("%s: case %s: kind %q", path, name, kind)
			}
		case strings.HasPrefix(line, ">>> "):
			s, err := strconv.Unquote(line[4:])
			if err != nil {
				t.Fatalf("%s: case %s: %v", path, g.Name, err)
			}
			g.Send = s
		case strings.HasPrefix(line, "<<< "):
			s, err := strconv.Unquote(line[4:])
			if err != nil {
				t.Fatalf("%s: case %s: %v", path, g.Name, err)
			}
			g.Got = s
			out = append(out, g)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Write writes goldens in Load's format.
func Write(path string, gs []Golden) error {
	var b strings.Builder
	for _, g := range gs {
		fmt.Fprintf(&b, "=== %s %s\n>>> %s\n<<< %s\n", g.Name, g.Kind, strconv.Quote(g.Send), strconv.Quote(g.Got))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// Split cuts an answer stream into replies: an IRRd frame (A<len>, its
// payload and its C line), a bare C, D or E line, an F line, or a RIPE-style
// answer (objects or a % line) ending in two blank lines. A frame is cut by
// its length, so a payload holding blank lines stays whole.
func Split(b string) []string {
	var out []string
	for len(b) > 0 {
		nl := strings.IndexByte(b, '\n')
		if nl < 0 {
			return append(out, b) // a fragment: kept as it is, to fail any comparison
		}
		line := b[:nl]
		switch {
		case len(line) > 1 && line[0] == 'A' && isDigits(line[1:]):
			n, err := strconv.Atoi(line[1:])
			if err != nil || n > len(b)-nl-1 {
				return append(out, b) // a length past the input: a fragment
			}
			end := nl + 1 + n
			if c := strings.IndexByte(b[end:], '\n'); c >= 0 {
				end += c + 1
			} else {
				end = len(b)
			}
			out = append(out, b[:end])
			b = b[end:]
		case line == "C" || line == "D" || line == "E" || strings.HasPrefix(line, "F ") || line == "F":
			out = append(out, b[:nl+1])
			b = b[nl+1:]
		default:
			end := strings.Index(b, "\n\n\n")
			if end < 0 {
				return append(out, b)
			}
			out = append(out, b[:end+3])
			b = b[end+3:]
		}
	}
	return out
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// Compare reports how got differs from want under k, or nil.
func Compare(k Kind, got, want string) error {
	if k == Exact {
		if got != want {
			return fmt.Errorf("got %q\nwant %q", got, want)
		}
		return nil
	}
	g, w := Split(got), Split(want)
	if len(g) != len(w) {
		return fmt.Errorf("%d replies, want %d:\n got %q\nwant %q", len(g), len(w), got, want)
	}
	for i := range g {
		var a, b []string
		if k == Words {
			a, b = words(g[i]), words(w[i])
		} else {
			a, b = objects(g[i]), objects(w[i])
		}
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			return fmt.Errorf("reply %d differs:\n got %q\nwant %q", i, g[i], w[i])
		}
	}
	return nil
}

// words is a frame's payload as words; a RIPE-style % message as its words,
// commas separating them too (IRRd lists some, such as the attributes -i can
// search, in hash order); any other reply (C, D, E, F) as one word.
func words(r string) []string {
	if p, ok := payload(r); ok {
		return strings.Fields(p)
	}
	if strings.HasPrefix(r, "%") {
		return strings.FieldsFunc(r, func(c rune) bool { return c == ',' || unicode.IsSpace(c) })
	}
	return []string{r}
}

// payload is an A-frame's payload.
func payload(r string) (string, bool) {
	nl := strings.IndexByte(r, '\n')
	if nl < 0 || r[0] != 'A' || !isDigits(r[1:nl]) {
		return "", false
	}
	n, err := strconv.Atoi(r[1:nl])
	if err != nil || n > len(r)-nl-1 {
		return "", false
	}
	return r[nl+1 : nl+1+n], true
}

// objects is a reply's objects, each Normalized; a reply holding none (C, D,
// F, a % line) is itself.
func objects(r string) []string {
	text, ok := payload(r)
	if !ok {
		if r == "C\n" || r == "D\n" || r == "E\n" || r == "F\n" || strings.HasPrefix(r, "F ") || strings.HasPrefix(r, "%") {
			return []string{r} // a status line or a % message: compared whole
		}
		text = strings.TrimSuffix(r, "\n\n")
	}
	var out []string
	for _, o := range strings.Split(strings.Trim(text, "\n"), "\n\n") {
		if o != "" {
			out = append(out, Normalize(o+"\n"))
		}
	}
	return out
}

// Normalize returns an object's canonical form for comparison: one line per
// attribute, its name lower-case, its value as the lexer folds it (comments
// stripped, continuation lines joined), every run of whitespace one space,
// no space after a comma; list attributes item by item; a route's or
// route6's key, and a route-set's prefix members, as netip prints them
// (zero padding gone, a bare address given its host length). These are the
// rewrites IRRd makes when it serves an object, so an object as loaded and
// as IRRd serves it normalize alike.
func Normalize(objText string) string {
	o, _ := rpsl.ParseObject(objText)
	if o == nil || len(o.Attributes()) == 0 {
		return objText
	}
	class := strings.ToLower(o.Class())
	var b strings.Builder
	for i, a := range o.Attributes() {
		name := strings.ToLower(a.Name)
		var items []string
		for _, it := range a.List() {
			v := strings.Join(strings.Fields(it.Value), " ")
			if i == 0 && (class == "route" || class == "route6") {
				v = canonPrefix(v)
			}
			if class == "route-set" && (name == "members" || name == "mp-members") {
				v = canonMember(v)
			}
			items = append(items, v)
		}
		fmt.Fprintf(&b, "%s:%s\n", name, strings.Join(items, ","))
	}
	return b.String()
}

func canonPrefix(s string) string {
	if p, err := types.ParsePrefix(s); err == nil {
		return p.String()
	}
	return s
}

func canonMember(s string) string {
	base, op, hasOp := strings.Cut(s, "^")
	if p, err := types.ParsePrefix(base); err == nil {
		base = p.String()
	} else if a, err := types.ParseAddr(base); err == nil {
		base = netip.PrefixFrom(a, a.BitLen()).String()
	}
	if hasOp {
		return base + "^" + op
	}
	return base
}
