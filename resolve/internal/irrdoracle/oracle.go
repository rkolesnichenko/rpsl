// Package irrdoracle holds what a real IRRd 4.5.3 answered on a fixed fixture
// (resolve/testdata/irrd): the cases, their recorded answers (goldens), and
// how to compare another server's answer with one. TestRecord re-records the
// goldens from IRRd in Docker when RPSL_IRRD_DOCKER=1; every other test reads
// them, so CI holds irrtest (the library's in-process IRRd) and irrdq (the
// server rpsld runs) to IRRd without running it.
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
//
// Under Words and Objects only order is relaxed: the words of a frame (or of
// a % message), or the objects of an answer, may come in any order. Everything
// else about each reply is compared exactly: its shape (an A-frame, a bare
// C/D/E/F status line, RIPE-style text), a frame's status line after its
// payload (which also holds its A<n> header to its payload: a wrong length
// moves bytes into or out of that line), the whitespace between words, and
// the blank lines before, between and after objects, the terminator included.
// An Objects frame's A<n> may differ from want's, since object text is
// compared through Normalize, not byte for byte.
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
		ge, a := reply(k, g[i])
		we, b := reply(k, w[i])
		if ge != we {
			return fmt.Errorf("reply %d's form differs (%s, want %s):\n got %q\nwant %q", i, ge, we, g[i], w[i])
		}
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			return fmt.Errorf("reply %d differs:\n got %q\nwant %q", i, g[i], w[i])
		}
	}
	return nil
}

// reply splits one reply into its form, compared exactly, and its content,
// compared as a multiset.
func reply(k Kind, r string) (form string, content []string) {
	if hdr, p, trailer, ok := frameParts(r); ok {
		if k == Objects {
			// The header is not compared: IRRd re-renders object text.
			form, content = objectsOf(p)
			return "frame " + form + " status " + strconv.Quote(trailer), content
		}
		form, content = tokens(p, unicode.IsSpace)
		return "frame " + strconv.Quote(hdr) + " " + form + " status " + strconv.Quote(trailer), content
	}
	switch {
	case r == "C\n" || r == "D\n" || r == "E\n" || r == "F\n" || strings.HasPrefix(r, "F "):
		return "status " + strconv.Quote(r), nil
	case headerLine(r), !strings.HasSuffix(r, "\n"):
		// A frame cut short, or text with no line end: compared whole.
		return "raw " + strconv.Quote(r), nil
	case strings.HasPrefix(r, "%"):
		if k == Words {
			// IRRd lists some things (the attributes -i can search) in hash
			// order, comma-separated.
			form, content = tokens(r, func(c rune) bool { return c == ',' || unicode.IsSpace(c) })
			return "message " + form, content
		}
		return "message " + strconv.Quote(r), nil
	case k == Objects:
		form, content = objectsOf(r)
		return "text " + form, content
	}
	return "raw " + strconv.Quote(r), nil
}

// frameParts cuts an A-frame reply into its header line, its payload and
// what follows the payload (its status line).
func frameParts(r string) (hdr, payload, trailer string, ok bool) {
	nl := strings.IndexByte(r, '\n')
	if nl < 2 || r[0] != 'A' || !isDigits(r[1:nl]) {
		return "", "", "", false
	}
	n, err := strconv.Atoi(r[1:nl])
	if err != nil || n > len(r)-nl-1 {
		return "", "", "", false
	}
	return r[:nl+1], r[nl+1 : nl+1+n], r[nl+1+n:], true
}

// headerLine reports whether r's first line is an A<n> header.
func headerLine(r string) bool {
	line, _, _ := strings.Cut(r, "\n")
	return len(line) > 1 && line[0] == 'A' && isDigits(line[1:])
}

// tokens cuts s into the tokens between separator runs. Its form is the
// separators: the leading and trailing runs in place, the inner runs sorted
// (tokens may be reordered, and the separators between them with them).
func tokens(s string, sep func(rune) bool) (form string, toks []string) {
	var seps []string
	start, inTok := 0, false
	runStart := 0
	for i, c := range s {
		if sep(c) {
			if inTok {
				toks = append(toks, s[start:i])
				inTok = false
				runStart = i
			}
			continue
		}
		if !inTok {
			seps = append(seps, s[runStart:i])
			start, inTok = i, true
		}
	}
	if inTok {
		toks = append(toks, s[start:])
		seps = append(seps, "")
	} else {
		seps = append(seps, s[runStart:])
	}
	// seps[0] leads, the last one trails; with no token, s is all one run.
	if len(toks) == 0 {
		return "seps " + strconv.Quote(s), nil
	}
	lead, trail, inner := seps[0], seps[len(seps)-1], slices.Clone(seps[1:len(seps)-1])
	slices.Sort(inner)
	return fmt.Sprintf("lead %q trail %q inner %q", lead, trail, inner), toks
}

// objectsOf cuts text into objects, at runs of two or more newlines, each
// object Normalized. Its form is the newline runs: the leading and trailing
// ones in place, those between objects sorted.
func objectsOf(text string) (form string, objs []string) {
	lead := len(text) - len(strings.TrimLeft(text, "\n"))
	if lead == len(text) {
		return fmt.Sprintf("newlines %d", lead), nil
	}
	trail := len(text) - len(strings.TrimRight(text, "\n"))
	mid := text[lead : len(text)-trail]
	var seps []int
	for {
		i := strings.Index(mid, "\n\n")
		if i < 0 {
			objs = append(objs, Normalize(mid+"\n"))
			break
		}
		objs = append(objs, Normalize(mid[:i+1]))
		j := i
		for j < len(mid) && mid[j] == '\n' {
			j++
		}
		seps = append(seps, j-i)
		mid = mid[j:]
	}
	slices.Sort(seps)
	return fmt.Sprintf("lead %d trail %d between %v", lead, trail, seps), objs
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
