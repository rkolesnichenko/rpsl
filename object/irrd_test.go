package object

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

const irrdSource = "testdata/irrd/rpsl_objects.py"

var (
	irrdClassDef = regexp.MustCompile(`(?m)^class (RPSL\w+)\(RPSL\w+\):`)
	irrdMapping  = regexp.MustCompile(`"([a-z0-9-]+)": (RPSL\w+),`)
	irrdField    = regexp.MustCompile(`\(\s*"([a-z0-9-]+)",\s*RPSL\w+\(`)
)

// parseIRRdClasses reads IRRd's rpsl_objects.py: for each RPSL class, its
// fields and whether each is mandatory (no optional=True) and single (no
// multiple=True).
func parseIRRdClasses(t *testing.T, src string) map[string]map[string]AttrSpec {
	t.Helper()
	bodies := map[string]string{} // Python class name -> body
	defs := irrdClassDef.FindAllStringSubmatchIndex(src, -1)
	for i, d := range defs {
		end := len(src)
		if i+1 < len(defs) {
			end = defs[i+1][0]
		}
		bodies[src[d[2]:d[3]]] = src[d[1]:end]
	}
	out := map[string]map[string]AttrSpec{}
	for _, m := range irrdMapping.FindAllStringSubmatch(src, -1) {
		class, pyClass := m[1], m[2]
		body, ok := bodies[pyClass]
		if !ok {
			t.Fatalf("no definition of %s for %s", pyClass, class)
		}
		fields := map[string]AttrSpec{}
		for _, loc := range irrdField.FindAllStringSubmatchIndex(body, -1) {
			name := body[loc[2]:loc[3]]
			args := balanced(body[loc[1]:])
			fields[name] = AttrSpec{
				Required: !strings.Contains(args, "optional=True"),
				Single:   !strings.Contains(args, "multiple=True"),
			}
		}
		if len(fields) == 0 {
			t.Fatalf("%s (%s): no fields found", class, pyClass)
		}
		out[class] = fields
	}
	return out
}

// balanced returns s up to the parenthesis that closes one already opened.
func balanced(s string) string {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// The IRRd profile is IRRd's own class tables — every attribute, whether it is
// mandatory, whether it may repeat — plus last-modified:, which IRRd ignores
// when validating and so allows anywhere, any number of times.
func TestIRRdProfileMatchesSource(t *testing.T) {
	b, err := os.ReadFile(irrdSource)
	if err != nil {
		t.Fatal(err)
	}
	src := parseIRRdClasses(t, string(b))
	if len(src) != 19 {
		t.Fatalf("%d classes in %s, want 19", len(src), irrdSource)
	}
	var classes []string
	for class, want := range src {
		classes = append(classes, class)
		want["last-modified"] = AttrSpec{}
		spec, ok := IRRd.Class(class)
		if !ok {
			t.Errorf("IRRd has no %s class", class)
			continue
		}
		if spec.AllowUnknown {
			t.Errorf("%s: IRRd tolerates attributes outside IRRd's table", class)
		}
		for name, as := range want {
			if got, ok := spec.Attrs[name]; !ok || got != as {
				t.Errorf("%s.%s: profile %+v (present %v), IRRd %+v", class, name, got, ok, as)
			}
		}
		for name := range spec.Attrs {
			if _, ok := want[name]; !ok {
				t.Errorf("%s.%s: in the profile, not in IRRd's table", class, name)
			}
		}
	}
	sort.Strings(classes)
	if got := IRRd.Classes(); !reflect.DeepEqual(got, classes) {
		t.Errorf("IRRd classes %v, IRRd's source %v", got, classes)
	}
}

// Where IRRd's tables part from RIPE's, Validate follows the profile it is
// given.
func TestIRRdValidate(t *testing.T) {
	obj := func(src string) *ast.Object { return ast.New(lexer.Tokenize(src)) }
	rules := func(p Profile, src string) string {
		var out []string
		for _, d := range p.Validate(obj(src)) {
			out = append(out, d.Rule)
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		name, src  string
		irrd, ripe string // the rules each profile raises
	}{
		{"a RADB route", "route: 192.0.2.0/24\ndescr: X\norigin: AS1\nmnt-by: MAINT-X\nchanged: a@b.net 20240101\nsource: RADB\n",
			"", "dict/unknown-attr"}, // RIPE has no changed:
		{"an aut-num without mnt-by", "aut-num: AS1\nas-name: X\nadmin-c: X1\ntech-c: X1\nsource: RADB\n",
			"", "dict/missing-required"},
		{"last-modified repeated", "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nlast-modified: 2024-01-01T00:00:00Z\nlast-modified: 2024-01-02T00:00:00Z\nsource: RADB\n",
			"", "dict/cardinality"},
		{"ARIN's created:", "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\ncreated: 2024-01-01T00:00:00Z\nsource: ARIN\n",
			"dict/unknown-attr", ""},
		{"a filter-set without filter:", "filter-set: FLTR-X\nmp-filter: ANY\nmnt-by: M\nsource: RADB\n",
			"dict/missing-required", "dict/missing-required dict/missing-required"},
		{"a poem", "poem: POEM-X\nform: FORM-X\ntext: x\nmnt-by: M\nsource: RIPE\n", "dict/unknown-class", ""},
	} {
		if got := rules(IRRd, c.src); got != c.irrd {
			t.Errorf("%s under IRRd: %q, want %q", c.name, got, c.irrd)
		}
		if got := rules(RIPE, c.src); got != c.ripe {
			t.Errorf("%s under RIPE: %q, want %q", c.name, got, c.ripe)
		}
	}
}

// The fixture is IRRd's file at its latest release, so a release that changes
// a class fails here, and the profile can follow.
func TestIRRdSourceIsCurrent(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to compare the IRRd fixture with IRRd's latest release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	get := func(url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", url, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	}
	b, err := get("https://api.github.com/repos/irrdnet/irrd/releases/latest")
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &release); err != nil || release.Tag == "" {
		t.Fatalf("latest IRRd release: %v %q", err, b)
	}
	latest, err := get("https://raw.githubusercontent.com/irrdnet/irrd/" + release.Tag + "/irrd/rpsl/rpsl_objects.py")
	if err != nil {
		t.Fatal(err)
	}
	have, err := os.ReadFile(irrdSource)
	if err != nil {
		t.Fatal(err)
	}
	if string(latest) != string(have) {
		t.Errorf("IRRd %s changed rpsl_objects.py: update %s and the IRRd profile", release.Tag, irrdSource)
	}
}
