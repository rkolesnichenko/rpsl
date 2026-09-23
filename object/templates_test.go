package object

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// template is one RIPE template as the profile should encode it.
type template struct {
	attrs map[string]AttrSpec
}

// parseTemplate reads "attr: [mandatory] [single] [...]" lines.
func parseTemplate(t *testing.T, text string) template {
	t.Helper()
	tpl := template{attrs: map[string]AttrSpec{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		tpl.attrs[name] = AttrSpec{
			Required: strings.Contains(rest, "[mandatory]"),
			Single:   strings.Contains(rest, "[single]"),
		}
	}
	return tpl
}

// The RIPE profile is exactly RIPE's own templates: every attribute, whether
// it is mandatory, and whether it may repeat. Attributes outside the template
// are flagged.
func TestRIPEProfileMatchesTemplates(t *testing.T) {
	files, _ := filepath.Glob("testdata/ripe-templates/*.txt")
	if len(files) != 21 {
		t.Fatalf("%d template files, want 21", len(files))
	}
	var classes []string
	for _, f := range files {
		class := strings.TrimSuffix(filepath.Base(f), ".txt")
		classes = append(classes, class)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want := parseTemplate(t, string(b))
		spec, ok := RIPE.Class(class)
		if !ok {
			t.Errorf("RIPE has no %s class", class)
			continue
		}
		if spec.AllowUnknown {
			t.Errorf("%s: RIPE tolerates attributes outside the template", class)
		}
		if !reflect.DeepEqual(spec.Attrs, want.attrs) {
			for name, as := range want.attrs {
				if got, ok := spec.Attrs[name]; !ok || got != as {
					t.Errorf("%s.%s: profile %+v (present %v), template %+v", class, name, got, ok, as)
				}
			}
			for name := range spec.Attrs {
				if _, ok := want.attrs[name]; !ok {
					t.Errorf("%s.%s: in the profile, not in the template", class, name)
				}
			}
		}
	}
	sort.Strings(classes)
	if got := RIPE.Classes(); !reflect.DeepEqual(got, classes) {
		t.Errorf("RIPE classes %v, templates %v", got, classes)
	}
}

// templateLine matches an attribute line of "whois -t" output, as the fixtures
// keep them.
var templateLine = regexp.MustCompile(`^[a-z0-9-]+:[ \t]*\[`)

// fetchTemplate queries whois.ripe.net for class's template (attribute lines
// only), retrying a few times because RIPE rate-limits bursts of queries.
func fetchTemplate(ctx context.Context, class string) (string, error) {
	var err error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		var out string
		if out, err = queryTemplate(ctx, class); err == nil {
			return out, nil
		}
	}
	return "", err
}

func queryTemplate(ctx context.Context, class string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "whois.ripe.net:43")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte("-t " + class + "\r\n")); err != nil {
		return "", err
	}
	var b strings.Builder
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		if line := sc.Text(); templateLine.MatchString(line) {
			b.WriteString(line + "\n")
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("no template in the response for %s", class)
	}
	return b.String(), nil
}

// TestRIPETemplatesAreCurrent is an opt-in check (RPSL_LIVE=1) that the
// fixtures still match the RIPE Database's templates. A failure means RIPE
// changed a class: refresh the fixture (testdata/ripe-templates/README.md),
// then update the RIPE profile and the typed decoder to match.
func TestRIPETemplatesAreCurrent(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to compare the templates with whois.ripe.net")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	files, _ := filepath.Glob("testdata/ripe-templates/*.txt")
	for _, f := range files {
		class := strings.TrimSuffix(filepath.Base(f), ".txt")
		want, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := fetchTemplate(ctx, class)
		if err != nil {
			t.Errorf("%s: %v", class, err)
			continue
		}
		if got != string(want) {
			t.Errorf("%s: whois.ripe.net template differs from %s:\n%s", class, f, got)
		}
	}
}

// RIPE prints a name that fills the column with no space before "[":
// "assignment-size:[optional]". A pattern that required one dropped the
// attribute from the fixtures, the profile and the live check alike.
func TestTemplateLineWithoutSpace(t *testing.T) {
	for _, line := range []string{
		"assignment-size:[optional]   [single]     [ ]",
		"status:         [mandatory]  [single]     [ ]",
	} {
		if !templateLine.MatchString(line) {
			t.Errorf("templateLine does not match %q", line)
		}
	}
	tmpl := parseTemplate(t, "status:         [mandatory]  [single]     [ ]\nassignment-size:[optional]   [single]     [ ]\n")
	if _, ok := tmpl.attrs["assignment-size"]; !ok {
		t.Errorf("parseTemplate lost assignment-size: %+v", tmpl.attrs)
	}
}
