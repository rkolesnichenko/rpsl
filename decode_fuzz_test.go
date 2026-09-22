package rpsl

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// FuzzDecode: Decode and Validate never panic, keep the object they were given,
// point every diagnostic inside it, and are deterministic. An object that
// decodes without Errors decodes the same — typed values and diagnostic rules —
// after changes RPSL does not give meaning to: '+' continuation lines,
// attribute-name case, trailing spaces, CRLF line endings.
func FuzzDecode(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(corpusDir, "*.txt"))
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for o := range Parse(strings.NewReader(string(b))) {
			f.Add(o.String(), uint8(0))
		}
	}
	for _, s := range []string{
		"route: 91.207.181.0/24\n+\norigin: AS1\nmember-of: RS-X, RS-Y\nmnt-by: M\nsource: RIPE\n",
		"aut-num: AS1\nimport: from AS2 action pref=10; accept {192.0.2.0/24^+} AND NOT <^AS3$>\nexport: to AS2 announce AS-X\n",
		"route-set: RS-X\nmembers: 192.0.2.0/24^+, AS1^24, RS-Y^-\nmp-members: 2001:db8::/32\nmbrs-by-ref: ANY\n",
		"inetnum: 192.0.2.0 - 192.0.2.255\nnetname: X\ncountry: NL\nadmin-c: X1-RIPE\nstatus: ASSIGNED PA\n",
		"filter-set: FLTR-X\nfilter: community == {1:2} OR community.contains(3:4)\n",
	} {
		f.Add(s, uint8(1))
	}
	addrs := regexp.MustCompile(`0x[0-9a-f]+`)
	typed := func(src string) (string, []string, bool) {
		raw, _ := ParseObject(src)
		obj, ds := Decode(raw)
		clean := true
		var rules []string
		for _, d := range ds {
			rules = append(rules, d.Rule+"/"+d.Severity.String())
			clean = clean && d.Severity < Error
		}
		return addrs.ReplaceAllString(fmt.Sprintf("%T %+v", obj, obj), "0x"), rules, clean
	}
	f.Fuzz(func(t *testing.T, src string, variant uint8) {
		raw, lexDiags := ParseObject(src)
		obj, ds := Decode(raw)
		if obj == nil || obj.Raw() != raw {
			t.Fatalf("Decode(%q) = %#v, which does not keep its object", src, obj)
		}
		all := append(append([]Diagnostic(nil), lexDiags...), ds...)
		all = append(all, Validate(raw, RIPE)...)
		all = append(all, Validate(raw, RFCStrict)...)
		for _, d := range all {
			sp := d.Span
			if sp.StartByte < 0 || sp.EndByte > len(src) || sp.StartByte > sp.EndByte || sp.StartLine < 0 {
				t.Fatalf("%q: diagnostic %v points outside the object", src, d)
			}
		}
		if again, ds2 := Decode(raw); !reflect.DeepEqual(obj, again) || !reflect.DeepEqual(ds, ds2) {
			t.Fatalf("%q: Decode is not deterministic", src)
		}

		want, wantRules, clean := typed(src)
		if !clean || strings.ContainsAny(src, "\r") {
			return
		}
		for v := range uint8(4) {
			v = (v + variant) % 4
			got, gotRules, _ := typed(rewrite(src, v))
			if got != want || !reflect.DeepEqual(gotRules, wantRules) {
				t.Fatalf("rewrite %d of %q:\n%q\ndecodes to %s %v\nnot %s %v", v, src, rewrite(src, v), got, gotRules, want, wantRules)
			}
		}
	})
}

// rewrite changes src in a way RPSL gives no meaning to: 0 adds a '+'
// continuation line to every attribute, 1 upper-cases attribute names, 2 adds
// trailing spaces to attribute lines, 3 uses CRLF line endings.
func rewrite(src string, variant uint8) string {
	var b strings.Builder
	for _, tk := range lexer.Tokenize(src) {
		if tk.Kind != lexer.KindAttribute {
			b.WriteString(tk.Raw)
			continue
		}
		raw := tk.Raw
		switch variant {
		case 0:
			if !strings.HasSuffix(raw, "\n") {
				raw += "\n"
			}
			raw += "+\n"
		case 1:
			i := strings.IndexByte(raw, ':')
			raw = strings.ToUpper(raw[:i]) + raw[i:]
		case 2:
			lines := strings.SplitAfter(raw, "\n")
			for i, l := range lines {
				if body, ok := strings.CutSuffix(l, "\n"); ok {
					lines[i] = body + "  \n"
				} else if l != "" {
					lines[i] = l + "  "
				}
			}
			raw = strings.Join(lines, "")
		}
		b.WriteString(raw)
	}
	if variant == 3 {
		return strings.ReplaceAll(b.String(), "\n", "\r\n")
	}
	return b.String()
}
