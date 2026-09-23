package rpsl

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rkolesnichenko/rpsl/policy"
)

// docs/diagnostics.md is a contract: every rule the library emits is listed
// there with its severity, and every row is something the library emits.

// ruleRow is one row of docs/diagnostics.md: the rules it covers and the
// severities it allows.
type ruleRow struct {
	patterns []*regexp.Regexp
	text     string
	severity string
	seen     bool
}

func readRuleRows(t *testing.T) []*ruleRow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("docs", "diagnostics.md"))
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]bool{}
	attrs := map[string]bool{}
	for _, p := range []Profile{RIPE, RFCStrict} {
		for _, c := range p.Classes() {
			classes[c] = true
			spec, _ := p.Class(c)
			for a := range spec.Attrs {
				attrs[a] = true
			}
		}
	}
	alt := func(set map[string]bool) string {
		var names []string
		for n := range set {
			names = append(names, regexp.QuoteMeta(n))
		}
		sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
		return "(?:" + strings.Join(names, "|") + ")"
	}
	classAlt, attrAlt := alt(classes), alt(attrs)
	code := regexp.MustCompile("`([^`]+)`")
	var rows []*ruleRow
	for _, line := range strings.Split(string(b), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			continue
		}
		row := &ruleRow{text: strings.TrimSpace(cells[1]), severity: cells[2]}
		prev := ""
		for _, m := range code.FindAllStringSubmatch(cells[1], -1) {
			pat := m[1]
			if strings.HasPrefix(pat, "-") { // "-mp-members": a suffix for the pattern before
				pat = prev[:strings.Index(prev, "<class>")+len("<class>")] + pat
			}
			prev = pat
			re := regexp.QuoteMeta(pat)
			re = strings.ReplaceAll(re, "<class>", classAlt)
			re = strings.ReplaceAll(re, "<attr>", attrAlt)
			row.patterns = append(row.patterns, regexp.MustCompile("^"+re+"$"))
		}
		rows = append(rows, row)
	}
	return rows
}

func TestDiagnosticRulesAreDocumented(t *testing.T) {
	obj := func(src string) func() []Diagnostic {
		return func() []Diagnostic {
			raw, ds := ParseObject(src)
			_, dec := Decode(raw)
			ds = append(ds, dec...)
			ds = append(ds, Validate(raw, RIPE)...)
			return append(ds, Validate(raw, RFCStrict)...)
		}
	}
	stream := func(r io.Reader, opts ParseOptions) func() []Diagnostic {
		return func() []Diagnostic {
			var out []Diagnostic
			for _, ds := range ParseWith(r, opts) {
				out = append(out, ds...)
			}
			return out
		}
	}
	imp := func(v string) func() []Diagnostic { return obj("aut-num: AS1\nimport: " + v + "\n") }
	pol := func(parse func(string) []Diagnostic, v string) func() []Diagnostic {
		return func() []Diagnostic { return parse(v) }
	}
	mpImport := func(v string) []Diagnostic { _, d := policy.ParseMPImport(v); return d }
	parseImport := func(v string) []Diagnostic { _, d := policy.ParseImport(v); return d }
	parseInject := func(v string) []Diagnostic { _, d := policy.ParseInject(v); return d }
	parseAggrMtd := func(v string) []Diagnostic { _, d := policy.ParseAggrMtd(v); return d }
	parseIfaddr := func(v string) []Diagnostic { _, d := policy.ParseIfaddr(v); return d }
	parseIface := func(v string) []Diagnostic { _, d := policy.ParseInterface(v); return d }
	parsePeer := func(v string) []Diagnostic { _, d := policy.ParsePeer(v); return d }
	parseMntRoutes := func(v string) []Diagnostic { _, d := policy.ParseMntRoutes(v); return d }
	parseTypedef := func(v string) []Diagnostic { _, d := policy.ParseTypedef(v); return d }
	parseRPAttr := func(v string) []Diagnostic { _, d := policy.ParseRPAttribute(v); return d }
	parseProtocol := func(v string) []Diagnostic { _, d := policy.ParseProtocol(v); return d }
	// The dictionary checks only run when one is supplied.
	dict := policy.RFCDictionary
	withDict := func(v string) []Diagnostic {
		_, d := policy.ParseImportWith(v, false, policy.Options{Dict: &dict})
		return d
	}
	long := "#" + strings.Repeat("x", 64) + "\n"
	catalog := []struct {
		rule  string
		diags func() []Diagnostic
	}{
		{"lexer/malformed-line", obj("a: 1\njunk\n")},
		{"lexer/invalid-attribute-name", obj("a: 1\n1b: 2\n")},
		{"lexer/too-many-errors", obj("a: 1\n" + strings.Repeat("junk\n", 101))},
		{"rpsl/multiple-objects", obj("a: 1\n\nb: 2\n")},
		{"rpsl/object-too-large", stream(strings.NewReader("a: 1\nb: 22222222222\n"), ParseOptions{MaxObjectBytes: 8})},
		{"rpsl/trivia-too-large", stream(strings.NewReader(long+"a: 1\n"), ParseOptions{MaxObjectBytes: 32})},
		{"rpsl/read-error", stream(io.MultiReader(strings.NewReader("a: 1\n"), iotest.ErrReader(errors.New("boom"))), ParseOptions{})},
		{"object/empty-key", obj("route:\norigin: AS1\n")},
		{"object/route-origin", obj("route: 192.0.2.0/24\norigin: ASX\n")},
		{"object/route-prefix", obj("route: 192.0.2.0/33\norigin: AS1\n")},
		{"object/aut-num-as", obj("aut-num: 65000\n")},
		{"object/as-set-name", obj("as-set: AS-X!\n")},
		{"object/inetnum-range", obj("inetnum: 192.0.2.9 - 192.0.2.1\n")},
		{"object/as-block-range", obj("as-block: AS9 - AS1\n")},
		{"object/inet6num-prefix", obj("inet6num: 192.0.2.0/24\n")},
		{"object/as-set-members", obj("as-set: AS-X\nmembers: RS-Y\n")},
		{"object/as-set-members", obj("as-set: AS-X\nmembers: garbage!!\n")},
		{"object/route-set-mp-members", obj("route-set: RS-X\nmp-members: FLTR-Y\n")},
		{"object/route-set-members-host-bits", obj("route-set: RS-X\nmembers: 192.0.2.1/24\n")},
		{"object/route-set-mp-members-host-bits", obj("route-set: RS-X\nmp-members: 2001:db8::1/32\n")},
		{"object/route-set-members-afi", obj("route-set: RS-X\nmembers: 2001:db8::/32\n")},
		{"object/aut-num-member-of-class", obj("aut-num: AS1\nmember-of: RS-X\n")},
		{"object/list-empty-item", obj("as-set: AS-X\nmembers: AS1,,AS2\n")},
		{"object/list-line-break", obj("as-set: AS-X\nmembers: AS1\n AS2\n")},
		{"object/route-set-name-class", obj("route-set: AS-X\n")},
		{"object/route-afi", obj("route: 2001:db8::/32\norigin: AS1\n")},
		{"object/route6-afi", obj("route6: 192.0.2.0/24\norigin: AS1\n")},
		{"object/route-host-bits", obj("route: 192.0.2.1/24\norigin: AS1\n")},
		{"object/route-leading-zeros", obj("route: 064.006.160.000/19\norigin: AS1\n")},
		{"object/route-holes-host-bits", obj("route: 192.0.2.0/24\norigin: AS1\nholes: 192.0.2.1/25\n")},
		{"object/route-holes-outside", obj("route: 192.0.2.0/24\norigin: AS1\nholes: 198.51.100.0/25\n")},
		{"policy/empty", imp("")},
		{"policy/empty", imp("{ }")},
		{"policy/expect-peering", imp("accept ANY")},
		{"policy/expect-filter", imp("from AS1")},
		{"policy/via", obj("aut-num: AS1\nimport-via: from AS1 accept ANY\n")},
		{"policy/peering", imp("from RS-X accept ANY")},
		{"policy/as-expr", imp("from (AS1 accept ANY")},
		{"policy/router", imp("from AS1 PEERING accept ANY")},
		{"policy/router", imp("from AS1 at not 192.0.2.1 accept ANY")},
		{"policy/protocol", imp("protocol from AS1 accept ANY")},
		{"policy/action", imp("from AS1 action foo; accept ANY")},
		{"policy/filter", imp("from AS1 accept ANY junk!!")},
		{"policy/filter-method", imp("from AS1 accept foo(1)")},
		{"policy/filter-paren", imp("from AS1 accept (ANY")},
		{"policy/prefix-list", imp("from AS1 accept {bad}")},
		{"policy/prefix-list", imp("from AS1 accept {192.0.2.0/24,}")},
		{"policy/host-bits", imp("from AS1 accept {192.0.2.1/24}")},
		{"policy/leading-zeros", imp("from AS1 accept {064.006.160.000/19}")},
		{"policy/unicode-space", imp("from AS1\u00a0accept ANY")},
		{"policy/range-op", imp("from AS1 accept AS-X^+24")},
		{"policy/as-path-regexp", imp("from AS1 accept <RS-X>")},
		{"policy/as-path-regexp", imp("from AS1 accept <3333>")},
		{"policy/afi", pol(mpImport, "afi bogus from AS1 accept ANY")},
		{"policy/default-to", obj("aut-num: AS1\ndefault: AS2\n")},
		{"policy/expr-brace", imp("{ from AS1 accept ANY")},
		{"policy/missing-semicolon", imp("{ from AS1 accept AS1 from AS2 accept AS2 }")},
		{"policy/trailing", imp("from AS1 accept ANY; from AS2 accept ANY")},
		{"policy/nesting", pol(parseImport, "from AS1 accept "+strings.Repeat("(", 2000)+"ANY")},
		{"policy/too-long", pol(parseImport, strings.Repeat("AS1 ", 1<<20+1))},
		{"policy/too-many-errors", pol(parseImport, "from AS1 accept "+strings.Repeat("junk!! ", 150))},
		{"object/route-pingable", obj("route: 192.0.2.0/24\norigin: AS1\npingable: nope\n")},
		{"object/mntner-auth", obj("mntner: M\nadmin-c: EX1-RIPE\nupd-to: e@e.net\nauth: WEIRD-PW x\nmnt-by: M\nsource: RIPE\n")},
		{"object/irt-auth", obj("irt: IRT-X\naddress: A\ne-mail: e@e.net\nauth: WEIRD-PW x\nsource: RIPE\n")},
		{"object/route-created", obj("route: 192.0.2.0/24\norigin: AS1\ncreated: yesterday\n")},
		{"object/route-last-modified", obj("route: 192.0.2.0/24\norigin: AS1\nlast-modified: never\n")},
		{"object/route-changed", obj("route: 192.0.2.0/24\norigin: AS1\nchanged: e@e.net notadate\n")},
		{"object/rtr-set-members", obj("rtr-set: RTRS-X\nmembers: AS-WRONG\n")},
		{"object/poem-author", obj("poem: P\nform: F\ntext: t\nauthor: not a handle!\nmnt-by: M\nsource: RIPE\n")},
		{"policy/inject", pol(parseInject, "upon WHATEVER")},
		{"policy/aggr-mtd", pol(parseAggrMtd, "sideways")},
		{"policy/ifaddr", pol(parseIfaddr, "1.1.1.1")},
		{"policy/interface", pol(parseIface, "2001:db8::1 masklen 48 tunnel 192.0.2.1")},
		{"policy/peer", pol(parsePeer, "BGP4 192.0.2.1 asno(")},
		{"policy/peer", pol(parsePeer, "BGP4 192.0.2.1 ,")},
		{"policy/mnt-routes", pol(parseMntRoutes, "MNT-A junk")},
		{"policy/typedef", pol(parseTypedef, "lonely")},
		{"policy/rp-attribute", pol(parseRPAttr, "pref")},
		{"policy/rp-attribute", pol(withDict, "from AS1 action nonsense = 1; accept ANY")},
		{"policy/rp-method", pol(withDict, "from AS1 action aspath.append(AS1); accept ANY")},
		{"policy/rp-protocol", pol(parseProtocol, "BGP4 asno(as_number)")},
		{"policy/rp-protocol", pol(withDict, "protocol NONSENSE from AS1 accept ANY")},
		{"dict/unknown-class", obj("foo: x\n")},
		{"dict/unknown-attr", obj("route: 192.0.2.0/24\norigin: AS1\nfoo: x\n")},
		{"dict/missing-required", obj("route: 192.0.2.0/24\n")},
		{"dict/cardinality", obj("route: 192.0.2.0/24\norigin: AS1\norigin: AS2\n")},
	}
	var emitted []Diagnostic
	for _, c := range catalog {
		ds := c.diags()
		found := false
		for _, d := range ds {
			found = found || d.Rule == c.rule
		}
		if !found {
			t.Errorf("catalog: %s is not emitted by its input; got %v", c.rule, ds)
		}
		emitted = append(emitted, ds...)
	}
	files, _ := filepath.Glob(filepath.Join(corpusDir, "*.txt"))
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		for o, ds := range Parse(f) {
			emitted = append(emitted, ds...)
			_, dec := Decode(o)
			emitted = append(emitted, dec...)
			emitted = append(emitted, Validate(o, RIPE)...)
			emitted = append(emitted, Validate(o, RFCStrict)...)
		}
		f.Close()
	}

	rows := readRuleRows(t)
	for _, d := range emitted {
		documented := false
		for _, row := range rows {
			for _, re := range row.patterns {
				if re.MatchString(d.Rule) && strings.Contains(strings.ToLower(row.severity), d.Severity.String()) {
					documented, row.seen = true, true
				}
			}
		}
		if !documented {
			t.Errorf("%s (%v) is not in docs/diagnostics.md with that severity: %s", d.Rule, d.Severity, d.Message)
		}
	}
	for _, row := range rows {
		if !row.seen {
			t.Errorf("docs/diagnostics.md lists %s, which nothing here emits", row.text)
		}
	}
}
