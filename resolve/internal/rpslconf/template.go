package rpslconf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Command is one @RtConfig line of a template (IRRToolSet's rtconfig(1)).
type Command struct {
	Line   int      // 1-based
	Raw    string   // the line as written, without its line ending
	Name   string   // the command, lower-cased
	Args   []string // import/export: AS rtr AS rtr; default: AS AS; networks, v6networks: AS; a deferred command: its words
	Knob   string   // set: the knob, a deprecated spelling mapped to its current one
	Value  string   // set: the value, unquoted
	Format string   // printprefixes, printprefixranges: the format, escapes as written
	Filter string   // access_list, aspath_access_list, print…: the filter after "filter"
}

// Item is one line of a template: Text, a line copied to the output as it is
// (its line ending included), or Cmd, with its line ending in NL.
type Item struct {
	Text string
	Cmd  *Command
	NL   string
}

// supported are the commands template mode runs; deferred are those it
// recognises and refuses (spec §8.2: rtconfig's own are broken, D7 and D8,
// or have no oracle).
var (
	supported = map[string]bool{"import": true, "export": true, "default": true, "set": true,
		"access_list": true, "aspath_access_list": true, "printprefixes": true, "printprefixranges": true,
		"networks": true, "v6networks": true}
	deferred = map[string]bool{"printsuperprefixranges": true, "configurerouter": true, "importgroup": true,
		"exportgroup": true, "importpeergroup": true, "static2bgp": true, "inbound_pkt_filter": true,
		"outbound_pkt_filter": true, "pkt_filter": true}
)

// knobs maps each spelling of a set knob to its current name.
var knobs = map[string]string{
	"cisco_map_name": "cisco_map_name", "cisco_map_first_no": "cisco_map_first_no",
	"cisco_map_increment_by": "cisco_map_increment_by", "prefix_acl_no": "prefix_acl_no",
	"cisco_prefix_acl_no": "prefix_acl_no", "aspath_acl_no": "aspath_acl_no",
	"cisco_aspath_acl_no": "aspath_acl_no", "community_acl_no": "community_acl_no",
	"cisco_community_acl_no": "community_acl_no", "cisco_access_list_no": "cisco_access_list_no",
	"cisco_max_preference": "cisco_max_preference", "junos_policy_name": "junos_policy_name",
	"sources": "sources",
}

// formatVerbs are the letters a print command's format may put after '%'.
const formatVerbs = "plLnmkK%"

const keyword = "@rtconfig"

// isCommand reports whether line is an @RtConfig command: the keyword, in
// any case, at the start of the line, then a space, a tab or the end.
func isCommand(line string) bool {
	if len(line) < len(keyword) || !strings.EqualFold(line[:len(keyword)], keyword) {
		return false
	}
	return len(line) == len(keyword) || line[len(keyword)] == ' ' || line[len(keyword)] == '\t'
}

// readTemplate reads a template line by line, handing fn each item. The first
// bad command, or fn's first error, ends it.
func readTemplate(r io.Reader, fn func(Item) error) error {
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadString('\n')
		if line != "" {
			it := Item{Text: line}
			body, nl := line, ""
			switch {
			case strings.HasSuffix(body, "\r\n"):
				body, nl = body[:len(body)-2], "\r\n"
			case strings.HasSuffix(body, "\n"):
				body, nl = body[:len(body)-1], "\n"
			}
			if isCommand(body) {
				c, perr := parseCommand(body, n)
				if perr != nil {
					return perr
				}
				it = Item{Cmd: c, NL: nl}
			}
			if ferr := fn(it); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ParseTemplate reads a template whole. On an error it returns the items
// before the bad line too.
func ParseTemplate(text string) ([]Item, error) {
	var items []Item
	err := readTemplate(strings.NewReader(text), func(it Item) error {
		items = append(items, it)
		return nil
	})
	return items, err
}

// parseCommand reads one command line.
func parseCommand(line string, n int) (*Command, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("line %d: %s", n, fmt.Sprintf(format, args...))
	}
	c := &Command{Line: n, Raw: line}
	rest := strings.TrimSpace(line[len(keyword):])
	name, rest := cutWord(rest)
	if name == "" {
		return nil, fail("no command after @RtConfig")
	}
	c.Name = strings.ToLower(name)
	words := strings.Fields(rest)
	switch c.Name {
	case "import", "export":
		if len(words) != 4 {
			return nil, fail("%s takes AS, router, AS, router", c.Name)
		}
		var fam [2]bool
		for i, w := range words {
			if i%2 == 0 {
				if _, err := types.ParseASN(w); err != nil {
					return nil, fail("%s: %q is not an AS number", c.Name, w)
				}
				continue
			}
			a, err := netip.ParseAddr(w)
			if err != nil {
				return nil, fail("%s: %q is not a router address", c.Name, w)
			}
			fam[i/2] = a.Is4()
		}
		if fam[0] != fam[1] {
			return nil, fail("%s: the routers' addresses are not of one family", c.Name)
		}
		c.Args = words
	case "default", "networks", "v6networks":
		want := 1
		if c.Name == "default" {
			want = 2
		}
		if len(words) != want {
			return nil, fail("%s takes %d AS number(s)", c.Name, want)
		}
		for _, w := range words {
			if _, err := types.ParseASN(w); err != nil {
				return nil, fail("%s: %q is not an AS number", c.Name, w)
			}
		}
		c.Args = words
	case "set":
		knob, value, ok := strings.Cut(rest, "=")
		if !ok {
			return nil, fail("set takes knob = value")
		}
		k, ok := knobs[strings.TrimSpace(knob)]
		if !ok {
			return nil, fail("set: unknown knob %q", strings.TrimSpace(knob))
		}
		v, err := knobValue(k, strings.TrimSpace(value))
		if err != nil {
			return nil, fail("set %s: %v", k, err)
		}
		c.Knob, c.Value = k, v
	case "access_list", "aspath_access_list":
		f, ok := afterFilter(rest)
		if !ok {
			return nil, fail("%s takes filter <filter>", c.Name)
		}
		c.Filter = f
	case "printprefixes", "printprefixranges":
		if !strings.HasPrefix(rest, `"`) {
			return nil, fail("%s takes \"<format>\" filter <filter>", c.Name)
		}
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return nil, fail("%s: the format's quote is not closed", c.Name)
		}
		c.Format = rest[1 : 1+end]
		if err := checkFormat(c.Format); err != nil {
			return nil, fail("%s: %v", c.Name, err)
		}
		f, ok := afterFilter(strings.TrimSpace(rest[2+end:]))
		if !ok {
			return nil, fail("%s takes \"<format>\" filter <filter>", c.Name)
		}
		c.Filter = f
	default:
		if !deferred[c.Name] {
			return nil, fail("unknown command %q", name)
		}
		c.Args = words
	}
	return c, nil
}

// cutWord splits s at its first space or tab.
func cutWord(s string) (word, rest string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i:])
	}
	return s, ""
}

// afterFilter returns what follows the keyword "filter", which must be
// something.
func afterFilter(s string) (string, bool) {
	kw, rest := cutWord(s)
	if kw != "filter" || rest == "" {
		return "", false
	}
	return rest, true
}

// knobValue checks a set knob's value and returns it unquoted.
func knobValue(knob, v string) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	switch knob {
	case "cisco_map_name", "junos_policy_name":
		if strings.Count(v, "%d") > 2 {
			return "", fmt.Errorf("%q: at most two %%d", v)
		}
		rest := strings.ReplaceAll(v, "%d", "")
		if rest == "" && v == "" || strings.Trim(rest, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
			return "", fmt.Errorf("%q: a name of letters, digits, _ . - and %%d", v)
		}
	case "sources":
		for _, s := range strings.Split(v, ",") {
			if _, err := types.ParseSourceName(s); err != nil {
				return "", err
			}
		}
	default:
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1<<30 {
			return "", fmt.Errorf("%q is not a number from 0 to %d", v, 1<<30)
		}
	}
	return v, nil
}

// checkFormat checks a print command's format: its % verbs and \ escapes.
func checkFormat(f string) error {
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case '%':
			if i+1 == len(f) || strings.IndexByte(formatVerbs, f[i+1]) < 0 {
				return fmt.Errorf("unknown operator %q", f[i:min(i+2, len(f))])
			}
			i++
		case '\\':
			if i+1 == len(f) || strings.IndexByte(`nt\`, f[i+1]) < 0 {
				return fmt.Errorf("unknown escape %q", f[i:min(i+2, len(f))])
			}
			i++
		}
	}
	return nil
}
