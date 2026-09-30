package rpslconf

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
	"github.com/rkolesnichenko/rpsl/types"
)

// tmpl runs a template: its state is the backend, reopened when "set
// sources" changes the registries, and one Generator, which numbers lists
// and maps across the whole template as rtconfig does.
type tmpl struct {
	ctx       context.Context
	opts      backend.Options
	b         *backend.Backend
	g         *rtconfig.Generator
	out, errw io.Writer
	listed    bool // a list or policy has been written: list numbering is fixed
}

func (t *tmpl) open() error {
	b, err := backend.Open(t.opts)
	if err != nil {
		return err
	}
	if t.b != nil {
		t.b.Close()
	}
	t.b = b
	return nil
}

// run copies the template to the output, running each command, then writes
// the sessions a BIRD configuration collects. The first error ends it: 1.
func (t *tmpl) run(stdin io.Reader) int {
	if err := t.open(); err != nil {
		fmt.Fprintf(t.errw, "rpslconf: %v\n", err)
		return 1
	}
	defer func() { t.b.Close() }()
	err := readTemplate(stdin, func(it Item) error {
		if it.Cmd == nil {
			_, err := io.WriteString(t.out, it.Text)
			return err
		}
		if err := t.command(it.Cmd); err != nil {
			return fmt.Errorf("line %d: %w", it.Cmd.Line, err)
		}
		return nil
	})
	if err == nil {
		err = t.g.WriteSessions(t.out)
	}
	if err != nil {
		fmt.Fprintf(t.errw, "rpslconf: %v\n", err)
		return 1
	}
	return 0
}

func (t *tmpl) warnf(c *Command, format string, args ...any) {
	fmt.Fprintf(t.errw, "rpslconf: warning: line %d: %s\n", c.Line, fmt.Sprintf(format, args...))
}

// warn reports what an evaluation could not decide or find.
func (t *tmpl) warn(c *Command, und []peval.Undecided, missing []types.SetRef, rtrs []string) {
	for _, u := range und {
		t.warnf(c, "attribute %d not evaluated: %s", u.Index+1, u.Why)
	}
	for _, m := range missing {
		t.warnf(c, "%s not found", m)
	}
	for _, r := range rtrs {
		t.warnf(c, "inet-rtr %s not found", r)
	}
}

// session reads import/export's AS rtr AS rtr (checked by the reader).
func session(args []string) peval.Session {
	local, _ := types.ParseASN(args[0])
	peer, _ := types.ParseASN(args[2])
	s := peval.Session{Local: local, Peer: peer, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}}
	s.LocalRtr, _ = netip.ParseAddr(args[1])
	s.PeerRtr, _ = netip.ParseAddr(args[3])
	if s.LocalRtr.Is6() {
		s.AF.AFI = types.AFIv6
	}
	return s
}

func (t *tmpl) command(c *Command) error {
	ev := &peval.Evaluator{Src: t.b.Src}
	switch c.Name {
	case "import", "export":
		s := session(c.Args)
		evaluate, write := ev.Import, t.g.WriteImport
		if c.Name == "export" {
			evaluate, write = ev.Export, t.g.WriteExport
		}
		p, err := evaluate(t.ctx, s)
		if err != nil {
			return err
		}
		t.warn(c, p.Undecided, p.Missing(), p.MissingRouters())
		t.listed = true
		return write(t.out, s, p)
	case "default":
		local, _ := types.ParseASN(c.Args[0])
		peer, _ := types.ParseASN(c.Args[1])
		s := peval.Session{Local: local, Peer: peer, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}}
		d, err := ev.Default(t.ctx, s)
		if err != nil {
			return err
		}
		t.warn(c, d.Undecided, d.Missing(), d.MissingRouters())
		return t.g.WriteDefault(t.out, s, d)
	case "set":
		return t.set(c.Knob, c.Value)
	case "access_list":
		nf, afi, err := t.normalize(c)
		if err != nil {
			return err
		}
		t.listed = true
		return t.g.WritePrefixList(t.out, nf, afi)
	case "aspath_access_list":
		nf, _, err := t.normalize(c)
		if err != nil {
			return err
		}
		m, ok := onePath(nf)
		if !ok {
			return fmt.Errorf("aspath_access_list takes one AS-path regexp, or NOT one: %s", c.Filter)
		}
		t.listed = true
		return t.g.WriteASPathList(t.out, m)
	case "printprefixes", "printprefixranges":
		nf, afi, err := t.normalize(c)
		if err != nil {
			return err
		}
		return printPrefixes(t.out, c.Format, nf, afi, c.Name == "printprefixes")
	case "networks", "v6networks":
		as, _ := types.ParseASN(c.Args[0])
		afi := types.AFIv4
		if c.Name == "v6networks" {
			afi = types.AFIv6
		}
		ps, err := t.b.Src.OriginatedRoutes(t.ctx, as, afi)
		if err != nil {
			return err
		}
		return t.g.WriteNetworks(t.out, ps)
	}
	return fmt.Errorf("%s is not supported yet (see docs/rpslconf.md)", c.Name)
}

// numbering are the knobs that set where list numbers start.
var numbering = map[string]bool{"prefix_acl_no": true, "aspath_acl_no": true, "community_acl_no": true, "cisco_access_list_no": true}

func (t *tmpl) set(knob, v string) error {
	if numbering[knob] && t.listed {
		return fmt.Errorf("set %s after a list was written: lists are numbered across the template, so set it first", knob)
	}
	n, _ := strconv.Atoi(v) // checked by the reader, for the number knobs
	names := &t.g.Names
	switch knob {
	case "cisco_map_name":
		names.MapName = v
	case "junos_policy_name":
		names.JunosPolicyName = v
	case "cisco_map_first_no":
		names.MapFirstNo = n
	case "cisco_map_increment_by":
		names.MapIncrementBy = n
	case "prefix_acl_no":
		names.PrefixACLNo = n
	case "aspath_acl_no":
		names.ASPathACLNo = n
	case "community_acl_no":
		names.CommunityACLNo = n
	case "cisco_access_list_no":
		names.AccessListNo = n
	case "cisco_max_preference":
		t.g.MaxPreference = n
	case "sources":
		t.opts.Sources = v
		return t.open()
	}
	return nil
}

// normalize reads a command's (mp-)filter and normalizes it for one family:
// its afi clause's, or IPv4 without one, as rtconfig reads a filter.
func (t *tmpl) normalize(c *Command) (resolve.NormalFilter, types.AFI, error) {
	afis, f, diags := policy.ParseMPFilter(c.Filter)
	for _, d := range diags {
		if d.Severity >= ast.Error {
			return resolve.NormalFilter{}, 0, fmt.Errorf("%s: %v", c.Filter, d)
		}
		t.warnf(c, "%v", d)
	}
	afi := types.AFIv4
	if len(afis) > 0 {
		if afi = afiOf(afis); afi == types.AFIAny {
			return resolve.NormalFilter{}, 0, fmt.Errorf("%s: name one address family", c.Filter)
		}
	}
	e := resolve.Expander{Src: t.b.Src, AFI: afi}
	nf, err := e.NormalizeFilter(t.ctx, f)
	if err != nil {
		return nf, afi, err
	}
	for _, m := range nf.Missing() {
		t.warnf(c, "%s not found", m)
	}
	return nf, afi, nil
}

// onePath returns the AS-path test nf consists of, alone: one conjunct, any
// prefix, no community test, one path test.
func onePath(nf resolve.NormalFilter) (resolve.PathMatch, bool) {
	if len(nf.Conjuncts) != 1 {
		return resolve.PathMatch{}, false
	}
	c := nf.Conjuncts[0]
	if !c.AnyPrefix() || c.NotPrefixes.Len() > 0 || len(c.Communities) > 0 || len(c.Paths) != 1 {
		return resolve.PathMatch{}, false
	}
	return c.Paths[0], true
}
