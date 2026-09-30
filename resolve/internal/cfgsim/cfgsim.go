// Package cfgsim reads router configuration — the subset resolve/rtconfig
// writes for Cisco IOS, Junos, Cisco IOS-XR and BIRD 2, and the subset
// IRRToolSet's rtconfig writes for the first three — and runs routes through
// its policies, with each vendor's documented semantics. It exists for tests:
// it is the semantic oracle that holds the printers to resolve/peval, and
// rtconfig to them. Like resolve/internal/routemodel it matches AS-path
// regexps against synthetic paths, which library code never does.
package cfgsim

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/types"
)

// Route is a route as a policy sees it.
type Route = routemodel.Route

// Attrs is what a policy did to a route it accepted.
type Attrs struct {
	LocalPref   int // −1: not set
	MED         int // −1: not set
	MEDIGP      bool
	Communities []string    // the route's communities afterwards, a:b, sorted; nil when none
	Prepended   []types.ASN // what was prepended, leftmost first
	NextHop     string      // "", an address, or "self"
}

// Config is a parsed configuration.
type Config interface {
	// Policy runs r through the named policy.
	Policy(name string, r Route) (accepted bool, a Attrs, err error)
	// Attached returns the policy a neighbour uses on import (or export).
	Attached(neighbor netip.Addr, export bool) (policy string, ok bool)
	// Policies lists the policies defined, in the order first defined.
	Policies() []string
}

// Parse reads text as the named vendor's configuration (rtconfig's names:
// cisco, junos, ciscoxr, bird).
func Parse(vendor, text string) (Config, error) {
	switch vendor {
	case "cisco":
		return ParseIOS(text)
	case "junos":
		return ParseJunos(text)
	case "ciscoxr":
		return ParseXR(text)
	case "bird":
		return ParseBIRD(text)
	}
	return nil, fmt.Errorf("cfgsim: unknown vendor %q", vendor)
}

// state is a route while a policy runs over it.
type state struct {
	r     Route
	attrs Attrs
	comms map[string]bool
}

func newState(r Route) *state {
	s := &state{r: r, attrs: Attrs{LocalPref: -1, MED: -1}, comms: map[string]bool{}}
	for _, c := range r.Communities {
		if k, ok := CanonCommunity(c); ok {
			s.comms[k] = true
		}
	}
	return s
}

func (s *state) finish() Attrs {
	a := s.attrs
	for c := range s.comms {
		a.Communities = append(a.Communities, c)
	}
	sort.Strings(a.Communities)
	return a
}

// has reports whether the route carries every community in cs.
func (s *state) has(cs []string) bool {
	for _, c := range cs {
		if !s.comms[c] {
			return false
		}
	}
	return true
}

// equals reports whether the route carries exactly cs.
func (s *state) equals(cs []string) bool {
	set := map[string]bool{}
	for _, c := range cs {
		set[c] = true
	}
	return len(set) == len(s.comms) && s.has(cs)
}

func (s *state) prepend(as []types.ASN) {
	s.attrs.Prepended = append(append([]types.ASN(nil), as...), s.attrs.Prepended...)
}

// CanonCommunity writes a community as a:b: a:b itself, a 32-bit decimal,
// BIRD's (a,b), or a well-known name as any vendor spells it.
func CanonCommunity(s string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "no_export", "no-export":
		return "65535:65281", true
	case "no_advertise", "no-advertise":
		return "65535:65282", true
	case "no_export_subconfed", "no-export-subconfed", "local-as":
		return "65535:65283", true
	}
	if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.Replace(strings.Trim(t, "()"), ",", ":", 1)
		t = strings.ReplaceAll(t, " ", "")
	}
	if a, b, ok := strings.Cut(t, ":"); ok {
		hi, err1 := strconv.ParseUint(a, 10, 16)
		lo, err2 := strconv.ParseUint(b, 10, 16)
		if err1 != nil || err2 != nil {
			return "", false
		}
		return fmt.Sprintf("%d:%d", hi, lo), true
	}
	v, err := strconv.ParseUint(t, 10, 32)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%d:%d", v>>16, v&0xFFFF), true
}

func canonList(vals []string) ([]string, error) {
	var out []string
	for _, v := range vals {
		c, ok := CanonCommunity(v)
		if !ok {
			return nil, fmt.Errorf("cfgsim: community %q", v)
		}
		out = append(out, c)
	}
	return out, nil
}

// pathString writes a path as IOS sees it: AS numbers separated by spaces.
func pathString(p []types.ASN) string {
	parts := make([]string, len(p))
	for i, a := range p {
		parts[i] = strconv.FormatUint(uint64(a), 10)
	}
	return strings.Join(parts, " ")
}
