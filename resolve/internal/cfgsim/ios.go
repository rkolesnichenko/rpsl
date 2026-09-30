package cfgsim

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

type aclEntry struct {
	permit                         bool
	addr, addrWild, mask, maskWild uint32
}

type plEntry struct {
	permit bool
	p      netip.Prefix
	ge, le int // 0: absent
}

type reEntry struct {
	permit bool
	re     string
}

type commEntry struct {
	permit   bool
	internet bool
	comms    []string
}

type rmEntry struct {
	seq      int
	permit   bool
	acls     []string
	prefixes []string // keys "v4:NAME" or "v6:NAME"
	paths    []string
	comms    []string
	exact    bool
	sets     []string // the set lines, applied in order
}

type attachKey struct {
	addr   netip.Addr
	export bool
}

type iosConfig struct {
	acls     map[string][]aclEntry
	pls      map[string][]plEntry
	paths    map[string][]reEntry
	comms    map[string][]commEntry
	maps     map[string][]*rmEntry
	order    []string
	attached map[attachKey]string
}

// ParseIOS reads a Cisco IOS configuration: route-maps, extended access-lists
// (as rtconfig writes them), prefix-lists, as-path access-lists,
// community-lists, and "router bgp" neighbours' route-maps.
func ParseIOS(text string) (Config, error) {
	c := &iosConfig{acls: map[string][]aclEntry{}, pls: map[string][]plEntry{}, paths: map[string][]reEntry{},
		comms: map[string][]commEntry{}, maps: map[string][]*rmEntry{}, attached: map[attachKey]string{}}
	var cur *rmEntry
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		f := strings.Fields(trimmed)
		if len(f) == 0 || f[0] == "!" || strings.HasPrefix(trimmed, "Warning:") || strings.HasPrefix(trimmed, "***") {
			continue
		}
		fail := func(why string) error { return fmt.Errorf("cfgsim: ios line %d %q: %s", n+1, trimmed, why) }
		if line != trimmed { // indented: inside a route-map entry or router bgp
			if cur != nil && (f[0] == "match" || f[0] == "set") {
				if err := c.entryLine(cur, f); err != nil {
					return nil, fail(err.Error())
				}
				continue
			}
			if f[0] == "neighbor" && len(f) >= 5 && f[2] == "route-map" {
				addr, err := netip.ParseAddr(f[1])
				if err != nil {
					return nil, fail("neighbour address")
				}
				c.attached[attachKey{addr, f[4] == "out"}] = f[3]
			}
			continue // remote-as, activate, address-family, network, exit, …
		}
		cur = nil
		var err error
		switch {
		case f[0] == "exit", f[0] == "router":
		case f[0] == "no":
			c.remove(f[1:])
		case f[0] == "access-list":
			err = c.acl(f)
		case len(f) > 2 && (f[0] == "ip" || f[0] == "ipv6") && f[1] == "prefix-list":
			err = c.prefixList(f)
		case len(f) > 4 && f[0] == "ip" && f[1] == "as-path" && f[2] == "access-list":
			c.paths[f[3]] = append(c.paths[f[3]], reEntry{permit: f[4] == "permit", re: strings.Join(f[5:], " ")})
		case len(f) > 3 && f[0] == "ip" && f[1] == "community-list":
			err = c.communityList(f[2:])
		case len(f) > 1 && f[0] == "ip" && (f[1] == "bgp-community" || f[1] == "default-network"):
		case f[0] == "route-map" && len(f) == 4:
			seq, e := strconv.Atoi(f[3])
			if e != nil {
				return nil, fail("sequence")
			}
			cur = &rmEntry{seq: seq, permit: f[2] == "permit"}
			if _, ok := c.maps[f[1]]; !ok {
				c.order = append(c.order, f[1])
			}
			c.maps[f[1]] = append(c.maps[f[1]], cur)
		default:
			err = fmt.Errorf("unknown line")
		}
		if err != nil {
			return nil, fail(err.Error())
		}
	}
	return c, nil
}

func (c *iosConfig) remove(f []string) {
	switch {
	case len(f) >= 2 && f[0] == "route-map":
		delete(c.maps, f[1])
	case len(f) >= 2 && f[0] == "access-list":
		delete(c.acls, f[1])
	case len(f) >= 3 && f[0] == "ip" && f[1] == "prefix-list":
		delete(c.pls, "v4:"+f[2])
	case len(f) >= 3 && f[0] == "ipv6" && f[1] == "prefix-list":
		delete(c.pls, "v6:"+f[2])
	case len(f) >= 4 && f[0] == "ip" && f[1] == "as-path":
		delete(c.paths, f[3])
	case len(f) >= 3 && f[0] == "ip" && f[1] == "community-list":
		delete(c.comms, f[len(f)-1])
	}
}

// parsePlainASN reads an AS number the way "set as-path prepend" writes it:
// a bare decimal, with no "AS" prefix.
func parsePlainASN(s string) (types.ASN, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("AS number %q", s)
	}
	return types.ASN(v), nil
}

func dotted(s string) (uint32, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return 0, fmt.Errorf("address %q", s)
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}

func (c *iosConfig) acl(f []string) error {
	// access-list N permit|deny ip A AW M MW
	if len(f) != 8 || f[3] != "ip" {
		return fmt.Errorf("extended access-list")
	}
	var v [4]uint32
	for i := range v {
		x, err := dotted(f[4+i])
		if err != nil {
			return err
		}
		v[i] = x
	}
	c.acls[f[1]] = append(c.acls[f[1]], aclEntry{permit: f[2] == "permit", addr: v[0], addrWild: v[1], mask: v[2], maskWild: v[3]})
	return nil
}

func (c *iosConfig) prefixList(f []string) error {
	// ip[v6] prefix-list NAME [seq N] permit|deny P [ge a] [le b]
	key := "v4:" + f[2]
	if f[0] == "ipv6" {
		key = "v6:" + f[2]
	}
	rest := f[3:]
	if len(rest) >= 2 && rest[0] == "seq" {
		rest = rest[2:]
	}
	if len(rest) < 2 {
		return fmt.Errorf("prefix-list entry")
	}
	p, err := netip.ParsePrefix(rest[1])
	if err != nil {
		return err
	}
	e := plEntry{permit: rest[0] == "permit", p: p}
	for i := 2; i+1 < len(rest); i += 2 {
		v, err := strconv.Atoi(rest[i+1])
		if err != nil {
			return err
		}
		switch rest[i] {
		case "ge":
			e.ge = v
		case "le":
			e.le = v
		default:
			return fmt.Errorf("prefix-list modifier %q", rest[i])
		}
	}
	c.pls[key] = append(c.pls[key], e)
	return nil
}

func (c *iosConfig) communityList(f []string) error {
	// [standard] NAME permit|deny values… | internet
	if f[0] == "standard" {
		f = f[1:]
	}
	if len(f) < 2 {
		return fmt.Errorf("community-list entry")
	}
	e := commEntry{permit: f[1] == "permit"}
	vals := f[2:]
	if len(vals) == 1 && vals[0] == "internet" {
		e.internet = true
	} else {
		cs, err := canonList(vals)
		if err != nil {
			return err
		}
		e.comms = cs
	}
	c.comms[f[0]] = append(c.comms[f[0]], e)
	return nil
}

func (c *iosConfig) entryLine(e *rmEntry, f []string) error {
	if f[0] == "set" {
		e.sets = append(e.sets, strings.Join(f[1:], " "))
		return nil
	}
	switch {
	case len(f) >= 4 && f[1] == "ip" && f[2] == "address" && f[3] == "prefix-list":
		for _, n := range f[4:] {
			e.prefixes = append(e.prefixes, "v4:"+n)
		}
	case len(f) >= 4 && f[1] == "ipv6" && f[2] == "address" && f[3] == "prefix-list":
		for _, n := range f[4:] {
			e.prefixes = append(e.prefixes, "v6:"+n)
		}
	case len(f) >= 4 && f[1] == "ip" && f[2] == "address":
		e.acls = append(e.acls, f[3:]...)
	case len(f) >= 3 && f[1] == "as-path":
		e.paths = append(e.paths, f[2:]...)
	case len(f) >= 3 && f[1] == "community":
		for _, n := range f[2:] {
			if n == "exact-match" {
				e.exact = true
				continue
			}
			e.comms = append(e.comms, n)
		}
	default:
		return fmt.Errorf("unknown match")
	}
	return nil
}

func (c *iosConfig) Policies() []string { return append([]string(nil), c.order...) }

func (c *iosConfig) Attached(n netip.Addr, export bool) (string, bool) {
	name, ok := c.attached[attachKey{n, export}]
	return name, ok
}

func (c *iosConfig) Policy(name string, r Route) (bool, Attrs, error) {
	entries, ok := c.maps[name]
	if !ok {
		return false, Attrs{}, fmt.Errorf("cfgsim: no route-map %q", name)
	}
	sorted := append([]*rmEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].seq < sorted[j].seq })
	s := newState(r)
	for _, e := range sorted {
		ok, err := c.matches(e, s)
		if err != nil {
			return false, Attrs{}, err
		}
		if !ok {
			continue
		}
		if !e.permit {
			return false, Attrs{}, nil
		}
		for _, set := range e.sets {
			if err := c.apply(set, s); err != nil {
				return false, Attrs{}, err
			}
		}
		return true, s.finish(), nil
	}
	return false, Attrs{}, nil
}

func (c *iosConfig) matches(e *rmEntry, s *state) (bool, error) {
	if len(e.acls) > 0 && !anyOf(e.acls, func(n string) bool { return c.aclPermits(n, s.r.Prefix) }) {
		return false, nil
	}
	if len(e.prefixes) > 0 && !anyOf(e.prefixes, func(k string) bool { return c.plPermits(k, s.r.Prefix) }) {
		return false, nil
	}
	if len(e.paths) > 0 {
		ok := false
		for _, n := range e.paths {
			p, err := c.pathPermits(n, s.r.Path)
			if err != nil {
				return false, err
			}
			ok = ok || p
		}
		if !ok {
			return false, nil
		}
	}
	if len(e.comms) > 0 && !anyOf(e.comms, func(n string) bool { return c.commPermits(n, s, e.exact) }) {
		return false, nil
	}
	return true, nil
}

func anyOf(names []string, f func(string) bool) bool {
	for _, n := range names {
		if f(n) {
			return true
		}
	}
	return false
}

func (c *iosConfig) aclPermits(name string, p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	b := p.Masked().Addr().As4()
	addr := binary.BigEndian.Uint32(b[:])
	mask := ^uint32(0) << (32 - p.Bits())
	if p.Bits() == 0 {
		mask = 0
	}
	for _, e := range c.acls[name] {
		if addr&^e.addrWild == e.addr&^e.addrWild && mask&^e.maskWild == e.mask&^e.maskWild {
			return e.permit
		}
	}
	return false
}

// covers reports whether the entry's prefix and length window contain p: an
// IOS prefix-list entry, or an IOS-XR prefix-set element.
func (e plEntry) covers(p netip.Prefix) bool {
	if e.p.Addr().Is4() != p.Addr().Is4() || p.Bits() < e.p.Bits() || !e.p.Contains(p.Addr()) {
		return false
	}
	lo, hi := e.p.Bits(), e.p.Bits()
	switch {
	case e.ge > 0 && e.le > 0:
		lo, hi = e.ge, e.le
	case e.ge > 0:
		lo, hi = e.ge, p.Addr().BitLen()
	case e.le > 0:
		hi = e.le
	}
	return p.Bits() >= lo && p.Bits() <= hi
}

func (c *iosConfig) plPermits(key string, p netip.Prefix) bool {
	for _, e := range c.pls[key] {
		if e.covers(p) {
			return e.permit
		}
	}
	return false
}

func (c *iosConfig) pathPermits(name string, path []types.ASN) (bool, error) {
	for _, e := range c.paths[name] {
		ok, err := MatchIOS(e.re, path)
		if err != nil {
			return false, err
		}
		if ok {
			return e.permit, nil
		}
	}
	return false, nil
}

func (c *iosConfig) commPermits(name string, s *state, exact bool) bool {
	for _, e := range c.comms[name] {
		var hit bool
		switch {
		case exact:
			hit = !e.internet && s.equals(e.comms)
		case e.internet:
			hit = true
		default:
			hit = s.has(e.comms)
		}
		if hit {
			return e.permit
		}
	}
	return false
}

func (c *iosConfig) apply(set string, s *state) error {
	f := strings.Fields(set)
	switch {
	case len(f) == 2 && f[0] == "local-preference":
		v, err := strconv.Atoi(f[1])
		s.attrs.LocalPref = v
		return err
	case len(f) == 2 && f[0] == "metric":
		v, err := strconv.Atoi(f[1])
		s.attrs.MED, s.attrs.MEDIGP = v, false
		return err
	case len(f) == 2 && f[0] == "metric-type" && f[1] == "internal":
		s.attrs.MED, s.attrs.MEDIGP = -1, true
	case len(f) >= 2 && f[0] == "community":
		vals, additive := f[1:], false
		if vals[len(vals)-1] == "additive" {
			vals, additive = vals[:len(vals)-1], true
		}
		if len(vals) == 1 && vals[0] == "none" {
			s.comms = map[string]bool{}
			return nil
		}
		cs, err := canonList(vals)
		if err != nil {
			return err
		}
		if !additive {
			s.comms = map[string]bool{}
		}
		for _, c := range cs {
			s.comms[c] = true
		}
	case len(f) == 3 && f[0] == "comm-list" && f[2] == "delete":
		for _, e := range c.comms[f[1]] {
			if e.permit {
				for _, x := range e.comms {
					delete(s.comms, x)
				}
			}
		}
	case len(f) >= 3 && f[0] == "as-path" && f[1] == "prepend":
		var as []types.ASN
		for _, x := range f[2:] {
			a, err := parsePlainASN(x)
			if err != nil {
				return err
			}
			as = append(as, a)
		}
		s.prepend(as)
	case len(f) == 3 && (f[0] == "ip" || f[0] == "ipv6") && f[1] == "next-hop":
		s.attrs.NextHop = f[2]
	default:
		return fmt.Errorf("cfgsim: ios set %q", set)
	}
	return nil
}
