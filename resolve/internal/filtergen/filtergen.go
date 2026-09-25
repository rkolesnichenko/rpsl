// Package filtergen writes prefix and AS lists in the formats router
// configuration takes, as bgpq4 writes them: the same text, so a generated
// filter can replace bgpq4's line for line. It does no I/O of its own and no
// expansion; cmd/rpslq feeds it the engine's results.
package filtergen

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Format is an output format.
type Format uint8

// The formats, named as bgpq4's options: Cisco IOS (its default), -j, -b, -J;
// Plain is one entry per line in RPSL's notation.
const (
	Cisco Format = iota
	JSON
	BIRD
	Junos
	Plain
)

func (f Format) String() string {
	switch f {
	case Cisco:
		return "cisco"
	case JSON:
		return "json"
	case BIRD:
		return "bird"
	case Junos:
		return "junos"
	case Plain:
		return "plain"
	}
	return fmt.Sprintf("Format(%d)", uint8(f))
}

// List is a prefix list: its name, its family, and its entries. An entry that
// is a range (lengths beyond its own) is written in bgpq4's aggregated form
// ("le"/"ge", "{lo,hi}").
type List struct {
	Name   string
	V6     bool
	Ranges []types.PrefixRange
}

// ErrUnsupported reports a list a format cannot express.
var ErrUnsupported = errors.New("filtergen: not expressible in this format")

// Sort orders ranges as bgpq4 prints them: by address, then prefix length,
// then the range's lengths.
func Sort(rs []types.PrefixRange) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i].Prefix(), rs[j].Prefix()
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		if rs[i].Lo() != rs[j].Lo() {
			return rs[i].Lo() < rs[j].Lo()
		}
		return rs[i].Hi() < rs[j].Hi()
	})
}

// exact reports whether r is one prefix rather than a range of lengths.
func exact(r types.PrefixRange) bool {
	return int(r.Lo()) == r.Prefix().Bits() && r.Hi() == r.Lo()
}

// Write writes l in format f, its entries sorted as bgpq4 sorts them.
func Write(w io.Writer, f Format, l List) error {
	rs := append([]types.PrefixRange(nil), l.Ranges...)
	Sort(rs)
	var b strings.Builder
	switch f {
	case Cisco:
		ip := "ip"
		any := "0.0.0.0/0"
		if l.V6 {
			ip, any = "ipv6", "::/0"
		}
		fmt.Fprintf(&b, "no %s prefix-list %s\n", ip, l.Name)
		if len(rs) == 0 {
			fmt.Fprintf(&b, "! generated prefix-list %s is empty\n%s prefix-list %s deny %s\n", l.Name, ip, l.Name, any)
		}
		for _, r := range rs {
			p := r.Prefix()
			switch {
			case exact(r):
				fmt.Fprintf(&b, "%s prefix-list %s permit %s\n", ip, l.Name, p)
			case int(r.Lo()) > p.Bits():
				fmt.Fprintf(&b, "%s prefix-list %s permit %s ge %d le %d\n", ip, l.Name, p, r.Lo(), r.Hi())
			default:
				fmt.Fprintf(&b, "%s prefix-list %s permit %s le %d\n", ip, l.Name, p, r.Hi())
			}
		}
	case JSON:
		fmt.Fprintf(&b, "{ \"%s\": [", l.Name)
		for i, r := range rs {
			comma := ""
			if i > 0 {
				comma = ","
			}
			p := jsonPrefix(r.Prefix())
			switch {
			case exact(r):
				fmt.Fprintf(&b, "%s\n    { \"prefix\": \"%s\", \"exact\": true }", comma, p)
			case int(r.Lo()) > r.Prefix().Bits():
				fmt.Fprintf(&b, "%s\n    { \"prefix\": \"%s\", \"exact\": false,\n      \"greater-equal\": %d, \"less-equal\": %d }", comma, p, r.Lo(), r.Hi())
			default:
				fmt.Fprintf(&b, "%s\n    { \"prefix\": \"%s\", \"exact\": false, \"less-equal\": %d }", comma, p, r.Hi())
			}
		}
		b.WriteString("\n] }\n")
	case BIRD:
		if len(rs) == 0 {
			break // bgpq4 prints an empty BIRD list as nothing at all
		}
		fmt.Fprintf(&b, "%s = [", l.Name)
		for i, r := range rs {
			comma := ""
			if i > 0 {
				comma = ","
			}
			if exact(r) {
				fmt.Fprintf(&b, "%s\n    %s", comma, r.Prefix())
			} else {
				fmt.Fprintf(&b, "%s\n    %s{%d,%d}", comma, r.Prefix(), r.Lo(), r.Hi())
			}
		}
		b.WriteString("\n];\n")
	case Junos:
		for _, r := range rs {
			if !exact(r) {
				return fmt.Errorf("%w: a Junos prefix-list holds exact prefixes, and %s is a range", ErrUnsupported, r)
			}
		}
		fmt.Fprintf(&b, "policy-options {\nreplace:\n prefix-list %s {\n", l.Name)
		for _, r := range rs {
			fmt.Fprintf(&b, "    %s;\n", r.Prefix())
		}
		b.WriteString(" }\n}\n")
	case Plain:
		for _, r := range rs {
			b.WriteString(r.String() + "\n")
		}
	default:
		return fmt.Errorf("%w: unknown format %s", ErrUnsupported, f)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// jsonPrefix writes a prefix as bgpq4's JSON does, its slash escaped.
func jsonPrefix(p netip.Prefix) string {
	return fmt.Sprintf("%s\\/%d", p.Addr(), p.Bits())
}

// asWidth is how many AS numbers bgpq4 -t puts on a line.
const asWidth = 8

// WriteASList writes a list of AS numbers, sorted, as bgpq4 -t writes it in
// JSON or BIRD; Plain writes one per line. Other formats have no AS list.
func WriteASList(w io.Writer, f Format, name string, asns []types.ASN) error {
	as := append([]types.ASN(nil), asns...)
	sort.Slice(as, func(i, j int) bool { return as[i] < as[j] })
	var b strings.Builder
	switch f {
	case JSON:
		fmt.Fprintf(&b, "{\"%s\": [", name)
		for i, a := range as {
			switch {
			case i == 0:
				fmt.Fprintf(&b, "\n  %d", uint32(a))
			case i%asWidth == 0:
				fmt.Fprintf(&b, ",\n  %d", uint32(a))
			default:
				fmt.Fprintf(&b, ",%d", uint32(a))
			}
		}
		b.WriteString("\n]}\n")
	case BIRD:
		fmt.Fprintf(&b, "%s = [", name)
		if len(as) == 0 {
			b.WriteString("];\n")
			break
		}
		for i, a := range as {
			switch {
			case i == 0:
				fmt.Fprintf(&b, "\n    %d", uint32(a))
			case i%asWidth == 0:
				fmt.Fprintf(&b, ",\n    %d", uint32(a))
			default:
				fmt.Fprintf(&b, ", %d", uint32(a))
			}
		}
		b.WriteString("\n];\n")
	case Plain:
		for _, a := range as {
			b.WriteString(a.String() + "\n")
		}
	default:
		return fmt.Errorf("%w: an AS list in %s", ErrUnsupported, f)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// MaxLen drops the prefixes longer than n and clamps a range reaching past n,
// as bgpq4 -m does.
func MaxLen(rs []types.PrefixRange, n int) []types.PrefixRange {
	var out []types.PrefixRange
	for _, r := range rs {
		if int(r.Lo()) > n {
			continue
		}
		hi := int(r.Hi())
		if hi > n {
			hi = n
		}
		if c, ok := types.NewPrefixRange(r.Prefix(), int(r.Lo()), hi); ok {
			out = append(out, c)
		}
	}
	return out
}

// Enumerate returns the exact prefixes the ranges hold, each once, refusing
// to produce more than max: bgpq4 lists every prefix a range holds unless it
// is asked to aggregate.
func Enumerate(rs []types.PrefixRange, max int) ([]types.PrefixRange, error) {
	seen := map[netip.Prefix]bool{}
	var out []types.PrefixRange
	for _, r := range rs {
		for p := range r.All() {
			if seen[p] {
				continue
			}
			if len(seen) >= max {
				return nil, fmt.Errorf("filtergen: more than %d prefixes", max)
			}
			seen[p] = true
			e, _ := types.NewPrefixRange(p, p.Bits(), p.Bits())
			out = append(out, e)
		}
	}
	return out, nil
}
