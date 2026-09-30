package rtconfig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// community is a standard BGP community (RFC 1997), high and low 16 bits.
type community struct{ hi, lo uint16 }

// The well-known communities RPSL names (RFC 2622 §7).
var (
	noExport          = community{0xFFFF, 0xFF01}
	noAdvertise       = community{0xFFFF, 0xFF02}
	noExportSubconfed = community{0xFFFF, 0xFF03}
)

// parseCommunity reads a community as RPSL writes one: a:b (each at most
// 65535), a 32-bit decimal, or a well-known name. Large and extended
// communities, and "internet", are not read.
func parseCommunity(s string) (community, bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "no_export":
		return noExport, true
	case "no_advertise":
		return noAdvertise, true
	case "no_export_subconfed":
		return noExportSubconfed, true
	}
	if a, b, ok := strings.Cut(t, ":"); ok {
		hi, err1 := strconv.ParseUint(a, 10, 16)
		lo, err2 := strconv.ParseUint(b, 10, 16)
		if err1 != nil || err2 != nil {
			return community{}, false
		}
		return community{uint16(hi), uint16(lo)}, true
	}
	v, err := strconv.ParseUint(t, 10, 32)
	if err != nil {
		return community{}, false
	}
	return community{uint16(v >> 16), uint16(v)}, true
}

// String renders the community as a:b.
func (c community) String() string { return fmt.Sprintf("%d:%d", c.hi, c.lo) }

// spell renders the community as the vendor writes it.
func (c community) spell(v Vendor) string {
	if v == BIRD2 {
		return fmt.Sprintf("(%d,%d)", c.hi, c.lo)
	}
	switch c {
	case noExport:
		return "no-export"
	case noAdvertise:
		return "no-advertise"
	case noExportSubconfed:
		if v == Junos {
			return "no-export-subconfed"
		}
		return "local-AS"
	}
	return c.String()
}

// parseCommunities reads a list of community values, each once, sorted.
func (g *Generator) parseCommunities(vals []string, term string) ([]community, error) {
	seen := map[community]bool{}
	var out []community
	for _, v := range vals {
		c, ok := parseCommunity(v)
		if !ok {
			return nil, unsupported(g.Vendor, CauseCommunityForm, term)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].hi < out[j].hi || out[i].hi == out[j].hi && out[i].lo < out[j].lo })
	return out, nil
}
