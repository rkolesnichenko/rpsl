package filtergen

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// WriteASNs writes a list made of AS numbers — an AS set (-t), an input or
// output as-path filter (-f, -G) or a Junos as-list (-H) — in o's vendor
// format, the numbers in ascending order, o.Width to a line (0: all on one).
// For -f, -G and -H, o.AS is the neighbour's own AS: a path of it alone is
// written first, and the list then allows paths through it (-f) or ending in
// one of the others (-G).
func WriteASNs(w io.Writer, o Options, asns []types.ASN) error {
	if !o.Kind.asKind() {
		return unsupported("%s are written from prefixes", o.Kind)
	}
	if !supports(o.Vendor, o.Kind) {
		return unsupported("%s writes no %s", o.Vendor, o.Kind)
	}
	as := slices.Clone(asns)
	slices.Sort(as)
	as = slices.Compact(as)
	var b strings.Builder
	switch o.Kind {
	case ASSet:
		asSet(&b, o, as)
	case ASPath:
		asPath(&b, o, as)
	case OriginASPath:
		originASPath(&b, o, as)
	case ASList:
		asList(&b, o, as)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// lines splits as into the lines of an as-path list: width to a line, or all
// on one when width is 0.
func lines(as []types.ASN, width int) [][]types.ASN {
	var out [][]types.ASN
	for len(as) > 0 {
		n := len(as)
		if width > 0 && width < n {
			n = width
		}
		out = append(out, as[:n])
		as = as[n:]
	}
	return out
}

// own removes o.AS from as and reports whether it was there: the neighbour's
// own AS gets a line of its own.
func own(o Options, as []types.ASN) ([]types.ASN, bool) {
	i := slices.Index(as, o.AS)
	if i < 0 {
		return as, false
	}
	return slices.Delete(slices.Clone(as), i, i+1), true
}

func join(as []types.ASN, sep string) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = fmt.Sprint(uint32(a))
	}
	return strings.Join(s, sep)
}

func asSet(b *strings.Builder, o Options, as []types.ASN) {
	name := o.name()
	switch o.Vendor {
	case JSON:
		jsonASNs(b, o, as)
	case BIRD:
		birdASNs(b, o, as)
	case OpenBGPD:
		fmt.Fprintf(b, "as-set %s {", name)
		for i, a := range as {
			sep := " "
			if o.Width == 0 && i == 0 || o.Width > 0 && i%o.Width == 0 {
				sep = "\n\t"
			}
			fmt.Fprintf(b, "%s%d", sep, uint32(a))
		}
		b.WriteString("\n}\n")
	case Plain:
		for _, a := range as {
			b.WriteString(a.String() + "\n")
		}
	}
}

func jsonASNs(b *strings.Builder, o Options, as []types.ASN) {
	fmt.Fprintf(b, "{\"%s\": [", o.name())
	for i, a := range as {
		switch {
		case i == 0:
			fmt.Fprintf(b, "\n  %d", uint32(a))
		case o.Width > 0 && i%o.Width == 0:
			fmt.Fprintf(b, ",\n  %d", uint32(a))
		default:
			fmt.Fprintf(b, ",%d", uint32(a))
		}
	}
	b.WriteString("\n]}\n")
}

func birdASNs(b *strings.Builder, o Options, as []types.ASN) {
	fmt.Fprintf(b, "%s = [", o.name())
	if len(as) == 0 {
		b.WriteString("];\n")
		return
	}
	for i, a := range as {
		switch {
		case i == 0:
			fmt.Fprintf(b, "\n    %d", uint32(a))
		case o.Width > 0 && i%o.Width == 0:
			fmt.Fprintf(b, ",\n    %d", uint32(a))
		default:
			fmt.Fprintf(b, ", %d", uint32(a))
		}
	}
	b.WriteString("\n];\n")
}

// asPath writes -f: paths from the neighbour o.AS, through anything, to one
// of the ASes.
func asPath(b *strings.Builder, o Options, all []types.ASN) {
	name, me := o.name(), uint32(o.AS)
	as, mine := own(o, all)
	ls := lines(as, o.Width)
	switch o.Vendor {
	case Cisco, Arista:
		fmt.Fprintf(b, "no ip as-path access-list %s\n", name)
		if len(all) == 0 {
			fmt.Fprintf(b, "ip as-path access-list %s deny .*\n", name)
			return
		}
		if mine {
			fmt.Fprintf(b, "ip as-path access-list %s permit ^%d(_%d)*$\n", name, me, me)
		}
		for _, l := range ls {
			fmt.Fprintf(b, "ip as-path access-list %s permit ^%d(_[0-9]+)*_(%s)$\n", name, me, join(l, "|"))
		}
	case CiscoXR:
		fmt.Fprintf(b, "as-path-set %s", name)
		comma := ""
		if mine {
			fmt.Fprintf(b, "\n  ios-regex '^%d(_%d)*$'", me, me)
			comma = ","
		}
		for _, l := range ls {
			fmt.Fprintf(b, "%s\n  ios-regex '^%d(_[0-9]+)*_(%s)$'", comma, me, join(l, "|"))
			comma = ","
		}
		b.WriteString("\nend-set\n")
	case Junos:
		fmt.Fprintf(b, "policy-options {\nreplace:\n as-path-group %s {\n", name)
		n := 0
		if mine {
			fmt.Fprintf(b, "  as-path a0 \"^%d(%d)*$\";\n", me, me)
			n++
		}
		for _, l := range ls {
			fmt.Fprintf(b, "  as-path a%d \"^%d(.)*(%s)$\";\n", n, me, join(l, "|"))
			if len(l) == o.Width {
				n++
			}
		}
		if len(ls) == 0 && n == 0 {
			b.WriteString("  as-path aNone \"!.*\";\n")
		}
		b.WriteString(" }\n}\n")
	case JSON:
		jsonASNs(b, o, all)
	case BIRD:
		birdASNs(b, o, all)
	case OpenBGPD:
		if len(all) == 0 {
			fmt.Fprintf(b, "deny from AS %d\n", me)
		}
		for _, a := range all {
			fmt.Fprintf(b, "allow from AS %d AS %d\n", me, uint32(a))
		}
	case Nokia:
		fmt.Fprintf(b, "configure router policy-options\nbegin\nno as-path-group \"%s\"\nas-path-group \"%s\"\n", name, name)
		n := 1
		if mine {
			fmt.Fprintf(b, "  entry 1 expression \"%d+\"\n", me)
			n++
		}
		for i, l := range ls {
			fmt.Fprintf(b, "  entry %d expression \"%d.*[%s]\"\n", n+i, me, join(l, " "))
		}
		b.WriteString("exit\ncommit\n")
	case NokiaMD:
		fmt.Fprintf(b, "/configure policy-options\ndelete as-path-group \"%s\"\nas-path-group \"%s\" {\n", name, name)
		n := 1
		if mine {
			fmt.Fprintf(b, "  entry 1 {\n    expression \"%d+\"\n  }\n", me)
			n++
		}
		for i, l := range ls {
			fmt.Fprintf(b, "  entry %d {\n    expression \"%d.*[%s]\"\n  }\n", n+i, me, join(l, " "))
		}
		b.WriteString("}\n")
	case Huawei:
		fmt.Fprintf(b, "undo ip as-path-filter %s\n", name)
		if len(all) == 0 {
			fmt.Fprintf(b, "ip as-path-filter %s deny .*\n", name)
			return
		}
		if mine {
			fmt.Fprintf(b, "ip as-path-filter %s permit ^%d(_%d)*$\n", name, me, me)
		}
		for _, l := range ls {
			fmt.Fprintf(b, "ip as-path-filter %s permit ^%d(_[0-9]+)*_(%s)$\n", name, me, join(l, "|"))
		}
	case HuaweiXPL:
		fmt.Fprintf(b, "xpl as-path-list %s", name)
		if mine {
			fmt.Fprintf(b, "\n  regular ^%d(_%d)*$", me, me)
		}
		// bgpq4 starts every line of this list with a comma, the first too.
		for _, l := range ls {
			fmt.Fprintf(b, ",\n  regular ^%d(_[0-9]+)*_(%s)$", me, join(l, "|"))
		}
		b.WriteString("\nend-list\n")
	}
}

// originASPath writes -G: paths that end in one of the ASes, announced to
// the neighbour o.AS.
func originASPath(b *strings.Builder, o Options, all []types.ASN) {
	name, me := o.name(), uint32(o.AS)
	as, mine := own(o, all)
	ls := lines(as, o.Width)
	switch o.Vendor {
	case Cisco, Arista:
		fmt.Fprintf(b, "no ip as-path access-list %s\n", name)
		if len(all) == 0 {
			fmt.Fprintf(b, "ip as-path access-list %s deny .*\n", name)
			return
		}
		if mine {
			fmt.Fprintf(b, "ip as-path access-list %s permit ^(_%d)*$\n", name, me)
		}
		for _, l := range ls {
			fmt.Fprintf(b, "ip as-path access-list %s permit ^(_[0-9]+)*_(%s)$\n", name, join(l, "|"))
		}
	case CiscoXR:
		fmt.Fprintf(b, "as-path-set %s", name)
		comma := ""
		if mine {
			fmt.Fprintf(b, "\n  ios-regex '^(_%d)*$'", me)
			comma = ","
		}
		for _, l := range ls {
			fmt.Fprintf(b, "%s\n  ios-regex '^(_[0-9]+)*_(%s)$'", comma, join(l, "|"))
			comma = ","
		}
		b.WriteString("\nend-set\n")
	case Junos:
		fmt.Fprintf(b, "policy-options {\nreplace:\n as-path-group %s {\n", name)
		n := 0
		if mine {
			fmt.Fprintf(b, "  as-path a0 \"^%d(%d)*$\";\n", me, me)
			n++
		}
		for _, l := range ls {
			fmt.Fprintf(b, "  as-path a%d \"^(.)*(%s)$\";\n", n, join(l, "|"))
			if len(l) == o.Width {
				n++
			}
		}
		if len(ls) == 0 && n == 0 {
			b.WriteString(" as-path aNone \"!.*\";\n") // one space short, as bgpq4 writes it
		}
		b.WriteString(" }\n}\n")
	case OpenBGPD:
		if len(all) == 0 {
			fmt.Fprintf(b, "deny to AS %d\n", me)
		}
		for _, a := range all {
			fmt.Fprintf(b, "allow to AS %d AS %d\n", me, uint32(a))
		}
	case Nokia:
		// bgpq4 misses a space here, and writes no exit or commit.
		fmt.Fprintf(b, "configure router policy-options\nbegin\nno as-path-group\"%s\"\nas-path-group \"%s\"\n", name, name)
		n := 1
		if mine {
			fmt.Fprintf(b, "  entry 1 expression \"%d+\"\n", me)
			n++
		}
		for i, l := range ls {
			fmt.Fprintf(b, "  entry %d expression \".*[%s]\"\n", n+i, join(l, " "))
		}
	case NokiaMD:
		fmt.Fprintf(b, "/configure policy-options\ndelete as-path-group \"%s\"\nas-path-group \"%s\" {\n", name, name)
		n := 1
		if mine {
			fmt.Fprintf(b, "  entry 1 {\n    expression \"%d+\"\n  }\n", me)
			n++
		}
		for i, l := range ls {
			fmt.Fprintf(b, "  entry %d {\n    expression \".*[%s]\"\n  }\n", n+i, join(l, " "))
		}
		b.WriteString("}\n")
	case Huawei:
		fmt.Fprintf(b, "undo ip as-path-filter %s\n", name)
		if mine {
			fmt.Fprintf(b, "ip as-path-filter %s permit ^(_%d)*$\n", name, me)
		}
		if len(as) == 0 {
			fmt.Fprintf(b, "ip as-path-filter %s deny .*\n", name)
			return
		}
		for _, l := range ls {
			fmt.Fprintf(b, "ip as-path-filter %s permit ^(_[0-9]+)*_(%s)$\n", name, join(l, "|"))
		}
	case HuaweiXPL:
		fmt.Fprintf(b, "xpl as-path-list %s", name)
		comma := ""
		if mine {
			fmt.Fprintf(b, "\n  regular ^(_%d)*$", me)
			comma = ","
		}
		for _, l := range ls {
			fmt.Fprintf(b, "%s\n  regular ^(_[0-9]+)*_(%s)$", comma, join(l, "|"))
			comma = ","
		}
		b.WriteString("\nend-list\n")
	}
}

// asList writes -H, a Junos as-list-group; AS 0, which Junos refuses, is left
// out of its line but still counts toward the width.
func asList(b *strings.Builder, o Options, all []types.ASN) {
	fmt.Fprintf(b, "policy-options {\nreplace:\n as-list-group %s {\n", o.name())
	as, mine := own(o, all)
	n := 0
	if mine {
		fmt.Fprintf(b, "  as-list a0 members %d;\n", uint32(o.AS))
		n++
	}
	for _, l := range lines(as, o.Width) {
		fmt.Fprintf(b, "  as-list a%d members [", n)
		for _, a := range l {
			if a != 0 {
				fmt.Fprintf(b, " %d", uint32(a))
			}
		}
		b.WriteString(" ];\n")
		if len(l) == o.Width {
			n++
		}
	}
	b.WriteString(" }\n}\n")
}
