package rpslconf

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// printMax caps printPrefixes: Expander.MaxPrefixes's default.
const printMax = 1 << 20

var errPrintShape = errors.New("a print command's filter must be prefix ranges alone (no regexp, community test or NOT)")

// printPrefixes writes nf's prefix ranges through format (printPrefixRanges),
// or, with each, every prefix they hold, one at a time (printPrefixes).
func printPrefixes(w io.Writer, format string, nf resolve.NormalFilter, afi types.AFI, each bool) error {
	var ranges []types.PrefixRange
	switch len(nf.Conjuncts) {
	case 0: // matches nothing: nothing to print
	case 1:
		c := nf.Conjuncts[0]
		if len(c.Paths) > 0 || len(c.Communities) > 0 || c.NotPrefixes.Len() > 0 {
			return errPrintShape
		}
		if !c.AnyPrefix() {
			ranges = c.Prefixes.List()
			break
		}
		whole := netip.MustParsePrefix("0.0.0.0/0")
		if afi == types.AFIv6 {
			whole = netip.MustParsePrefix("::/0")
		}
		r, _ := types.NewPrefixRange(whole, 0, whole.Addr().BitLen())
		ranges = []types.PrefixRange{r}
	default:
		return errPrintShape
	}
	var b strings.Builder
	n := 0
	for _, r := range ranges {
		if !each {
			b.WriteString(renderFormat(format, r))
			continue
		}
		for p := range r.All() {
			if n++; n > printMax {
				return fmt.Errorf("printPrefixes: more than %d prefixes; printPrefixRanges prints them as ranges", printMax)
			}
			exact, _ := types.NewPrefixRange(p, p.Bits(), p.Bits())
			b.WriteString(renderFormat(format, exact))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// renderFormat writes one range through a format checkFormat accepted.
func renderFormat(format string, r types.PrefixRange) string {
	p := r.Prefix()
	bits, size := p.Bits(), p.Addr().BitLen()
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' && c != '\\' || i+1 == len(format) {
			b.WriteByte(c)
			continue
		}
		i++
		switch format[i-1 : i+1] {
		case "%p":
			b.WriteString(p.Addr().String())
		case "%l":
			b.WriteString(strconv.Itoa(bits))
		case "%L":
			b.WriteString(strconv.Itoa(size - bits))
		case "%n":
			b.WriteString(strconv.Itoa(r.Lo()))
		case "%m":
			b.WriteString(strconv.Itoa(r.Hi()))
		case "%k":
			b.WriteString(mask(bits, size, false))
		case "%K":
			b.WriteString(mask(bits, size, true))
		case "%%":
			b.WriteByte('%')
		case `\n`:
			b.WriteByte('\n')
		case `\t`:
			b.WriteByte('\t')
		case `\\`:
			b.WriteByte('\\')
		}
	}
	return b.String()
}

// mask writes a netmask of bits ones in a size-bit address, or its inverse.
func mask(bits, size int, inverse bool) string {
	m := make([]byte, size/8)
	for i := 0; i < bits; i++ {
		m[i/8] |= 0x80 >> (i % 8)
	}
	if inverse {
		for i := range m {
			m[i] = ^m[i]
		}
	}
	a, _ := netip.AddrFromSlice(m)
	return a.String()
}
