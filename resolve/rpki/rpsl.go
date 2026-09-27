package rpki

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// PseudoSource is the source: of the route objects IRRd makes from ROAs.
const PseudoSource = "RPKI"

// pseudoRemarks is IRRd's default rpki.pseudo_irr_remarks, continuation lines
// already indented to the value column.
const pseudoRemarks = "This AS%d route object represents routing data retrieved\n" +
	"                from the RPKI. This route object is the result of an automated\n" +
	"                RPKI-to-IRR conversion process performed by IRRd."

// WriteRPSL writes the pseudo route and route6 objects IRRd 4 makes from the
// VRPs (irrd/rpki/importer.py, RPSLObjectFromROA), byte for byte as IRRd
// serves them with its default remarks, separated by blank lines: a dump that
// resolve.DumpLoader reads as the registry PseudoSource. There is one object
// per prefix, ASN and maxLength — IRRd's key for them — so a VRP repeated
// under another trust anchor adds none; the first one's TA is written. A
// pseudo object's route is the VRP's prefix alone, not the more specifics its
// maxLength allows: that is what IRRd's !g answers.
func (s *VRPs) WriteRPSL(w io.Writer) error {
	type key struct {
		p   netip.Prefix
		asn types.ASN
		max uint8
	}
	bw := bufio.NewWriter(w)
	seen := map[key]bool{}
	for v := range s.All() {
		k := key{v.Prefix, v.ASN, v.MaxLength}
		if seen[k] {
			continue
		}
		if len(seen) > 0 {
			bw.WriteByte('\n')
		}
		seen[k] = true
		class := "route"
		if v.Prefix.Addr().Is6() {
			class = "route6"
		}
		fmt.Fprintf(bw, "%-16s%s\n", class+":", v.Prefix)
		fmt.Fprintf(bw, "descr:          RPKI ROA for %s / AS%d\n", v.Prefix, uint32(v.ASN))
		fmt.Fprintf(bw, "remarks:        "+pseudoRemarks+"\n", uint32(v.ASN))
		fmt.Fprintf(bw, "max-length:     %d\n", v.MaxLength)
		fmt.Fprintf(bw, "origin:         AS%d\n", uint32(v.ASN))
		fmt.Fprintf(bw, "source:         %s  # Trust Anchor: %s\n", PseudoSource, oneLine(v.TA))
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("rpki: writing pseudo objects: %w", err)
	}
	return nil
}

// oneLine keeps a trust anchor name from breaking the object it is written
// into: a line break would start a new attribute or end the object.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}
