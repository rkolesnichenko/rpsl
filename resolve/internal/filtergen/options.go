package filtergen

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Vendor is an output target, named after bgpq4's option for it.
type Vendor uint8

const (
	Cisco      Vendor = iota // Cisco IOS, bgpq4's default
	CiscoXR                  // -X
	JSON                     // -j
	BIRD                     // -b
	Junos                    // -J
	OpenBGPD                 // -B
	Arista                   // -e
	Nokia                    // -N, SR OS classic CLI
	NokiaMD                  // -n, SR OS MD-CLI
	NokiaSRL                 // -n2, SR Linux
	MikroTik6                // -K, RouterOS v6
	MikroTik7                // -K7, RouterOS v7
	Huawei                   // -U
	HuaweiXPL                // -u
	UserFormat               // -F, Options.Format
	Plain                    // rpslq's -P: RPSL notation, one entry per line
)

var vendorNames = [...]string{"Cisco IOS", "Cisco IOS XR", "JSON", "BIRD", "Junos", "OpenBGPD", "Arista EOS",
	"Nokia SR OS", "Nokia SR OS MD-CLI", "Nokia SR Linux", "MikroTik RouterOS v6", "MikroTik RouterOS v7",
	"Huawei", "Huawei XPL", "a user format", "plain"}

func (v Vendor) String() string {
	if int(v) < len(vendorNames) {
		return vendorNames[v]
	}
	return fmt.Sprintf("Vendor(%d)", uint8(v))
}

// Kind is what a list holds and how it is used: bgpq4's "generation".
type Kind uint8

const (
	PrefixList      Kind = iota // bgpq4's default
	ASSet                       // -t: the AS numbers themselves
	ASPath                      // -f AS: an input as-path filter
	OriginASPath                // -G AS: an output as-path filter
	ASList                      // -H AS: Junos as-list-group
	RouteFilter                 // -E: route-filter, extended access-list, prefix-set
	RouteFilterList             // -z: Junos route-filter-list
)

var kindNames = [...]string{"prefix-lists", "as-sets (-t)", "as-path lists (-f)", "output as-path lists (-G)",
	"as-lists (-H)", "route-filters (-E)", "route-filter-lists (-z)"}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// asKind reports whether a kind is written from AS numbers rather than prefixes.
func (k Kind) asKind() bool { return k >= ASSet && k <= ASList }

// Options say what to write and how.
type Options struct {
	Vendor   Vendor
	Kind     Kind
	Name     string    // the list's name (-l); "" is bgpq4's "NN"
	V6       bool      // an IPv6 list (-6)
	AS       types.ASN // -f, -G and -H's AS, and OpenBGPD's -a
	Width    int       // AS numbers per line (-W); 0 is unlimited. See DefaultWidth.
	Sequence bool      // sequence numbers (-s; Arista always has them)
	Match    string    // extra Junos route-filter conditions (-M), escapes decoded
	Format   string    // the UserFormat template (-F)
}

func (o Options) name() string {
	if o.Name == "" {
		return "NN"
	}
	return o.Name
}

// DefaultWidth is how many AS numbers bgpq4 puts on a line of an as-path or
// AS list when -W does not say.
func DefaultWidth(v Vendor, k Kind) int {
	switch k {
	case ASPath:
		switch v {
		case Arista, Cisco, MikroTik6, MikroTik7:
			return 4
		case CiscoXR:
			return 6
		case BIRD:
			return 10
		}
	case OriginASPath:
		switch v {
		case Arista, Cisco:
			return 5
		case CiscoXR:
			return 7
		}
	}
	return 8
}

// ErrUnsupported reports a list a vendor cannot express, or options bgpq4
// refuses together.
var ErrUnsupported = errors.New("filtergen: not supported")

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}

// supports reports whether bgpq4 writes kind k for vendor v at all.
func supports(v Vendor, k Kind) bool {
	if v == Plain {
		return k == PrefixList || k == ASSet
	}
	switch k {
	case PrefixList:
		return true
	case ASSet:
		return v == JSON || v == OpenBGPD || v == BIRD
	case ASPath:
		switch v {
		case Junos, Cisco, Arista, CiscoXR, JSON, BIRD, OpenBGPD, Nokia, NokiaMD, Huawei, HuaweiXPL:
			return true
		}
	case OriginASPath:
		switch v {
		case Junos, Cisco, Arista, CiscoXR, OpenBGPD, Nokia, NokiaMD, Huawei, HuaweiXPL:
			return true
		}
	case ASList, RouteFilterList:
		return v == Junos
	case RouteFilter:
		switch v {
		case Junos, Cisco, Arista, OpenBGPD, Nokia, NokiaMD, NokiaSRL:
			return true
		}
	}
	return false
}

// Check applies bgpq4's rules for what goes together (its main.c): which
// vendors write which kinds of list, and where aggregation (-A),
// more-specifics (-R, -r) and sequence numbers (-s) apply.
func (o Options) Check(aggregate bool, refine, refineLow int) error {
	if !supports(o.Vendor, o.Kind) {
		return unsupported("%s writes no %s", o.Vendor, o.Kind)
	}
	nokia := o.Vendor == Nokia || o.Vendor == NokiaMD || o.Vendor == NokiaSRL
	switch {
	case aggregate && o.Vendor == Junos && o.Kind == PrefixList:
		return unsupported("aggregation (-A) does not work in Junos prefix-lists; try route-filters (-E) or route-filter-lists (-z)")
	case aggregate && nokia && o.Kind != PrefixList:
		return unsupported("aggregation (-A) works only in Nokia prefix-lists")
	case (refine > 0 || refineLow > 0) && nokia && o.Kind != PrefixList:
		return unsupported("more-specifics (-R, -r) work only in Nokia prefix-lists")
	case aggregate && o.Kind.asKind():
		return unsupported("aggregation (-A) is for prefix-lists, access-lists and route-filters")
	case o.Kind == RouteFilter && o.V6 && (o.Vendor == Arista || o.Vendor == Cisco):
		return unsupported("%s extended access-lists are IPv4 only", o.Vendor)
	case o.Sequence && o.Vendor != Cisco && o.Vendor != Arista:
		return unsupported("sequence numbers (-s) are for Cisco IOS and Arista EOS prefix-lists")
	case o.Sequence && o.Kind.asKind():
		return unsupported("sequence numbers (-s) are for prefix-lists")
	case (refine > 0 || refineLow > 0) && o.Vendor == Junos && o.Kind == PrefixList:
		return unsupported("more-specifics (-R, -r) do not work in Junos prefix-lists; try route-filters (-E) or route-filter-lists (-z)")
	case (refine > 0 || refineLow > 0) && o.Kind.asKind():
		return unsupported("more-specifics (-R, -r) are for prefix-lists")
	case o.Match != "" && (o.Vendor != Junos || o.Kind != RouteFilter):
		return unsupported("extra match conditions (-M) are for Junos route-filters (-J -E)")
	case o.Vendor == UserFormat:
		return checkFormat(o.Format)
	}
	return nil
}

// checkFormat refuses a -F template bgpq4 would print only part of: an
// unknown directive, or a lone % or \ at the end, where bgpq4 reads past the
// template.
func checkFormat(f string) error {
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case '%':
			if i+1 == len(f) || !strings.ContainsRune("rnlaA%Nmi", rune(f[i+1])) {
				if i+1 == len(f) {
					return unsupported("-F ends in a lone %%")
				}
				return unsupported("unknown directive %%%c in -F", f[i+1])
			}
			i++
		case '\\':
			if i+1 == len(f) {
				return unsupported("-F ends in a lone \\")
			}
			i++
		}
	}
	return nil
}
