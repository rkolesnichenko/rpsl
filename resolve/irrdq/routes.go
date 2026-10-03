package irrdq

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

func init() {
	commands['g'] = func(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
		return cmdOriginated(ctx, s, snap, arg, types.AFIv4)
	}
	commands['6'] = func(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
		return cmdOriginated(ctx, s, snap, arg, types.AFIv6)
	}
}

// parseAS reads an AS number as IRRd's parse_as_number does: trimmed and
// upper-cased, "AS" then decimal digits, at most 4294967295 (no asdot, no
// range operator). msg is IRRd's refusal, naming the value upper-cased, or
// "" for an AS number.
func parseAS(s string) (as types.ASN, msg string) {
	v := strings.ToUpper(strings.TrimSpace(s))
	num, ok := strings.CutPrefix(v, "AS")
	if !ok {
		return 0, "Invalid AS number " + v + `: must start with "AS"`
	}
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return 0, "Invalid AS number " + v + ": number part is not numeric"
	}
	n, err := strconv.ParseUint(num, 10, 32)
	if err != nil {
		return 0, "Invalid AS number " + v + ": valid range is 0-4294967295"
	}
	return types.ASN(n), ""
}

// cmdOriginated answers "!g" (afi AFIv4) and "!6" (AFIv6): the distinct
// prefixes of that family the AS originates in the selected registries.
func cmdOriginated(ctx context.Context, s *Session, snap *Snapshot, arg string, afi types.AFI) Reply {
	as, msg := parseAS(arg)
	if msg != "" {
		return Fail(msg)
	}
	return prefixes(snap.originated(ctx, snap.selected(s.sources(snap)), as, afi))
}

// prefixes is the answer listing ps, or "D" when it is empty.
func prefixes(ps []netip.Prefix) Reply {
	if len(ps) == 0 {
		return notFound
	}
	words := make([]string, len(ps))
	for i, p := range ps {
		words[i] = p.String()
	}
	return frame(strings.Join(words, " "))
}

// originated is the distinct prefixes as originates in regs, of afi
// (AFIUnspecified or AFIAny: both), sorted (prefixCmp). Task 7 drops
// RPKI-invalid ones.
func (snap *Snapshot) originated(ctx context.Context, regs []*Registry, as types.ASN, afi types.AFI) []netip.Prefix {
	if afi == types.AFIUnspecified {
		afi = types.AFIAny
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, r := range regs {
		if ctx.Err() != nil {
			return nil
		}
		ps, _ := r.src.OriginatedRoutes(ctx, as, afi)
		for _, p := range ps {
			p = p.Masked()
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, prefixCmp)
	return out
}
