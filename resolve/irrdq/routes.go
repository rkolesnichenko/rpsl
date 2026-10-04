package irrdq

import (
	"context"
	"math"
	"net/netip"
	"slices"
	"strings"
	"unicode"

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

// parseAS reads an AS number as IRRd's parse_as_number does
// (irrd/utils/validators.py, without asdot, which IRRd's default
// configuration leaves off): the value upper-cased, not trimmed — a "!g"
// parameter is the line after "!g", the line itself stripped — must start
// with "AS", and the rest is read by Python's int(): surrounding
// whitespace, a sign, decimal digits (any script's) with single
// underscores between them. A number outside 0-4294967295, negative ones
// included, is out of range. msg is IRRd's refusal, naming the value
// upper-cased, or "" for an AS number.
func parseAS(s string) (as types.ASN, msg string) {
	v := strings.ToUpper(s)
	num, ok := strings.CutPrefix(v, "AS")
	if !ok {
		return 0, "Invalid AS number " + v + `: must start with "AS"`
	}
	n, inRange, ok := pyInt(num)
	switch {
	case !ok:
		return 0, "Invalid AS number " + v + ": number part is not numeric"
	case !inRange:
		return 0, "Invalid AS number " + v + ": valid range is 0-4294967295"
	}
	return types.ASN(n), ""
}

// maxIntDigits is Python's default limit on the digits int() converts
// (sys.int_info.default_max_str_digits): a longer string is a ValueError.
const maxIntDigits = 4300

// pyInt reads s as Python's int(s) does: ok is false where int raises
// ValueError, inRange whether the value is in 0-4294967295, and n the value
// when it is.
func pyInt(s string) (n uint64, inRange, ok bool) {
	s = strings.TrimFunc(s, pySpace)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	digits, prevDigit, overflow := 0, false, false
	for _, r := range s {
		if r == '_' {
			if !prevDigit {
				return 0, false, false
			}
			prevDigit = false
			continue
		}
		d, isDigit := digitValue(r)
		if !isDigit {
			return 0, false, false
		}
		digits++
		prevDigit = true
		if n = n*10 + uint64(d); n > math.MaxUint32 {
			overflow, n = true, math.MaxUint32+1 // no further growth: it is out of range
		}
	}
	if digits == 0 || !prevDigit || digits > maxIntDigits {
		return 0, false, false
	}
	return n, !overflow && (!neg || n == 0), true
}

// pySpace reports whether Python's str.isspace() holds for r: Go's
// unicode.IsSpace and the separators U+001C-U+001F.
func pySpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

// digitValue is the value of a decimal digit of any script (Unicode Nd),
// as Python's int() reads it. Nd digits come in runs of whole 0-9 blocks,
// so a digit's value is its distance from its run's start, modulo 10.
func digitValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if !unicode.IsDigit(r) {
		return 0, false
	}
	start := r
	for start > 0 && unicode.IsDigit(start-1) {
		start--
	}
	return int(r-start) % 10, true
}

// cmdOriginated answers "!g" (afi AFIv4) and "!6" (AFIv6): the distinct
// prefixes of that family the AS originates in the selected registries.
func cmdOriginated(ctx context.Context, s *Session, snap *Snapshot, arg string, afi types.AFI) Reply {
	as, msg := parseAS(arg)
	if msg != "" {
		return Fail(msg)
	}
	ps, err := snap.originated(ctx, snap.selected(s.sources(snap)), as, afi)
	if err != nil {
		return internalErr(err)
	}
	return s.newAnswer().prefixes(ps)
}

// prefixes is the answer listing ps, or "D" when it is empty; each prefix is
// written out only while the answer is within its budget.
func (a *answer) prefixes(ps []netip.Prefix) Reply {
	if len(ps) == 0 {
		return notFound
	}
	for i, p := range ps {
		if i > 0 {
			a.add(" ")
		}
		if !a.addPrefix(p) {
			break
		}
	}
	a.add("\n")
	return a.frame()
}

// originated is the distinct prefixes as originates in regs, of afi
// (AFIUnspecified or AFIAny: both), sorted (prefixCmp), without the routes
// RPKI-aware mode hides (visible); err is a Source's error or ctx's.
func (snap *Snapshot) originated(ctx context.Context, regs []*Registry, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	if afi == types.AFIUnspecified {
		afi = types.AFIAny
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, r := range regs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ps, err := r.src.OriginatedRoutes(ctx, as, afi)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			p = p.Masked()
			if !seen[p] && snap.routeVisible(r, p, as) {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, prefixCmp)
	return out, nil
}
