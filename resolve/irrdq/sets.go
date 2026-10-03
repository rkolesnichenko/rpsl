package irrdq

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func init() {
	commands['i'] = cmdMembers
	commands['a'] = cmdASetPrefixes
}

// normMember is one members:/mp-members: item as IRRd's parser stores it:
// an AS number upper-case and asplain, a prefix as netip prints it (zero-
// padded and abbreviated IPv4 read as IRRd reads them), a bare address as
// its host prefix, anything else upper-case; a range operator is kept as
// written after any of them.
func normMember(item string) string {
	base, op, hasOp := strings.Cut(strings.TrimSpace(item), "^")
	if as, msg := parseAS(base); msg == "" {
		base = as.String()
	} else if strings.Contains(base, "/") {
		if p, err := types.ParsePrefix(base); err == nil {
			base = p.String()
		} else {
			base = strings.ToUpper(base)
		}
	} else if a, err := types.ParseAddr(base); err == nil {
		base = netip.PrefixFrom(a, a.BitLen()).String()
	} else {
		base = strings.ToUpper(base)
	}
	if hasOp {
		return base + "^" + op
	}
	return base
}

// isASN reports whether s is an AS number as IRRd's parse_as_number reads
// one: "AS" then digits, no operator.
func isASN(s string) bool {
	_, msg := parseAS(s)
	return msg == ""
}

// isPrefixOrAddr reports whether s (a member, its operator cut) is an IP
// prefix or address.
func isPrefixOrAddr(s string) bool {
	if strings.Contains(s, "/") {
		_, err := types.ParsePrefix(s)
		return err == nil
	}
	_, err := types.ParseAddr(s)
	return err == nil
}

// setMembers returns the members of the set name — the first found among
// as-sets, then among route-sets (only as-sets when asOnly), in each of regs
// in order — and its class; found is false when no such set is held. Only
// as-sets and route-sets are looked up, and a set whose class is not its
// name's (route-set: AS-EVIL) is no set of that name. err is a Source's
// error other than resolve.ErrNotFound, or ctx's.
func (snap *Snapshot) setMembers(ctx context.Context, regs []*Registry, name string, asOnly bool) (members []string, class types.SetClass, found bool, err error) {
	n, perr := types.ParseSetName(name)
	if perr != nil {
		return nil, types.ClassUnknown, false, nil
	}
	classes := []types.SetClass{types.ClassAsSet, types.ClassRouteSet}
	if asOnly {
		classes = classes[:1]
	}
	for _, want := range classes {
		if n.Class() != want {
			continue
		}
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return nil, types.ClassUnknown, false, err
			}
			set, err := r.src.GetSet(ctx, types.Ref(n))
			if errors.Is(err, resolve.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, types.ClassUnknown, false, err
			}
			if set.Class() != want.String() {
				continue
			}
			ms, err := snap.membersOf(ctx, r, set)
			return ms, want, err == nil, err
		}
	}
	return nil, types.ClassUnknown, false, nil
}

// membersOf is a set's members:/mp-members: items, normalized, and the
// primary keys of the objects mbrs-by-ref admits (ClaimAllowed: the set's
// own source, its maintainers): aut-nums for an as-set, routes and route6s
// (their prefixes) for a route-set.
func (snap *Snapshot) membersOf(ctx context.Context, r *Registry, set object.NamedSet) ([]string, error) {
	var out []string
	if raw := set.Raw(); raw != nil {
		for _, attr := range []string{"members", "mp-members"} {
			for _, a := range raw.GetAll(attr) {
				for _, it := range a.List() {
					if it.Value != "" {
						out = append(out, normMember(it.Value))
					}
				}
			}
		}
	}
	claims, err := snap.claimants(ctx, r, set)
	if err != nil {
		return nil, err
	}
	return append(out, claims...), nil
}

// claimants are the keys of set's honoured member-of claimants in r (Task 7
// filters RPKI-invalid routes out of them).
func (snap *Snapshot) claimants(ctx context.Context, r *Registry, set object.NamedSet) ([]string, error) {
	objs, err := r.src.MembersByRef(ctx, set)
	if err != nil {
		return nil, err
	}
	var out []string
	isAS := set.Class() == types.ClassAsSet.String()
	for _, o := range objs {
		switch t := o.(type) {
		case object.AutNum:
			if isAS {
				out = append(out, t.AS.String())
			}
		case object.Route:
			if !isAS && t.Prefix.IsValid() {
				out = append(out, t.Prefix.Masked().String())
			}
		case object.Route6:
			if !isAS && t.Prefix.IsValid() {
				out = append(out, t.Prefix.Masked().String())
			}
		}
	}
	return out, nil
}

// recursive is IRRd's _recursive_set_resolve from the set name, level by
// level with every name seen skipped: a member that is a prefix or address
// (operator cut) is a result when the root is a route-set; an AS number is
// a result when the root is an as-set, and when it is a route-set the
// prefixes that AS originates in regs are (looked up once per AS); anything
// else is a name for the next level, looked up among as-sets alone under an
// as-set root. root fixes the root class (types.ClassAsSet for "!a");
// ClassUnknown takes the first set found's. The answer is sorted, distinct,
// without name itself (as sent: IRRd's removal is case-sensitive, though a
// result, a prefix or an AS number, is never a set's name).
func (snap *Snapshot) recursive(ctx context.Context, regs []*Registry, name string, root types.SetClass) ([]string, error) {
	top := strings.ToUpper(name)
	results := map[string]bool{}
	seen := map[string]bool{top: true}
	routed := map[types.ASN]bool{} // ASes whose routes are in results
	level := []string{top}
	for len(level) > 0 {
		var sub []string
		for _, n := range level {
			ms, class, found, err := snap.setMembers(ctx, regs, n, root == types.ClassAsSet)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if root == types.ClassUnknown {
				root = class
			}
			sub = append(sub, ms...)
		}
		var next []string
		for _, m := range sub {
			base, _, _ := strings.Cut(m, "^")
			switch {
			case root == types.ClassRouteSet && isPrefixOrAddr(base):
				results[m] = true
			case isASN(m) && root == types.ClassRouteSet:
				as, _ := parseAS(m)
				if routed[as] {
					continue
				}
				routed[as] = true
				ps, err := snap.originated(ctx, regs, as, types.AFIAny)
				if err != nil {
					return nil, err
				}
				for _, p := range ps {
					results[p.String()] = true
				}
			case isASN(m):
				results[m] = true
			case !seen[m]:
				seen[m] = true
				next = append(next, m)
			}
		}
		level = next
	}
	return distinctSorted(mapKeys(results), name), nil
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// distinctSorted is ms sorted as strings, each once, without drop.
func distinctSorted(ms []string, drop string) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if m != drop {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// internalError is IRRd's answer when a query fails for a reason of the
// server's own (a Source's error): the cause is logged there, never sent.
var internalError = Fail(internalErrorText)

// cmdMembers answers "!i<set>" (the set's members, without the set's name
// as sent) and "!i<set>,1" (IRRd's recursive resolution); "D" when either
// is empty.
func cmdMembers(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
	regs := snap.selected(s.sources(snap))
	var out []string
	var err error
	if name, ok := strings.CutSuffix(arg, ",1"); ok {
		out, err = snap.recursiveOrRFC(ctx, regs, name)
	} else {
		var ms []string
		ms, _, _, err = snap.setMembers(ctx, regs, arg, false)
		// IRRd removes the parameter as sent, case and all
		// (members_for_set, irrd/server/query_resolver.py): "!iAS-SELF"
		// drops a member AS-SELF, "!ias-self" keeps it.
		out = distinctSorted(ms, arg)
	}
	if err != nil {
		return internalError
	}
	if len(out) == 0 {
		return notFound
	}
	return frame(strings.Join(out, " "))
}

// recursiveOrRFC is IRRd's recursion, or the engine's in RFC mode (Task 7).
func (snap *Snapshot) recursiveOrRFC(ctx context.Context, regs []*Registry, name string) ([]string, error) {
	return snap.recursive(ctx, regs, name, types.ClassUnknown)
}

// cmdASetPrefixes answers "!a<as-set>", "!a4<as-set>" and "!a6<as-set>".
func cmdASetPrefixes(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
	afi := types.AFIAny
	switch {
	case strings.HasPrefix(arg, "4"):
		arg, afi = arg[1:], types.AFIv4
	case strings.HasPrefix(arg, "6"):
		arg, afi = arg[1:], types.AFIv6
	}
	if arg == "" {
		return Fail("Missing required set name for A query")
	}
	ps, err := snap.asSetPrefixes(ctx, snap.selected(s.sources(snap)), arg, afi)
	if err != nil {
		return internalError
	}
	return prefixes(ps)
}

// asSetPrefixes is "!a": the as-set resolved with an as-set root, then the
// distinct prefixes of afi its ASes originate in regs, sorted (prefixCmp).
// Task 7 adds RFC mode.
func (snap *Snapshot) asSetPrefixes(ctx context.Context, regs []*Registry, name string, afi types.AFI) ([]netip.Prefix, error) {
	members, err := snap.recursive(ctx, regs, name, types.ClassAsSet)
	if err != nil {
		return nil, err
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, m := range members {
		as, msg := parseAS(m)
		if msg != "" {
			continue
		}
		ps, err := snap.originated(ctx, regs, as, afi)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, prefixCmp)
	return out, nil
}
