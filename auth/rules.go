package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// Action is what an update does to an object.
type Action uint8

// The actions of an update.
const (
	Create Action = iota + 1
	Modify
	Delete
)

// String returns "create", "modify" or "delete".
func (a Action) String() string {
	switch a {
	case Create:
		return "create"
	case Modify:
		return "modify"
	case Delete:
		return "delete"
	}
	return fmt.Sprintf("Action(%d)", uint8(a))
}

// Update is one change a credential asks to make: the object as submitted —
// the new object, its new version, or the object to delete — as object.Decode
// returns it.
type Update struct {
	Action Action
	Object object.Object
}

// Rules is one registry's authorisation model. The RIPE Database and IRRd
// decide differently who may change an object, so each is its own Rules: RIPE
// and IRRd. Use those; the zero Rules is RIPE's.
//
// Neither checks the origin AS of a new route, which RFC 2725 §9.9 asks for;
// RouteCreation does.
type Rules struct{ irrd bool }

var (
	// RIPE is the RIPE Database's model, as its whois server implements it.
	// Every update needs a maintainer of the object: of the stored version for
	// a modification or deletion. Creating an object also needs its parent's
	// consent: the less specific inetnum or inet6num for address space, the
	// as-block for an aut-num, the covering route or address space for a
	// route (mnt-routes:, then mnt-lower: for strictly less specific space,
	// then mnt-by:), the address space of a reverse domain (mnt-domains:
	// first), and for a set named hierarchically ("AS1:AS-FOO") the object
	// named left of its last colon. A new reference to an irt needs the irt's
	// consent, and a new reference to an object carrying mnt-ref: needs one of
	// those maintainers.
	RIPE = Rules{}

	// IRRd is IRRd 4's model, with its default settings. Every update needs a
	// maintainer of the object as submitted, and a modification or deletion one
	// of the stored version too. Creating a route needs a maintainer (mnt-by:)
	// of the exact or smallest covering inetnum or inet6num, else of the
	// smallest less specific route; creating a set whose name begins with an
	// AS number needs one of that aut-num's, when it exists. New maintainers
	// are an administrator's to create.
	IRRd = Rules{irrd: true}
)

// String returns "RIPE" or "IRRd".
func (r Rules) String() string {
	if r.irrd {
		return "IRRd"
	}
	return "RIPE"
}

// Authorise decides whether cred may make u in db. Every check the registry
// applies must pass; the Decision's reasons name each check made and its
// outcome, in order, up to the first that failed. An object the registry
// cannot place — no maintainer, no parent where one is required, nothing
// stored to modify — is refused, and an error from db is returned, never read
// as consent.
func (r Rules) Authorise(ctx context.Context, db Database, u Update, cred Credential, v Verifier) (Decision, error) {
	c := &check{ctx: ctx, db: db, cred: cred, v: v}
	if u.Object == nil || u.Object.Raw() == nil {
		return c.refuse("the update carries no object")
	}
	switch u.Action {
	case Create, Modify, Delete:
	default:
		return c.refuse("unknown action " + u.Action.String())
	}
	if r.irrd {
		return c.irrd(u)
	}
	return c.ripe(u)
}

// check carries one Authorise call: its inputs, and the decision so far.
type check struct {
	ctx  context.Context
	db   Database
	cred Credential
	v    Verifier
	d    Decision
}

// refuse ends the check with a final reason.
func (c *check) refuse(reason string) (Decision, error) {
	c.d.OK = false
	c.d.Reasons = append(c.d.Reasons, reason)
	return c.d, nil
}

// pass ends the check authorised.
func (c *check) pass() (Decision, error) {
	c.d.OK = true
	return c.d, nil
}

// mntners checks that cred satisfies one of names, recording the outcome
// under what. self is a maintainer being created: one that names itself is
// checked against its own auth: lines, since the registry does not have it yet.
func (c *check) mntners(what string, names []string, self *object.Mntner) (bool, error) {
	if len(names) == 0 {
		c.d.Reasons = append(c.d.Reasons, what+": names no maintainer")
		return false, nil
	}
	if self != nil {
		for _, n := range names {
			if !strings.EqualFold(strings.TrimSpace(n), self.Handle) {
				continue
			}
			ok, _, err := CheckMntner(c.ctx, *self, c.cred, c.v)
			if err != nil {
				return false, err
			}
			if ok {
				c.d.Reasons = append(c.d.Reasons, fmt.Sprintf("%s (%v): %s: credential accepted by the new maintainer itself", what, names, n))
				return true, nil
			}
		}
	}
	got, err := CheckMntners(c.ctx, c.db, names, c.cred, c.v)
	if err != nil {
		return false, err
	}
	c.d.Reasons = append(c.d.Reasons, fmt.Sprintf("%s (%v): %s", what, names, got))
	return got.OK, nil
}

// ---- RIPE ----

func (c *check) ripe(u Update) (Decision, error) {
	o := u.Object
	var stored object.Object
	if u.Action != Create {
		cur, err := c.db.Current(c.ctx, o)
		if errors.Is(err, ErrNotFound) {
			return c.refuse("there is no stored " + o.Class() + " to " + u.Action.String())
		}
		if err != nil {
			return Decision{}, err
		}
		stored = cur
	}

	switch u.Action {
	case Create:
		var self *object.Mntner
		if m, ok := o.(object.Mntner); ok {
			self = &m
		}
		if ok, err := c.mntners("the object's own maintainers", values(o, "mnt-by"), self); err != nil || !ok {
			return c.d, err
		}
		if ok, err := c.ripeParent(o); err != nil || !ok {
			return c.d, err
		}
	case Modify:
		names := values(stored, "mnt-by")
		if len(names) == 0 {
			names = values(o, "mnt-by") // the stored object had none: the new version's decide
		}
		if ok, err := c.mntners("the stored object's maintainers", names, nil); err != nil || !ok {
			return c.d, err
		}
	case Delete:
		ok, err := c.mntners("the stored object's maintainers", values(stored, "mnt-by"), nil)
		if err != nil {
			return c.d, err
		}
		if !ok {
			// A reverse domain may also be deleted by its address space's
			// mnt-domains:.
			if ok, err = c.domainHolder(stored); err != nil || !ok {
				return c.d, err
			}
		}
		return c.pass()
	}
	if ok, err := c.ripeReferences(stored, o); err != nil || !ok {
		return c.d, err
	}
	return c.pass()
}

// ripeParent applies the parent's consent a creation needs, by class.
func (c *check) ripeParent(o object.Object) (bool, error) {
	switch t := o.(type) {
	case object.Inetnum:
		return c.addressParent("inetnum", t.Lo, t.Hi)
	case object.Inet6num:
		lo, hi, ok := prefixRange(t.Prefix)
		if !ok {
			return c.fail("the inet6num has no valid prefix")
		}
		return c.addressParent("inet6num", lo, hi)
	case object.AutNum:
		blocks, err := c.db.ASBlocks(c.ctx, t.AS)
		if err != nil {
			return false, err
		}
		if len(blocks) == 0 {
			return c.fail("no as-block holds " + t.AS.String())
		}
		b := blocks[0]
		return c.mntners("the parent as-block "+b.Lo.String()+" - "+b.Hi.String(), firstPresent(b, "mnt-lower", "mnt-by"), nil)
	case object.Route:
		return c.routeParent("route", "inetnum", t.Prefix)
	case object.Route6:
		return c.routeParent("route6", "inet6num", t.Prefix)
	case object.Domain:
		return c.domainParent(t)
	case object.NamedSet:
		return c.namedParent(t)
	}
	return true, nil // no parent: the object's own maintainers decide
}

// fail records a failed check.
func (c *check) fail(reason string) (bool, error) {
	c.d.Reasons = append(c.d.Reasons, reason)
	return false, nil
}

// addressParent is the parent of new address space: the most specific inetnum
// or inet6num strictly less specific than lo..hi, and its mnt-lower:, else its
// mnt-by:.
func (c *check) addressParent(class string, lo, hi netip.Addr) (bool, error) {
	if !lo.IsValid() || !hi.IsValid() {
		return c.fail("the " + class + " has no valid range")
	}
	cov, err := c.db.Covering(c.ctx, class, lo, hi)
	if err != nil {
		return false, err
	}
	for _, p := range cov {
		if plo, phi, _ := addressRange(p); plo == lo && phi == hi {
			continue // the object itself, or one of the same range
		}
		return c.mntners("the parent "+describeObject(p), firstPresent(p, "mnt-lower", "mnt-by"), nil)
	}
	return c.fail("no less specific " + class + " holds " + lo.String() + " - " + hi.String())
}

// routeParent is the parent of a new route: the exact or first less specific
// route, else the exact or first less specific inetnum or inet6num. Its
// mnt-routes: decides, else its mnt-lower: when it is strictly less specific,
// else its mnt-by: — RouteAuthority.
func (c *check) routeParent(routeClass, spaceClass string, p netip.Prefix) (bool, error) {
	lo, hi, ok := prefixRange(p)
	if !ok {
		return c.fail("the " + routeClass + " has no valid prefix")
	}
	parent, err := c.firstCovering(lo, hi, routeClass, spaceClass)
	if err != nil {
		return false, err
	}
	if parent == nil {
		return c.fail("no " + routeClass + " or " + spaceClass + " covers " + p.String())
	}
	names := RouteAuthority(parent, p)
	if len(names) == 0 {
		return c.fail("the parent " + describeObject(parent) + " delegates no maintainer for " + p.String())
	}
	return c.mntners("the parent "+describeObject(parent), names, nil)
}

// firstCovering returns the first object covering lo..hi among classes, tried
// in order.
func (c *check) firstCovering(lo, hi netip.Addr, classes ...string) (object.Object, error) {
	for _, class := range classes {
		cov, err := c.db.Covering(c.ctx, class, lo, hi)
		if err != nil {
			return nil, err
		}
		if len(cov) > 0 {
			return cov[0], nil
		}
	}
	return nil, nil
}

// domainParent is the parent of a new reverse domain: the exact or first less
// specific inetnum or inet6num of its range. Its mnt-domains: decides, else its
// mnt-lower: when it is strictly less specific, else its mnt-by:. A domain
// outside in-addr.arpa and ip6.arpa (e164.arpa) has no parent.
func (c *check) domainParent(d object.Domain) (bool, error) {
	lo, hi, ok := d.ReverseRange()
	if !ok {
		if isReverseName(d.Name) {
			return c.fail("the domain " + d.Name + " is not a reverse zone this model can place")
		}
		return true, nil
	}
	class := "inetnum"
	if lo.Is6() {
		class = "inet6num"
	}
	parent, err := c.firstCovering(lo, hi, class)
	if err != nil {
		return false, err
	}
	if parent == nil {
		return c.fail("no " + class + " holds the domain " + d.Name)
	}
	attrs := []string{"mnt-domains", "mnt-by"}
	if plo, phi, _ := addressRange(parent); plo != lo || phi != hi {
		attrs = []string{"mnt-domains", "mnt-lower", "mnt-by"}
	}
	return c.mntners("the parent "+describeObject(parent), firstPresent(parent, attrs...), nil)
}

// domainHolder lets a reverse domain's exact address space delete it through
// its mnt-domains:, as the RIPE Database does when the domain's own
// maintainers fail.
func (c *check) domainHolder(stored object.Object) (bool, error) {
	d, ok := stored.(object.Domain)
	if !ok {
		return false, nil
	}
	lo, hi, ok := d.ReverseRange()
	if !ok {
		return false, nil
	}
	class := "inetnum"
	if lo.Is6() {
		class = "inet6num"
	}
	cov, err := c.db.Covering(c.ctx, class, lo, hi)
	if err != nil {
		return false, err
	}
	for _, p := range cov {
		if plo, phi, _ := addressRange(p); plo == lo && phi == hi {
			if names := values(p, "mnt-domains"); len(names) > 0 {
				return c.mntners("the address space "+describeObject(p)+"'s mnt-domains", names, nil)
			}
		}
	}
	return false, nil
}

// namedParent is the parent of a set named hierarchically: the object named
// left of the last colon — an aut-num when that is an AS number, an as-set
// when it names one, otherwise a set of the same class — and its mnt-lower:,
// else its mnt-by:. A set named without a colon has none.
func (c *check) namedParent(s object.NamedSet) (bool, error) {
	key := s.SetName().String()
	i := strings.LastIndexByte(key, ':')
	if i < 0 {
		return true, nil
	}
	parentKey := key[:i]
	class := s.Class()
	if _, err := types.ParseASN(parentKey); err == nil {
		class = "aut-num"
	} else if n, err := types.ParseSetName(parentKey); err == nil && n.Class() == types.ClassAsSet {
		class = "as-set"
	}
	parent, err := c.db.Object(c.ctx, class, parentKey)
	if errors.Is(err, ErrNotFound) {
		return c.fail("the parent " + class + " " + parentKey + " does not exist")
	}
	if err != nil {
		return false, err
	}
	return c.mntners("the parent "+class+" "+parentKey, firstPresent(parent, "mnt-lower", "mnt-by"), nil)
}

// referenceAttrs are the attributes whose new references the RIPE Database
// guards with the referenced object's mnt-ref:, and the classes each may name.
var referenceAttrs = []struct {
	attr    string
	classes []string
}{
	{"admin-c", []string{"person", "role"}},
	{"tech-c", []string{"person", "role"}},
	{"zone-c", []string{"person", "role"}},
	{"abuse-c", []string{"role", "person"}},
	{"author", []string{"person", "role"}},
	{"ping-hdl", []string{"person", "role"}},
	{"mnt-by", []string{"mntner"}},
	{"mnt-lower", []string{"mntner"}},
	{"mnt-routes", []string{"mntner"}},
	{"mnt-domains", []string{"mntner"}},
	{"mnt-ref", []string{"mntner"}},
	{"org", []string{"organisation"}},
}

// ripeReferences applies the consent new references need: an irt's for a new
// mnt-irt: (MntIrtChange), and one of the mnt-ref: maintainers of any other
// object a new reference names, when it has any — always, for an
// organisation.
func (c *check) ripeReferences(stored, o object.Object) (bool, error) {
	if added := AddedMntIrt(stored, o); len(added) > 0 {
		d, err := CheckIrts(c.ctx, irtLookup{c.db}, added, c.cred, c.v)
		if err != nil {
			return false, err
		}
		c.d.Reasons = append(c.d.Reasons, fmt.Sprintf("the added irts (%v): %s", added, d))
		if !d.OK {
			return false, nil
		}
	}
	_, selfKey, _ := primaryKey(o)
	for _, ra := range referenceAttrs {
		had := map[string]bool{}
		for _, v := range values(stored, ra.attr) {
			had[strings.ToUpper(v)] = true
		}
		for _, name := range values(o, ra.attr) {
			if had[strings.ToUpper(name)] {
				continue
			}
			had[strings.ToUpper(name)] = true
			ref, class, err := c.referenced(name, ra.classes)
			if err != nil {
				return false, err
			}
			if ref == nil || (class == o.Class() && normalKey(class, name) == selfKey) {
				continue // dangling, which is not this check's to judge, or the object itself
			}
			names := values(ref, "mnt-ref")
			if len(names) == 0 && class != "organisation" {
				continue
			}
			what := fmt.Sprintf("the %s %s referenced in %s", class, name, ra.attr)
			if ok, err := c.mntners(what+", its mnt-ref", names, nil); err != nil || !ok {
				return false, err
			}
		}
	}
	return true, nil
}

// referenced looks name up in the first of classes that has it.
func (c *check) referenced(name string, classes []string) (object.Object, string, error) {
	for _, class := range classes {
		o, err := c.db.Object(c.ctx, class, name)
		if err == nil {
			return o, class, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, "", err
		}
	}
	return nil, "", nil
}

// irtLookup is an IrtRegistry over a Database.
type irtLookup struct{ db Database }

func (l irtLookup) Irt(ctx context.Context, name string) (object.Irt, error) {
	o, err := l.db.Object(ctx, "irt", name)
	if errors.Is(err, ErrNotFound) {
		return object.Irt{}, fmt.Errorf("%w: %s", ErrNoIrt, name)
	}
	if err != nil {
		return object.Irt{}, err
	}
	irt, ok := o.(object.Irt)
	if !ok {
		return object.Irt{}, fmt.Errorf("%w: %s", ErrNoIrt, name)
	}
	return irt, nil
}

// ---- IRRd ----

func (c *check) irrd(u Update) (Decision, error) {
	o := u.Object
	if u.Action == Create {
		if _, ok := o.(object.Mntner); ok {
			return c.refuse("a new mntner is an administrator's to create")
		}
	}
	if ok, err := c.mntners("the submitted object's maintainers", values(o, "mnt-by"), nil); err != nil || !ok {
		return c.d, err
	}
	switch u.Action {
	case Modify, Delete:
		stored, err := c.db.Current(c.ctx, o)
		if errors.Is(err, ErrNotFound) {
			return c.refuse("there is no stored " + o.Class() + " to " + u.Action.String())
		}
		if err != nil {
			return Decision{}, err
		}
		if ok, err := c.mntners("the stored object's maintainers", values(stored, "mnt-by"), nil); err != nil || !ok {
			return c.d, err
		}
		if m, isMntner := o.(object.Mntner); isMntner && u.Action == Modify {
			ok, _, err := CheckMntner(c.ctx, m, c.cred, c.v)
			if err != nil {
				return Decision{}, err
			}
			if !ok {
				return c.refuse("the new version's own auth: lines: credential rejected")
			}
			c.d.Reasons = append(c.d.Reasons, "the new version's own auth: lines: credential accepted")
		}
	case Create:
		if ok, err := c.irrdRelated(o); err != nil || !ok {
			return c.d, err
		}
	}
	return c.pass()
}

// irrdRelated applies IRRd's related-object check on creation: a route needs
// a maintainer of the exact or smallest covering inetnum or inet6num, else of
// the smallest less specific route; a set whose name begins with an AS number
// needs one of that aut-num's, when it exists. Only mnt-by: counts.
func (c *check) irrdRelated(o object.Object) (bool, error) {
	var routeClass, spaceClass string
	var p netip.Prefix
	switch t := o.(type) {
	case object.Route:
		routeClass, spaceClass, p = "route", "inetnum", t.Prefix
	case object.Route6:
		routeClass, spaceClass, p = "route6", "inet6num", t.Prefix
	case object.NamedSet:
		first, _, _ := strings.Cut(t.SetName().String(), ":")
		as, err := types.ParseASN(first)
		if err != nil {
			return true, nil
		}
		autnum, err := c.db.Object(c.ctx, "aut-num", as.String())
		if errors.Is(err, ErrNotFound) {
			return true, nil // opportunistic: only an aut-num that exists is asked
		}
		if err != nil {
			return false, err
		}
		return c.mntners("the related aut-num "+as.String(), values(autnum, "mnt-by"), nil)
	default:
		return true, nil
	}
	lo, hi, ok := prefixRange(p)
	if !ok {
		return c.fail("the " + routeClass + " has no valid prefix")
	}
	related, err := c.firstCovering(lo, hi, spaceClass)
	if err != nil {
		return false, err
	}
	if related == nil {
		cov, err := c.db.Covering(c.ctx, routeClass, lo, hi)
		if err != nil {
			return false, err
		}
		for _, r := range cov {
			if rlo, rhi, _ := addressRange(r); rlo != lo || rhi != hi { // strictly less specific
				related = r
				break
			}
		}
	}
	if related == nil {
		return true, nil
	}
	return c.mntners("the related "+describeObject(related), values(related, "mnt-by"), nil)
}

// ---- helpers ----

// values returns the list items of every attr attribute of o, as written.
func values(o object.Object, attr string) []string {
	if o == nil || o.Raw() == nil {
		return nil
	}
	var out []string
	for _, a := range o.Raw().GetAll(attr) {
		for _, it := range a.List() {
			if it.Value != "" {
				out = append(out, it.Value)
			}
		}
	}
	return out
}

// firstPresent returns the values of the first of attrs that o has.
func firstPresent(o object.Object, attrs ...string) []string {
	for _, a := range attrs {
		if v := values(o, a); len(v) > 0 {
			return v
		}
	}
	return nil
}

// describeObject names an object for a reason: its class and key.
func describeObject(o object.Object) string {
	class, key, ok := primaryKey(o)
	if !ok {
		return o.Class()
	}
	return class + " " + key
}

// isReverseName reports whether a domain name claims to be a reverse zone.
func isReverseName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	return strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa")
}
