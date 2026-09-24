package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
)

// The RIPE Database guards the mnt-irt: attribute of inetnum and inet6num
// objects: pointing address space at an incident response team needs that
// team's consent, given through the irt object's own auth: lines. RFC 2725 has
// no irt class, so this is RIPE's rule, modelled on its implementation
// (MntIrtAuthentication in RIPE-NCC/whois).

// IrtRegistry looks irt objects up by name. It is kept apart from Registry so
// that a registry written before irt support still satisfies Registry; one
// type can implement both.
type IrtRegistry interface {
	// Irt returns the named irt object, or an error wrapping ErrNoIrt when the
	// registry has none by that name.
	Irt(ctx context.Context, name string) (object.Irt, error)
}

// ErrNoIrt reports an irt object the registry does not have.
var ErrNoIrt = errors.New("auth: no such irt")

// CheckIrt reports whether cred satisfies any auth: line of irt. It follows
// CheckMntner: a scheme the verifier does not handle is skipped and reported
// through unsupported, and a nil Verifier checks nothing.
func CheckIrt(ctx context.Context, irt object.Irt, cred Credential, v Verifier) (ok, unsupported bool, err error) {
	return checkAuth(ctx, irt.Auth, cred, v)
}

// CheckIrts reports whether cred satisfies any of the named irt objects. Irts
// the registry does not have are skipped with a reason; when none can be
// checked, the answer is a refusal.
func CheckIrts(ctx context.Context, reg IrtRegistry, names []string, cred Credential, v Verifier) (Decision, error) {
	var d Decision
	for _, name := range names {
		irt, err := reg.Irt(ctx, name)
		if err != nil {
			if !errors.Is(err, ErrNoIrt) {
				return Decision{}, err
			}
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: no such irt", name))
			continue
		}
		ok, unsupported, err := CheckIrt(ctx, irt, cred, v)
		if err != nil {
			return Decision{}, err
		}
		switch {
		case ok:
			d.OK = true
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: credential accepted", name))
			return d, nil
		case len(irt.Auth) == 0:
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: has no auth: lines, so accepts no credential", name))
		case unsupported:
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: no verifier for its auth scheme", name))
		default:
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: credential rejected", name))
		}
	}
	return d, nil
}

// AddedMntIrt returns the mnt-irt: names after carries and before does not,
// compared case-insensitively, each once, in after's order and as written
// there. A nil before is a creation, which adds every reference. Only inetnum
// and inet6num objects carry mnt-irt:; any other class adds none.
func AddedMntIrt(before, after object.Object) []string {
	had := map[string]bool{}
	for _, name := range mntIrt(before) {
		had[strings.ToUpper(strings.TrimSpace(name))] = true
	}
	var added []string
	for _, name := range mntIrt(after) {
		key := strings.ToUpper(strings.TrimSpace(name))
		if key == "" || had[key] {
			continue
		}
		had[key] = true
		added = append(added, name)
	}
	return added
}

// MntIrtChange decides whether cred may make the mnt-irt: references an update
// adds, as the RIPE Database does: only added references need an irt's
// consent, and the credential of any one of the added irts is enough. That is
// RIPE's rule, and it is lenient — a credential for one irt admits a second
// added beside it. An update that adds no reference passes.
//
// This is the irt part of an update's authorisation only. The object's own
// mnt-by: and its parent's mnt-lower: are checked separately, with
// CheckMntners.
func MntIrtChange(ctx context.Context, reg IrtRegistry, before, after object.Object, cred Credential, v Verifier) (Decision, error) {
	added := AddedMntIrt(before, after)
	if len(added) == 0 {
		return Decision{OK: true, Reasons: []string{"no mnt-irt: reference is added"}}, nil
	}
	return CheckIrts(ctx, reg, added, cred, v)
}

// mntIrt reads the mnt-irt: references of an object. The classes that carry
// them are read from their typed fields, as values or pointers; any other
// object is read from its text, so a shape this switch does not know cannot
// hide a reference and pass an update unchecked.
func mntIrt(o object.Object) []string {
	switch t := o.(type) {
	case nil:
		return nil
	case object.Inetnum:
		return t.MntIrt
	case *object.Inetnum:
		if t != nil {
			return t.MntIrt
		}
		return nil
	case object.Inet6num:
		return t.MntIrt
	case *object.Inet6num:
		if t != nil {
			return t.MntIrt
		}
		return nil
	}
	if v := reflect.ValueOf(o); v.Kind() == reflect.Pointer && v.IsNil() {
		return nil // a typed nil: no object, so no references
	}
	raw := o.Raw()
	if raw == nil {
		return nil
	}
	var out []string
	for _, a := range raw.GetAll("mnt-irt") {
		for _, it := range a.List() {
			if it.Value != "" {
				out = append(out, it.Value)
			}
		}
	}
	return out
}
