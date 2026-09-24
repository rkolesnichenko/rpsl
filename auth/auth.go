// Package auth models the RPSL authentication and authorisation of RFC 2725:
// which maintainers guard an object, and whether a given credential may create
// or change it.
//
// Nothing here performs cryptography. An auth: line names a scheme — MD5-PW, a
// PGP key, an X.509 certificate — and checking a credential against one needs a
// cryptography library; depending on one would cost every consumer of this
// library a dependency it mostly does not want. So verification is injected,
// exactly as resolve.Source injects I/O: supply a Verifier and the model uses
// it, supply none and the model answers the questions that do not need it.
//
// In scope: parsing and matching auth: schemes, the hierarchical authorisation
// of RFC 2725 §4 — which is what stops one maintainer registering a route in
// another's address space — the referral-by chains of RFC 2725 §9, and the
// RIPE Database's rule that adding an mnt-irt: reference needs the consent of
// the irt it names (MntIrtChange).
//
// Out of scope: the update-transaction protocol of RFC 2725 §7, and any
// cryptographic verification.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
)

// ErrUnsupportedMethod is returned by a Verifier that does not implement the
// scheme an auth: line names. It is not a failure to authenticate: a caller
// that holds no PGP verifier should not conclude that a PGP-guarded object is
// unguarded.
var ErrUnsupportedMethod = errors.New("auth: no verifier for this scheme")

// Credential is what a would-be updater presents. Which fields matter depends
// on the scheme: a password for MD5-PW, CRYPT-PW and BCRYPT-PW, a signature
// over Message for PGPKEY and X509, the sender's address for MAIL-FROM.
//
// MAIL-FROM (RFC 2622 §3.1) accepts an update whose sender matches the line's
// regular expression; a sender address is easily forged, and RFC 2725 calls it
// "a very weak authentication check". IRRD-INTERNAL-AUTH marks a maintainer
// whose users and API keys IRRd keeps in its own database, so a Verifier for
// it needs that database, and one without it reports ErrUnsupportedMethod.
type Credential struct {
	Password  string
	Signature []byte
	Message   []byte // the object text the signature covers
	From      string // the update's sender address, for MAIL-FROM
}

// Verifier decides whether a credential satisfies one auth: line. Implementing
// it is where cryptography goes; see the package comment.
//
// A Verifier reports ErrUnsupportedMethod for a scheme it does not handle, so
// the caller can tell "wrong password" from "cannot check".
type Verifier interface {
	Verify(ctx context.Context, m object.Auth, cred Credential) (bool, error)
}

// Registry looks maintainers up by name. It is the authorisation model's one
// piece of I/O, injected for the same reason resolve.Source is.
type Registry interface {
	// Mntner returns the named maintainer, or an error wrapping ErrNoMntner
	// when the registry has none by that name.
	Mntner(ctx context.Context, name string) (object.Mntner, error)
}

// ErrNoMntner reports a maintainer the registry does not have.
var ErrNoMntner = errors.New("auth: no such mntner")

// Decision is the outcome of an authorisation check: whether it passed, and the
// reasons behind it, in the order they were considered. The reasons are for
// showing a person why an update was refused, not for matching on.
type Decision struct {
	OK      bool
	Reasons []string
}

// String renders the decision and its reasons.
func (d Decision) String() string {
	head := "refused"
	if d.OK {
		head = "authorised"
	}
	if len(d.Reasons) == 0 {
		return head
	}
	return head + ": " + strings.Join(d.Reasons, "; ")
}

// CheckMntner reports whether cred satisfies any auth: line of m. A scheme the
// verifier does not handle is skipped, and reported through unsupported, so a
// caller can distinguish "no line matched" from "no line could be checked".
//
// A nil Verifier checks nothing and reports every line as unsupported.
func CheckMntner(ctx context.Context, m object.Mntner, cred Credential, v Verifier) (ok, unsupported bool, err error) {
	return checkAuth(ctx, m.Auth, cred, v)
}

// checkAuth reports whether cred satisfies any of the auth: lines, for
// CheckMntner and CheckIrt.
func checkAuth(ctx context.Context, lines []object.Auth, cred Credential, v Verifier) (ok, unsupported bool, err error) {
	for _, a := range lines {
		if v == nil {
			unsupported = true
			continue
		}
		got, err := v.Verify(ctx, a, cred)
		switch {
		case errors.Is(err, ErrUnsupportedMethod):
			unsupported = true
		case err != nil:
			return false, unsupported, err
		case got:
			return true, unsupported, nil
		}
	}
	return false, unsupported, nil
}

// CheckMntners reports whether cred satisfies any of the named maintainers.
// Maintainers the registry does not have are skipped: a dangling mnt-by is a
// data problem, not an authorisation.
func CheckMntners(ctx context.Context, reg Registry, names []string, cred Credential, v Verifier) (Decision, error) {
	if len(names) == 0 {
		return Decision{Reasons: []string{"no maintainer guards this object"}}, nil
	}
	var d Decision
	for _, name := range names {
		m, err := reg.Mntner(ctx, name)
		if err != nil {
			if !errors.Is(err, ErrNoMntner) {
				return Decision{}, err
			}
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: no such maintainer", name))
			continue
		}
		ok, unsupported, err := CheckMntner(ctx, m, cred, v)
		if err != nil {
			return Decision{}, err
		}
		switch {
		case ok:
			d.OK = true
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: credential accepted", name))
			return d, nil
		case unsupported:
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: no verifier for its auth scheme", name))
		default:
			d.Reasons = append(d.Reasons, fmt.Sprintf("%s: credential rejected", name))
		}
	}
	return d, nil
}

// ReferralChain walks referral-by from name towards the maintainer that
// authorised it, stopping at one that refers to itself — the root of the chain
// (RFC 2725 §9). maxDepth bounds the maintainers walked, root included; zero
// means 32.
//
// It returns the chain, starting with name's own maintainer. A cycle that does
// not close on itself returns ErrReferralCycle along with the chain walked so
// far, so a caller can show where it looped.
func ReferralChain(ctx context.Context, reg Registry, name string, maxDepth int) ([]object.Mntner, error) {
	if maxDepth <= 0 {
		maxDepth = 32
	}
	var chain []object.Mntner
	seen := map[string]bool{}
	for at := name; ; {
		key := strings.ToUpper(strings.TrimSpace(at))
		if seen[key] {
			return chain, fmt.Errorf("%w at %s", ErrReferralCycle, at)
		}
		seen[key] = true
		m, err := reg.Mntner(ctx, at)
		if err != nil {
			return chain, err
		}
		chain = append(chain, m)
		next := ""
		for _, r := range m.ReferralBy {
			if r = strings.TrimSpace(r); r != "" {
				next = r
				break
			}
		}
		if next == "" {
			return chain, nil // no referral: the chain ends here
		}
		if strings.EqualFold(next, m.Handle) {
			return chain, nil // self-referential: the root of the chain
		}
		if len(chain) >= maxDepth { // another maintainer follows, one past the bound
			return chain, fmt.Errorf("%w after %d maintainers", ErrReferralTooDeep, len(chain))
		}
		at = next
	}
}

// ErrReferralCycle reports a referral-by chain that loops without closing on a
// self-referential maintainer.
var ErrReferralCycle = errors.New("auth: referral-by cycle")

// ErrReferralTooDeep reports a referral-by chain longer than the caller allowed.
var ErrReferralTooDeep = errors.New("auth: referral-by chain too long")
