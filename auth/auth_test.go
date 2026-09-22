package auth

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
)

// decode parses and decodes one object, failing the test on any diagnostic.
func decode(t *testing.T, src string) object.Object {
	t.Helper()
	o, ds := rpsl.ParseObject(src)
	if len(ds) != 0 {
		t.Fatalf("parse %q: %v", src, ds)
	}
	obj, dds := rpsl.Decode(o)
	if len(dds) != 0 {
		t.Fatalf("decode %q: %v", src, dds)
	}
	return obj
}

// memRegistry is a Registry over decoded mntner objects.
type memRegistry map[string]object.Mntner

func newRegistry(t *testing.T, srcs ...string) memRegistry {
	t.Helper()
	r := memRegistry{}
	for _, src := range srcs {
		m, ok := decode(t, src).(object.Mntner)
		if !ok {
			t.Fatalf("not a mntner: %q", src)
		}
		r[strings.ToUpper(m.Handle)] = m
	}
	return r
}

func (r memRegistry) Mntner(_ context.Context, name string) (object.Mntner, error) {
	m, ok := r[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return object.Mntner{}, ErrNoMntner
	}
	return m, nil
}

// passwordVerifier accepts a password for MD5-PW and CRYPT-PW, and reports
// every other scheme as unsupported — the shape a real verifier has, minus the
// cryptography.
type passwordVerifier struct{ pass map[string]string } // credential -> mntner value

func (v passwordVerifier) Verify(_ context.Context, m object.Auth, cred Credential) (bool, error) {
	switch m.Method {
	case object.AuthMD5, object.AuthCrypt:
		want, ok := v.pass[cred.Password]
		return ok && want == m.Value, nil
	case object.AuthNone:
		return true, nil
	}
	return false, ErrUnsupportedMethod
}

func mntner(handle, auth string, referralBy ...string) string {
	src := "mntner: " + handle + "\nadmin-c: EX1-RIPE\nupd-to: e@e.net\nauth: " + auth + "\nmnt-by: " + handle + "\n"
	for _, r := range referralBy {
		src += "referral-by: " + r + "\n"
	}
	return src + "source: RIPE\n"
}

func goodCred() Credential  { return Credential{Password: "secret"} }
func wrongCred() Credential { return Credential{Password: "nope"} }

func verifier() passwordVerifier {
	return passwordVerifier{pass: map[string]string{"secret": "$1$abc$xyz"}}
}

func TestCheckMntner(t *testing.T) {
	ctx := context.Background()
	v := verifier()
	ok, unsup, err := CheckMntner(ctx, decode(t, mntner("MNT-A", "MD5-PW $1$abc$xyz")).(object.Mntner), goodCred(), v)
	if err != nil || !ok || unsup {
		t.Errorf("CheckMntner = %v, %v, %v; want true, false, nil", ok, unsup, err)
	}
	ok, _, err = CheckMntner(ctx, decode(t, mntner("MNT-A", "MD5-PW $1$abc$xyz")).(object.Mntner), wrongCred(), v)
	if err != nil || ok {
		t.Errorf("a wrong password was accepted")
	}
	// A scheme the verifier cannot check is reported, not treated as a refusal
	// — a PGP-guarded object is not an unguarded one.
	ok, unsup, err = CheckMntner(ctx, decode(t, mntner("MNT-P", "PGPKEY-1234ABCD")).(object.Mntner), goodCred(), v)
	if err != nil || ok || !unsup {
		t.Errorf("CheckMntner = %v, %v, %v; want false, true, nil", ok, unsup, err)
	}
	// No verifier at all checks nothing.
	ok, unsup, err = CheckMntner(ctx, decode(t, mntner("MNT-A", "MD5-PW $1$abc$xyz")).(object.Mntner), goodCred(), nil)
	if err != nil || ok || !unsup {
		t.Errorf("a nil Verifier accepted something: %v, %v, %v", ok, unsup, err)
	}
	// An error from the verifier stops the check.
	boom := errors.New("hsm offline")
	_, _, err = CheckMntner(ctx, decode(t, mntner("MNT-A", "MD5-PW $1$abc$xyz")).(object.Mntner), goodCred(), erroring{boom})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

type erroring struct{ err error }

func (e erroring) Verify(context.Context, object.Auth, Credential) (bool, error) { return false, e.err }

func TestCheckMntners(t *testing.T) {
	reg := newRegistry(t,
		mntner("MNT-A", "MD5-PW $1$abc$xyz"),
		mntner("MNT-P", "PGPKEY-1234ABCD"),
	)
	ctx, v := context.Background(), verifier()

	d, err := CheckMntners(ctx, reg, []string{"MNT-P", "MNT-A"}, goodCred(), v)
	if err != nil || !d.OK {
		t.Errorf("CheckMntners = %v, %v; want authorised", d, err)
	}
	if !strings.Contains(d.String(), "authorised") {
		t.Errorf("String() = %q", d.String())
	}
	d, _ = CheckMntners(ctx, reg, []string{"MNT-A"}, wrongCred(), v)
	if d.OK || !strings.Contains(d.String(), "rejected") {
		t.Errorf("CheckMntners = %v, want a rejection", d)
	}
	d, _ = CheckMntners(ctx, reg, []string{"MNT-P"}, goodCred(), v)
	if d.OK || !strings.Contains(d.String(), "no verifier") {
		t.Errorf("CheckMntners = %v, want an unsupported-scheme reason", d)
	}
	// A dangling mnt-by is a data problem, not an authorisation.
	d, _ = CheckMntners(ctx, reg, []string{"MNT-GONE"}, goodCred(), v)
	if d.OK || !strings.Contains(d.String(), "no such maintainer") {
		t.Errorf("CheckMntners = %v", d)
	}
	// No maintainer at all guards nothing, and is refused.
	d, _ = CheckMntners(ctx, reg, nil, goodCred(), v)
	if d.OK {
		t.Error("an object guarded by no maintainer was authorised")
	}
}

func TestReferralChain(t *testing.T) {
	ctx := context.Background()
	reg := newRegistry(t,
		mntner("MNT-LEAF", "NONE", "MNT-MID"),
		mntner("MNT-MID", "NONE", "MNT-ROOT"),
		mntner("MNT-ROOT", "NONE", "MNT-ROOT"), // self-referential: the root
		mntner("MNT-LONE", "NONE"),             // no referral-by at all
		mntner("MNT-X", "NONE", "MNT-Y"),
		mntner("MNT-Y", "NONE", "MNT-X"), // a cycle that never closes on itself
	)
	chain, err := ReferralChain(ctx, reg, "MNT-LEAF", 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range chain {
		got = append(got, m.Handle)
	}
	if want := "MNT-LEAF MNT-MID MNT-ROOT"; strings.Join(got, " ") != want {
		t.Errorf("chain = %v, want %v", got, want)
	}
	if chain, err := ReferralChain(ctx, reg, "MNT-LONE", 0); err != nil || len(chain) != 1 {
		t.Errorf("a maintainer with no referral-by gave %v, %v", chain, err)
	}
	chain, err = ReferralChain(ctx, reg, "MNT-X", 0)
	if !errors.Is(err, ErrReferralCycle) {
		t.Errorf("err = %v, want ErrReferralCycle", err)
	}
	if len(chain) != 2 {
		t.Errorf("the chain walked so far = %v, want 2 entries", chain)
	}
	if _, err := ReferralChain(ctx, reg, "MNT-LEAF", 2); !errors.Is(err, ErrReferralTooDeep) {
		t.Errorf("err = %v, want ErrReferralTooDeep", err)
	}
	if _, err := ReferralChain(ctx, reg, "MNT-GONE", 0); !errors.Is(err, ErrNoMntner) {
		t.Errorf("err = %v, want ErrNoMntner", err)
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
