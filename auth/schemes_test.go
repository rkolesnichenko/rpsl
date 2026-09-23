package auth

import (
	"context"
	"regexp"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// schemeVerifier checks BCRYPT-PW by exact match (standing in for bcrypt) and
// MAIL-FROM against the update's sender, the way RFC 2622 §3.1 describes it.
type schemeVerifier struct{}

func (schemeVerifier) Verify(_ context.Context, m object.Auth, cred Credential) (bool, error) {
	switch m.Method {
	case object.AuthBcrypt:
		return cred.Password == "secret" && m.Value == "$2b$12$hash", nil
	case object.AuthMailFrom:
		re, err := regexp.Compile("^(?:" + m.Value + ")$")
		return err == nil && re.MatchString(cred.From), nil
	}
	return false, ErrUnsupportedMethod
}

// A Verifier is handed BCRYPT-PW and MAIL-FROM lines as their own methods, and
// a MAIL-FROM check has the sender to look at; IRRD-INTERNAL-AUTH has nothing
// in the object to check.
func TestNewAuthSchemes(t *testing.T) {
	ctx := context.Background()
	v := schemeVerifier{}
	bc := decode(t, mntner("MNT-B", "BCRYPT-PW $2b$12$hash")).(object.Mntner)
	if ok, unsup, err := CheckMntner(ctx, bc, Credential{Password: "secret"}, v); !ok || unsup || err != nil {
		t.Errorf("BCRYPT-PW: %v, %v, %v; want accepted", ok, unsup, err)
	}
	mf := decode(t, mntner("MNT-M", `MAIL-FROM .*@example\.net`)).(object.Mntner)
	if ok, _, err := CheckMntner(ctx, mf, Credential{From: "noc@example.net"}, v); !ok || err != nil {
		t.Errorf("MAIL-FROM with a matching sender: %v, %v; want accepted", ok, err)
	}
	if ok, _, _ := CheckMntner(ctx, mf, Credential{From: "noc@example.org"}, v); ok {
		t.Error("MAIL-FROM accepted a sender that does not match")
	}
	in := decode(t, mntner("MNT-I", "IRRD-INTERNAL-AUTH")).(object.Mntner)
	if ok, unsup, err := CheckMntner(ctx, in, Credential{Password: "secret"}, v); ok || !unsup || err != nil {
		t.Errorf("IRRD-INTERNAL-AUTH: %v, %v, %v; want unsupported", ok, unsup, err)
	}
}
