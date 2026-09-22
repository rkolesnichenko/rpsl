package object

import (
	"fmt"
	"strings"
)

// AuthMethod is the scheme an auth: line names (RFC 2622 §3.2, RFC 2725 §5,
// and RIPE's SSO extension).
type AuthMethod uint8

// The authentication schemes seen on mntner and irt objects.
const (
	AuthUnknown AuthMethod = iota // a scheme this library does not know
	AuthNone                      // NONE: no authentication
	AuthMD5                       // MD5-PW <crypt>
	AuthCrypt                     // CRYPT-PW <crypt>
	AuthPGPKey                    // PGPKEY-<id>: the key-cert object holding the key
	AuthX509                      // X509-<n>: the key-cert object holding the certificate
	AuthSSO                       // SSO <account>: RIPE single sign-on
)

// String returns the scheme's RPSL keyword, or "unknown".
func (m AuthMethod) String() string {
	switch m {
	case AuthNone:
		return "NONE"
	case AuthMD5:
		return "MD5-PW"
	case AuthCrypt:
		return "CRYPT-PW"
	case AuthPGPKey:
		return "PGPKEY"
	case AuthX509:
		return "X509"
	case AuthSSO:
		return "SSO"
	}
	return "unknown"
}

// Auth is one auth: line of a mntner or irt object: the scheme and its
// credential. Raw keeps the line as written, so an unrecognised scheme still
// round-trips and no credential is ever reformatted.
//
// Nothing here verifies a credential. Verification needs cryptography, which
// this module deliberately does not depend on; a consumer that wants it
// supplies its own verifier.
type Auth struct {
	Method AuthMethod
	Value  string // the credential, or the key-cert handle for PGPKEY and X509
	Raw    string
}

// String returns the auth line as written.
func (a Auth) String() string { return a.Raw }

// ParseAuth parses one auth: value. An unrecognised scheme returns an error
// along with an Auth whose Method is AuthUnknown and whose Raw is the input, so
// a caller can keep the value and warn rather than drop it.
func ParseAuth(s string) (Auth, error) {
	raw := strings.TrimSpace(s)
	a := Auth{Raw: raw}
	if raw == "" {
		return a, fmt.Errorf("rpsl/object: empty auth line")
	}
	word, rest, _ := strings.Cut(raw, " ")
	cred := strings.TrimSpace(rest)
	switch up := strings.ToUpper(word); {
	case up == "NONE":
		a.Method = AuthNone
	case up == "MD5-PW":
		a.Method, a.Value = AuthMD5, cred
	case up == "CRYPT-PW":
		a.Method, a.Value = AuthCrypt, cred
	case up == "SSO":
		a.Method, a.Value = AuthSSO, cred
	case strings.HasPrefix(up, "PGPKEY-"):
		// The scheme is the key-cert handle itself, so there is no credential.
		a.Method, a.Value = AuthPGPKey, word
	case strings.HasPrefix(up, "X509-"):
		a.Method, a.Value = AuthX509, word
	default:
		return a, fmt.Errorf("rpsl/object: unknown auth scheme %q", word)
	}
	if a.Value == "" && a.Method != AuthNone {
		return a, fmt.Errorf("rpsl/object: auth scheme %s has no credential", a.Method)
	}
	return a, nil
}
