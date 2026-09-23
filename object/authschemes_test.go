package object

import "testing"

// IRRd 4's BCRYPT-PW, RFC 2622's MAIL-FROM and IRRd's IRRD-INTERNAL-AUTH are
// known schemes, in any letter case; the two that carry a credential need one.
func TestAuthSchemes(t *testing.T) {
	for _, c := range []struct {
		in     string
		method AuthMethod
		value  string
		name   string
	}{
		{"BCRYPT-PW $2b$12$abcdefghijklmnopqrstuv", AuthBcrypt, "$2b$12$abcdefghijklmnopqrstuv", "BCRYPT-PW"},
		{"bcrypt-pw DummyValue", AuthBcrypt, "DummyValue", "BCRYPT-PW"},
		{"MAIL-FROM .*@ripe\\.net", AuthMailFrom, ".*@ripe\\.net", "MAIL-FROM"},
		{"MAIL-From mleber@he.net", AuthMailFrom, "mleber@he.net", "MAIL-FROM"},
		{"IRRD-INTERNAL-AUTH", AuthIRRdInternal, "", "IRRD-INTERNAL-AUTH"},
	} {
		a, err := ParseAuth(c.in)
		if err != nil || a.Method != c.method || a.Value != c.value || a.Raw != c.in {
			t.Errorf("ParseAuth(%q) = %+v, %v; want method %v value %q", c.in, a, err, c.method, c.value)
		}
		if a.Method.String() != c.name {
			t.Errorf("%q: Method.String() = %q, want %q", c.in, a.Method.String(), c.name)
		}
	}
	for _, s := range []string{"BCRYPT-PW", "MAIL-FROM", "bcrypt-pw  "} {
		if _, err := ParseAuth(s); err == nil {
			t.Errorf("ParseAuth(%q): no error for a missing credential", s)
		}
	}
	// The existing constants keep their values.
	if AuthSSO != 6 || AuthBcrypt != 7 || AuthMailFrom != 8 || AuthIRRdInternal != 9 {
		t.Errorf("AuthMethod values moved: SSO %d, Bcrypt %d, MailFrom %d, IRRdInternal %d",
			AuthSSO, AuthBcrypt, AuthMailFrom, AuthIRRdInternal)
	}
	// A mntner guarded by them decodes without diagnostics.
	_, ds := Decode(parse("mntner: M\nauth: BCRYPT-PW $2b$12$x\nauth: MAIL-FROM a@b\nauth: IRRD-INTERNAL-AUTH\nmnt-by: M\nsource: RADB\n"))
	if len(ds) != 0 {
		t.Errorf("diagnostics %v", ds)
	}
}
