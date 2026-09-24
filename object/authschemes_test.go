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

// A tab separates an auth: scheme from its credential and a changed: address
// from its date, as a space does: RPSL values may use either, and real
// changed: lines do (two in the RADB dumps).
func TestAuthAndChangedTabSeparator(t *testing.T) {
	a, err := ParseAuth("CRYPT-PW\tabcdef")
	if err != nil || a.Method != AuthCrypt || a.Value != "abcdef" {
		t.Errorf("ParseAuth(CRYPT-PW<TAB>abcdef) = %+v, %v", a, err)
	}
	a, err = ParseAuth("MD5-PW \t $1$abc$xyz")
	if err != nil || a.Method != AuthMD5 || a.Value != "$1$abc$xyz" {
		t.Errorf("ParseAuth(MD5-PW, spaces and a tab) = %+v, %v", a, err)
	}
	c, err := ParseChanged("ddemore@clearcable.ca\t20180821")
	if err != nil || c.Email != "ddemore@clearcable.ca" || c.Date.Format("20060102") != "20180821" {
		t.Errorf("ParseChanged(<TAB>) = %+v, %v", c, err)
	}
}
