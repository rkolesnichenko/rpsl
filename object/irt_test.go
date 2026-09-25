package object

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// An irt's auth: lines decode as a mntner's do (RIPE defines them alike): the
// scheme and credential are read, the line is kept as written, and a scheme
// this library does not know is a warning, not a loss.
func TestIrtAuth(t *testing.T) {
	o := parse("irt:     IRT-EXAMPLE\n" +
		"address: Somewhere\n" +
		"e-mail:  irt@example.net\n" +
		"auth:    MD5-PW $1$salt$hash\n" +
		"auth:    PGPKEY-1234ABCD\n" +
		"auth:    X509-7\n" +
		"auth:    SSO noreply@ripe.net   # Real value hidden for security\n" +
		"auth:    WEIRD-PW secret\n" +
		"source:  RIPE\n")
	obj, diags := Decode(o)
	irt, ok := obj.(Irt)
	if !ok {
		t.Fatalf("decoded %T, want Irt", obj)
	}
	want := []struct {
		method AuthMethod
		value  string
	}{
		{AuthMD5, "$1$salt$hash"}, {AuthPGPKey, "PGPKEY-1234ABCD"}, {AuthX509, "X509-7"},
		{AuthSSO, "noreply@ripe.net"}, {AuthUnknown, ""},
	}
	if len(irt.Auth) != len(want) {
		t.Fatalf("Auth = %+v, want %d entries", irt.Auth, len(want))
	}
	for i, w := range want {
		if a := irt.Auth[i]; a.Method != w.method || (w.method != AuthUnknown && a.Value != w.value) {
			t.Errorf("Auth[%d] = %v %q, want %v %q", i, a.Method, a.Value, w.method, w.value)
		}
	}
	if got := irt.Auth[4].String(); got != "WEIRD-PW secret" {
		t.Errorf("unknown scheme kept as %q, want the line as written", got)
	}
	if len(diags) != 1 || diags[0].Rule != "object/irt-auth" || diags[0].Span.StartLine != 8 {
		t.Fatalf("diagnostics %+v, want one object/irt-auth on line 8", diags)
	}
	m, _ := Decode(parse("mntner: MNT-EXAMPLE\n" + "auth: MD5-PW $1$salt$hash\nauth: PGPKEY-1234ABCD\n" +
		"auth: X509-7\nauth: SSO noreply@ripe.net\nauth: WEIRD-PW secret\n"))
	if !reflect.DeepEqual(m.(Mntner).Auth, irt.Auth) {
		t.Errorf("mntner and irt decode the same auth: lines differently:\n%+v\n%+v", m.(Mntner).Auth, irt.Auth)
	}
}

// attrTypeExceptions are attributes whose decoded type legitimately depends on
// the class.
var attrTypeExceptions = map[string]string{
	"members":    "a set's members are what its class may contain: ASNs and sets, prefixes, routers or peerings",
	"mp-members": "as members:",
}

// An attribute decodes to the same element type in every class that has it
// (string and []string count as the same). The field-drift test checks which
// field a value lands in, not its type, so it could not see that irt kept
// auth: as strings while mntner parsed it; this can.
func TestAttributeTypesAgreeAcrossClasses(t *testing.T) {
	uses := map[string]map[string][]string{} // attribute -> element type -> classes
	for class, key := range classKey {
		obj, _ := Decode(parse(class + ": " + key[0] + "\n"))
		typ := reflect.TypeOf(obj)
		for _, p := range []Profile{RIPE, RFCStrict, IRRd} {
			spec, ok := p.Class(class)
			if !ok {
				continue
			}
			for attr := range spec.Attrs {
				if attr == class || attrTypeExceptions[attr] != "" {
					continue
				}
				f, ok := typ.FieldByName(fieldFor(attr))
				if !ok {
					continue // TestEveryAttributeLandsInItsOwnField reports a missing field
				}
				elem := f.Type
				if elem.Kind() == reflect.Slice {
					elem = elem.Elem()
				}
				if uses[attr] == nil {
					uses[attr] = map[string][]string{}
				}
				if !contains(uses[attr][elem.String()], class) {
					uses[attr][elem.String()] = append(uses[attr][elem.String()], class)
				}
			}
		}
	}
	for attr, types := range uses {
		if len(types) < 2 {
			continue
		}
		var parts []string
		for typ, classes := range types {
			sort.Strings(classes)
			parts = append(parts, typ+" in "+strings.Join(classes, ", "))
		}
		sort.Strings(parts)
		t.Errorf("%s: decoded to different types: %s", attr, strings.Join(parts, "; "))
	}
}
