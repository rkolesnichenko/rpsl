package object

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

func missingRequired(ds []ast.Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Rule == "dict/missing-required" {
			out = append(out, d.Message)
		}
	}
	return out
}

// key-cert, poem and poetic-form are RIPE classes, not unknown ones.
func TestRIPEKnowsItsClasses(t *testing.T) {
	for _, src := range []string{
		"key-cert: PGPKEY-1234ABCD\ncertif: -----BEGIN PGP PUBLIC KEY BLOCK-----\nmnt-by: MNT-X\nsource: RIPE\n",
		"poem: POEM-X\nform: FORM-HAIKU\ntext: a line\nmnt-by: LIM-MNT\nsource: RIPE\n",
		"poetic-form: FORM-HAIKU\nadmin-c: EX1-RIPE\nmnt-by: LIM-MNT\nsource: RIPE\n",
	} {
		if d := RIPE.Validate(parse(src)); len(d) != 0 {
			t.Errorf("RIPE.Validate(%q) = %+v, want none", strings.SplitN(src, "\n", 2)[0], d)
		}
	}
}

// RFC 4012 lets a peering-set carry only mp-peering (and a filter-set only
// mp-filter); one of each pair is still required.
func TestOneOfRequirements(t *testing.T) {
	for _, p := range []Profile{RIPE, RFCStrict} {
		for _, c := range []struct {
			src     string
			missing bool
		}{
			{"peering-set: PRNG-X\nmp-peering: AS1\n", false},
			{"peering-set: PRNG-X\npeering: AS1\n", false},
			{"peering-set: PRNG-X\n", true},
			{"filter-set: FLTR-X\nmp-filter: ANY\n", false},
			{"filter-set: FLTR-X\n", true},
		} {
			var got bool
			for _, m := range missingRequired(p.Validate(parse(c.src))) {
				if strings.Contains(m, "one of") {
					got = true
				}
			}
			if got != c.missing {
				t.Errorf("%s: %q one-of missing = %v, want %v", p.Name(), c.src, got, c.missing)
			}
		}
	}
}

// RFC 2622 §3.1: descr, tech-c, mnt-by, changed and source are mandatory on
// every class (admin-c too on aut-num), and all eight common attributes are
// valid everywhere.
func TestRFCStrictCommonAttributes(t *testing.T) {
	conformant := "route: 192.0.2.0/24\ndescr: example\norigin: AS65000\ntech-c: EX1-RIPE\n" +
		"admin-c: EX1-RIPE\nremarks: r\nnotify: noc@example.net\nmnt-by: MNT-X\n" +
		"changed: noc@example.net 20200101\nsource: RADB\n"
	if d := RFCStrict.Validate(parse(conformant)); len(d) != 0 {
		t.Errorf("RFC-conformant route: %+v, want no diagnostics", d)
	}
	minimal := "route: 192.0.2.0/24\norigin: AS65000\nmnt-by: MNT-X\nsource: RADB\n"
	want := []string{
		`required attribute "changed" is missing for class "route"`,
		`required attribute "descr" is missing for class "route"`,
		`required attribute "tech-c" is missing for class "route"`,
	}
	if got := missingRequired(RFCStrict.Validate(parse(minimal))); !reflect.DeepEqual(got, want) {
		t.Errorf("RFCStrict missing-required = %q, want %q", got, want)
	}
	if d := RIPE.Validate(parse(minimal)); len(d) != 0 {
		t.Errorf("RIPE flagged a minimal RIPE route: %+v", d)
	}
	autnum := "aut-num: AS1\nas-name: X\ndescr: d\ntech-c: EX1-RIPE\nmnt-by: M\nchanged: a@b 20200101\nsource: RADB\n"
	if got := missingRequired(RFCStrict.Validate(parse(autnum))); len(got) != 1 || !strings.Contains(got[0], "admin-c") {
		t.Errorf("RFCStrict aut-num missing-required = %q, want admin-c", got)
	}
}

// RFCStrict follows the RFC tables beyond RFC 2622: RFC 2725 (as-block,
// referral-by, mnt-routes and mnt-lower), RFC 2726 (key-cert) and RFC 4012
// (route6, inet6num, mp-members only on route-set and rtr-set).
func TestRFCStrictTables(t *testing.T) {
	req, reqS, opt, optS := AttrSpec{Required: true}, AttrSpec{Required: true, Single: true},
		AttrSpec{}, AttrSpec{Single: true}
	for _, c := range []struct {
		class, attr string
		want        AttrSpec
		present     bool
	}{
		{"route", "mnt-lower", opt, true}, // RFC 2725 §10.1
		{"route", "mnt-routes", opt, true},
		{"route6", "mnt-lower", opt, true}, // RFC 4012 §3
		{"route6", "mnt-routes", opt, true},
		{"aut-num", "mnt-routes", opt, true}, // RFC 2725 §10.1, RFC 4012 §5
		{"aut-num", "mnt-lower", opt, true},
		{"inetnum", "mnt-routes", opt, true},
		{"inetnum", "mnt-lower", opt, true},
		{"inet6num", "netname", reqS, true}, // RFC 4012 §5
		{"inet6num", "descr", req, true},
		{"inet6num", "country", req, true},
		{"inet6num", "mnt-lower", opt, true},
		{"inet6num", "mnt-routes", opt, true},
		{"inet6num", "status", AttrSpec{}, false},
		{"as-set", "mp-members", AttrSpec{}, false}, // RFC 4012 §4.1: unchanged
		{"route-set", "mp-members", opt, true},
		{"as-block", "descr", opt, true}, // RFC 2725 §10.1
		{"as-block", "admin-c", req, true},
		{"as-block", "mnt-lower", opt, true},
		{"mntner", "referral-by", req, true},
		{"key-cert", "key-cert", reqS, true}, // RFC 2726 §2.1
		{"key-cert", "method", optS, true},
		{"key-cert", "owner", opt, true},
		{"key-cert", "fingerpr", optS, true},
		{"key-cert", "certif", reqS, true},
		{"key-cert", "descr", AttrSpec{}, false},
		{"key-cert", "tech-c", AttrSpec{}, false},
	} {
		spec, ok := RFCStrict.Class(c.class)
		if !ok {
			t.Errorf("RFCStrict has no %s class", c.class)
			continue
		}
		got, present := spec.Attrs[c.attr]
		if present != c.present || got != c.want {
			t.Errorf("RFCStrict %s.%s = %+v (present %v), want %+v (present %v)",
				c.class, c.attr, got, present, c.want, c.present)
		}
	}
}
