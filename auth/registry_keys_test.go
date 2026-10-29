package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
)

// warnedCase is a ruleCase whose object decodes with a Warning, which
// runRules' decode refuses: a key a registry writes its own way.
type warnedCase struct {
	name   string
	stored string
	action Action
	obj    string
	accept []string
	ok     bool
	reason string
}

// runWarned authorises each case's object as decoded, Warnings and all, after
// confirming the decode is the one the case is about: it carries a Warning
// under rule, and check holds.
func runWarned(t *testing.T, rule string, check func(object.Object) bool, cases []warnedCase) {
	t.Helper()
	for _, c := range cases {
		raw, _ := rpsl.ParseObject(c.obj)
		obj, ds := rpsl.Decode(raw)
		warned := false
		for _, d := range ds {
			warned = warned || (d.Rule == rule && d.Severity == rpsl.Warning)
		}
		if !warned || !check(obj) {
			t.Fatalf("%s: %q decoded with %v, not the %s Warning and value the case is about", c.name, c.obj, ds, rule)
		}
		srcs := []string{c.stored}
		for _, m := range testMntners {
			pw := "MD5-PW $1$other$pw"
			for _, a := range c.accept {
				if a == m {
					pw = "MD5-PW $1$abc$xyz"
				}
			}
			srcs = append(srcs, mntner(m, pw))
		}
		d, err := RIPE.Authorise(context.Background(), memDB(t, srcs...), Update{Action: c.action, Object: obj}, goodCred(), verifier())
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if d.OK != c.ok || !strings.Contains(d.String(), c.reason) {
			t.Errorf("%s: %s\n  want ok=%v with %q", c.name, d, c.ok, c.reason)
		}
	}
}

// An inetnum whose key is a prefix ("192.0.2.0/24", as LACNIC writes them)
// decodes to the prefix's range, with a Warning, and is authorised as the
// inetnum of that range: its parent's consent for a creation, the stored
// object's maintainers for a deletion, whichever way the key is spelled.
func TestRIPEInetnumPrefixKey(t *testing.T) {
	created := "inetnum: 192.0.2.0/24\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n"
	hostBits := "inetnum: 192.0.2.77/24\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n"
	runWarned(t, "object/inetnum-prefix-key", func(o object.Object) bool { return o.(*object.Inetnum).Lo.String() == "192.0.2.0" }, []warnedCase{
		{"create: the parent's mnt-lower", bigInetnum, Create, created, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"create: without the parent", bigInetnum, Create, created, []string{"MNT-OWN"}, false, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"create, host bits: the parent's mnt-lower", bigInetnum, Create, hostBits, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"delete: the stored lo - hi object", newInetnum, Delete, hostBits, []string{"MNT-OWN"}, true, "stored object's maintainers"},
		{"delete: refused", newInetnum, Delete, hostBits, []string{"MNT-OTHER"}, false, "stored object's maintainers"},
	})
}

// An aut-num whose key is a bare number ("aut-num: 64500", as LACNIC writes
// them) decodes to that AS, with a Warning, and is authorised as AS64500's
// aut-num: its as-block's consent for a creation, the stored object's
// maintainers for a deletion.
func TestRIPEAutNumBareNumber(t *testing.T) {
	block := "as-block: AS64000 - AS64999\nmnt-by: MNT-PARENT\nsource: RIPE\n"
	created := "aut-num: 64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n"
	runWarned(t, "object/aut-num-bare-number", func(o object.Object) bool { return o.(*object.AutNum).AS == 64500 }, []warnedCase{
		{"create: the as-block's maintainer", block, Create, created, []string{"MNT-OWN", "MNT-PARENT"}, true, "as-block AS64000 - AS64999"},
		{"create: without the as-block", block, Create, created, []string{"MNT-OWN"}, false, "as-block AS64000 - AS64999"},
		{"delete: the stored AS64500", "aut-num: AS64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n", Delete, created, []string{"MNT-OWN"}, true, "stored object's maintainers"},
	})
}

// MemDatabase keys an aut-num by its AS, written either way; a key that is no
// AS stays as written (upper-cased), and an empty one stays empty, never "AS".
func TestNormalAutNumKey(t *testing.T) {
	for key, want := range map[string]string{
		"AS64500":    "AS64500",
		"as64500":    "AS64500",
		"64500":      "AS64500",
		" 64500 ":    "AS64500",
		"AS1.10":     "AS65546",
		"4294967296": "4294967296",
		"AS-X":       "AS-X",
		"":           "",
	} {
		if got := normalKey("aut-num", key); got != want {
			t.Errorf("normalKey(aut-num, %q) = %q, want %q", key, got, want)
		}
	}
}
