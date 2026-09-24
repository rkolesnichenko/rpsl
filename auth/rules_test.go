package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// The maintainers the rule tests use. A case lists those that accept the
// credential; the rest reject it.
var testMntners = []string{"MNT-OWN", "MNT-PARENT", "MNT-LOWER", "MNT-ROUTES", "MNT-DOMAINS", "MNT-OTHER", "MNT-REF"}

type ruleCase struct {
	name   string
	stored []string // registry objects besides the maintainers
	action Action
	obj    string
	accept []string // maintainers the credential satisfies
	ok     bool
	reason string // a substring of the reasons: the deciding check
}

func runRules(t *testing.T, rules Rules, cases []ruleCase) {
	t.Helper()
	for _, c := range cases {
		srcs := append([]string(nil), c.stored...)
		for _, m := range testMntners {
			auth := "MD5-PW $1$other$pw"
			for _, a := range c.accept {
				if a == m {
					auth = "MD5-PW $1$abc$xyz"
				}
			}
			srcs = append(srcs, mntner(m, auth))
		}
		db := memDB(t, srcs...)
		d, err := rules.Authorise(context.Background(), db, Update{Action: c.action, Object: decode(t, c.obj)}, goodCred(), verifier())
		if err != nil {
			t.Errorf("%s %s: %v", rules, c.name, err)
			continue
		}
		if d.OK != c.ok || !strings.Contains(d.String(), c.reason) {
			t.Errorf("%s %s: %s\n  want ok=%v with %q", rules, c.name, d, c.ok, c.reason)
		}
	}
}

const (
	bigInetnum  = "inetnum: 192.0.0.0 - 192.0.255.255\nnetname: BIG\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"
	exactInet   = "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXACT\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"
	newInetnum  = "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n"
	newRoute    = "route: 192.0.2.0/24\norigin: AS64500\nmnt-by: MNT-OWN\nsource: RIPE\n"
	newPerson   = "person: A Person\nnic-hdl: AP1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n"
	otherPerson = "person: A Person\nnic-hdl: AP1-RIPE\nmnt-by: MNT-OTHER\nsource: RIPE\n"
)

func TestRIPERules(t *testing.T) {
	runRules(t, RIPE, []ruleCase{
		// Every object needs its own maintainers.
		{"create: own maintainer", nil, Create, newPerson, []string{"MNT-OWN"}, true, "own maintainers"},
		{"create: own maintainer refuses", nil, Create, newPerson, []string{"MNT-OTHER"}, false, "own maintainers"},
		{"create: no mnt-by", nil, Create, "person: A Person\nnic-hdl: AP1-RIPE\nsource: RIPE\n", []string{"MNT-OWN"}, false, "names no maintainer"},
		// A new maintainer naming itself is checked against its own auth: lines.
		{"create mntner: self", nil, Create, mntner("MNT-NEW", "MD5-PW $1$abc$xyz"), nil, true, "the new maintainer itself"},
		{"create mntner: self refuses", nil, Create, mntner("MNT-NEW", "MD5-PW $1$other$pw"), nil, false, "own maintainers"},

		// Address space: the strictly less specific parent's mnt-lower:, else mnt-by:.
		{"inetnum: parent mnt-lower", []string{bigInetnum}, Create, newInetnum, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"inetnum: mnt-lower shadows mnt-by", []string{bigInetnum}, Create, newInetnum, []string{"MNT-OWN", "MNT-PARENT"}, false, "parent inetnum"},
		{"inetnum: parent mnt-by", []string{"inetnum: 192.0.0.0 - 192.0.255.255\nnetname: BIG\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, newInetnum, []string{"MNT-OWN", "MNT-PARENT"}, true, "parent inetnum"},
		{"inetnum: no parent", nil, Create, newInetnum, []string{"MNT-OWN"}, false, "no less specific inetnum"},
		{"inetnum: an exact one is not the parent", []string{bigInetnum, strings.Replace(exactInet, "MNT-LOWER", "MNT-OTHER", 1)}, Create, newInetnum, []string{"MNT-OWN", "MNT-LOWER"}, true, "192.0.0.0 - 192.0.255.255"},
		{"inet6num: parent", []string{"inet6num: 2001:db8::/32\nnetname: BIG\nmnt-lower: MNT-LOWER\nsource: RIPE\n"}, Create, "inet6num: 2001:db8:1::/48\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inet6num"},

		// aut-num: the most specific as-block.
		{"aut-num: narrower as-block", []string{
			"as-block: AS1 - AS65535\nmnt-lower: MNT-OTHER\nsource: RIPE\n",
			"as-block: AS64000 - AS64999\nmnt-by: MNT-PARENT\nsource: RIPE\n",
		}, Create, "aut-num: AS64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "as-block AS64000 - AS64999"},
		{"aut-num: wider as-block's maintainer is not enough", []string{
			"as-block: AS1 - AS65535\nmnt-lower: MNT-OTHER\nsource: RIPE\n",
			"as-block: AS64000 - AS64999\nmnt-by: MNT-PARENT\nsource: RIPE\n",
		}, Create, "aut-num: AS64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-OTHER"}, false, "as-block AS64000 - AS64999"},
		{"aut-num: no as-block", nil, Create, "aut-num: AS64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "no as-block holds AS64500"},

		// route: a covering route before address space; no origin check.
		{"route: covering route's mnt-routes", []string{
			bigInetnum, "route: 192.0.0.0/16\norigin: AS1\nmnt-routes: MNT-ROUTES\nmnt-by: MNT-PARENT\nsource: RIPE\n",
		}, Create, newRoute, []string{"MNT-OWN", "MNT-ROUTES"}, true, "parent route 192.0.0.0/16AS1"},
		{"route: the inetnum is not asked when a route covers", []string{
			bigInetnum, "route: 192.0.0.0/16\norigin: AS1\nmnt-routes: MNT-ROUTES\nmnt-by: MNT-PARENT\nsource: RIPE\n",
		}, Create, newRoute, []string{"MNT-OWN", "MNT-LOWER"}, false, "parent route"},
		{"route: exact inetnum skips mnt-lower", []string{exactInet}, Create, newRoute, []string{"MNT-OWN", "MNT-PARENT"}, true, "parent inetnum 192.0.2.0 - 192.0.2.255"},
		{"route: exact inetnum's mnt-lower is no authority", []string{exactInet}, Create, newRoute, []string{"MNT-OWN", "MNT-LOWER"}, false, "parent inetnum"},
		{"route: covering inetnum's mnt-lower", []string{bigInetnum}, Create, newRoute, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum"},
		{"route: mnt-routes out of scope", []string{"inetnum: 192.0.2.0 - 192.0.2.255\nnetname: X\nmnt-routes: MNT-ROUTES {198.51.100.0/24}\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, newRoute, []string{"MNT-OWN", "MNT-ROUTES", "MNT-PARENT"}, false, "delegates no maintainer"},
		{"route: no covering space", nil, Create, newRoute, []string{"MNT-OWN"}, false, "no route or inetnum covers"},

		// Reverse domains: mnt-domains:, then mnt-lower: when strictly less specific, then mnt-by:.
		{"domain: mnt-domains", []string{strings.Replace(exactInet, "netname: EXACT\n", "netname: EXACT\nmnt-domains: MNT-DOMAINS\n", 1)}, Create, "domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-DOMAINS"}, true, "parent inetnum"},
		{"domain: exact space skips mnt-lower", []string{exactInet}, Create, "domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-LOWER"}, false, "parent inetnum"},
		{"domain: covering space's mnt-lower", []string{bigInetnum}, Create, "domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"domain: e164 has no parent", nil, Create, "domain: 4.4.e164.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, true, "own maintainers"},
		{"domain: no space", nil, Create, "domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "no inetnum holds"},

		// Hierarchical set names: the object left of the last colon.
		{"as-set under an aut-num", []string{"aut-num: AS1\nas-name: X\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "as-set: AS1:AS-FOO\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-LOWER"}, true, "parent aut-num AS1"},
		{"as-set under an aut-num: mnt-by is shadowed", []string{"aut-num: AS1\nas-name: X\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "as-set: AS1:AS-FOO\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, false, "parent aut-num AS1"},
		{"as-set under an as-set", []string{"as-set: AS-FOO\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "as-set: AS-FOO:AS-BAR\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "parent as-set AS-FOO"},
		{"route-set under a route-set", []string{"route-set: RS-A\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "route-set: RS-A:RS-B\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "parent route-set RS-A"},
		{"route-set under an aut-num", []string{"aut-num: AS1\nas-name: X\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "route-set: AS1:RS-X\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "parent aut-num AS1"},
		{"as-set two levels down", []string{"as-set: AS1:AS-FOO\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "as-set: AS1:AS-FOO:AS-BAR\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "parent as-set AS1:AS-FOO"},
		{"set: missing parent", nil, Create, "as-set: AS1:AS-FOO\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "does not exist"},
		{"set: a flat name has no parent", nil, Create, "as-set: AS-FOO\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, true, "own maintainers"},

		// Modify and delete: the stored object's maintainers.
		{"modify: the stored mnt-by decides", []string{newPerson}, Modify, otherPerson, []string{"MNT-OWN"}, true, "stored object's maintainers"},
		{"modify: the new mnt-by is not enough", []string{newPerson}, Modify, otherPerson, []string{"MNT-OTHER"}, false, "stored object's maintainers"},
		{"modify: nothing stored", nil, Modify, newPerson, []string{"MNT-OWN"}, false, "no stored person"},
		{"delete", []string{newPerson}, Delete, newPerson, []string{"MNT-OWN"}, true, "stored object's maintainers"},
		{"delete: refused", []string{newPerson}, Delete, newPerson, []string{"MNT-OTHER"}, false, "stored object's maintainers"},
		{"delete domain: the space's mnt-domains", []string{
			strings.Replace(exactInet, "netname: EXACT\n", "netname: EXACT\nmnt-domains: MNT-DOMAINS\n", 1),
			"domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n",
		}, Delete, "domain: 2.0.192.in-addr.arpa\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-DOMAINS"}, true, "mnt-domains"},

		// New references need the referenced object's consent.
		{"irt: added", []string{bigInetnum, irt("IRT-X", "MD5-PW $1$other$pw")}, Create,
			strings.Replace(newInetnum, "mnt-by:", "mnt-irt: IRT-X\nmnt-by:", 1), []string{"MNT-OWN", "MNT-LOWER"}, false, "the added irts"},
		{"irt: already there", []string{bigInetnum, irt("IRT-X", "MD5-PW $1$other$pw"), strings.Replace(newInetnum, "mnt-by:", "mnt-irt: IRT-X\nmnt-by:", 1)}, Modify,
			strings.Replace(newInetnum, "mnt-by:", "mnt-irt: IRT-X\nremarks: changed\nmnt-by:", 1), []string{"MNT-OWN"}, true, "stored object's maintainers"},
		{"org: needs its mnt-ref", []string{"organisation: ORG-X1-RIPE\norg-name: X\nmnt-ref: MNT-REF\nsource: RIPE\n"}, Create,
			"person: A Person\nnic-hdl: AP1-RIPE\norg: ORG-X1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "mnt-ref"},
		{"org: with its mnt-ref", []string{"organisation: ORG-X1-RIPE\norg-name: X\nmnt-ref: MNT-REF\nsource: RIPE\n"}, Create,
			"person: A Person\nnic-hdl: AP1-RIPE\norg: ORG-X1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-REF"}, true, "mnt-ref"},
		{"org: without mnt-ref consents to nothing", []string{"organisation: ORG-X1-RIPE\norg-name: X\nsource: RIPE\n"}, Create,
			"person: A Person\nnic-hdl: AP1-RIPE\norg: ORG-X1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "names no maintainer"},
		{"admin-c: a person's mnt-ref", []string{"person: B Person\nnic-hdl: BP1-RIPE\nmnt-ref: MNT-REF\nmnt-by: MNT-OTHER\nsource: RIPE\n"}, Create,
			"person: A Person\nnic-hdl: AP1-RIPE\nadmin-c: BP1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, false, "person BP1-RIPE referenced in admin-c"},
		{"admin-c: no mnt-ref, no consent needed", []string{"person: B Person\nnic-hdl: BP1-RIPE\nmnt-by: MNT-OTHER\nsource: RIPE\n"}, Create,
			"person: A Person\nnic-hdl: AP1-RIPE\nadmin-c: BP1-RIPE\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, true, "own maintainers"},
	})
}

func TestIRRdRules(t *testing.T) {
	inetWithRoutes := "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: X\nmnt-routes: MNT-ROUTES\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"
	runRules(t, IRRd, []ruleCase{
		{"create: own maintainer", nil, Create, newPerson, []string{"MNT-OWN"}, true, "submitted object's maintainers"},
		{"create mntner: an administrator's", nil, Create, mntner("MNT-NEW", "MD5-PW $1$abc$xyz"), nil, false, "administrator"},
		// A modification needs both the new version's and the stored one's maintainers.
		{"modify: both", []string{newPerson}, Modify, otherPerson, []string{"MNT-OWN", "MNT-OTHER"}, true, "stored object's maintainers"},
		{"modify: the stored alone is not enough", []string{newPerson}, Modify, otherPerson, []string{"MNT-OWN"}, false, "submitted object's maintainers"},
		{"modify: the new alone is not enough", []string{newPerson}, Modify, otherPerson, []string{"MNT-OTHER"}, false, "stored object's maintainers"},
		{"modify mntner: its new auth: lines too", []string{mntner("MNT-NEW", "MD5-PW $1$abc$xyz")}, Modify,
			strings.Replace(mntner("MNT-NEW", "MD5-PW $1$other$pw"), "mnt-by: MNT-NEW", "mnt-by: MNT-OWN", 1), []string{"MNT-OWN"}, false, "new version's own auth"},
		// Routes: the address space first, and only its mnt-by:.
		{"route: the space's mnt-by", []string{inetWithRoutes}, Create, newRoute, []string{"MNT-OWN", "MNT-PARENT"}, true, "related inetnum"},
		{"route: mnt-routes is not IRRd's", []string{inetWithRoutes}, Create, newRoute, []string{"MNT-OWN", "MNT-ROUTES"}, false, "related inetnum"},
		{"route: a less specific route when no space", []string{"route: 192.0.0.0/16\norigin: AS1\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, newRoute, []string{"MNT-OWN", "MNT-PARENT"}, true, "related route 192.0.0.0/16AS1"},
		{"route: nothing related", nil, Create, newRoute, []string{"MNT-OWN"}, true, "submitted object's maintainers"},
		// Sets: the aut-num of the name's first segment, when it exists.
		{"set: the aut-num's mnt-by", []string{"aut-num: AS1\nas-name: X\nmnt-lower: MNT-LOWER\nmnt-by: MNT-PARENT\nsource: RIPE\n"}, Create, "as-set: AS1:AS-FOO:AS-BAR\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN", "MNT-PARENT"}, true, "related aut-num AS1"},
		{"set: no aut-num, no check", nil, Create, "as-set: AS1:AS-FOO\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, true, "submitted object's maintainers"},
		// No parent checks for other classes.
		{"inetnum: no parent check", nil, Create, newInetnum, []string{"MNT-OWN"}, true, "submitted object's maintainers"},
		{"aut-num: no as-block check", nil, Create, "aut-num: AS64500\nas-name: X\nmnt-by: MNT-OWN\nsource: RIPE\n", []string{"MNT-OWN"}, true, "submitted object's maintainers"},
	})
}

// Where the two models part, the same update is decided differently; this
// pins each difference, so a change on either side shows.
func TestRIPEAndIRRdDiffer(t *testing.T) {
	stored := []string{"inetnum: 192.0.2.0 - 192.0.2.255\nnetname: X\nmnt-routes: MNT-ROUTES\nmnt-by: MNT-PARENT\nsource: RIPE\n"}
	for _, c := range []struct {
		name     string
		stored   []string
		action   Action
		obj      string
		accept   []string
		ripe, ir bool
	}{
		{"route: mnt-routes (RIPE) or mnt-by (IRRd)", stored, Create, newRoute, []string{"MNT-OWN", "MNT-ROUTES"}, true, false},
		{"modify: the new version's maintainers count only in IRRd", []string{newPerson}, Modify, otherPerson, []string{"MNT-OWN"}, true, false},
		{"inetnum without a parent", nil, Create, newInetnum, []string{"MNT-OWN"}, false, true},
		{"a new maintainer", nil, Create, mntner("MNT-NEW", "MD5-PW $1$abc$xyz"), nil, true, false},
	} {
		for _, r := range []struct {
			rules Rules
			want  bool
		}{{RIPE, c.ripe}, {IRRd, c.ir}} {
			srcs := append([]string(nil), c.stored...)
			for _, m := range testMntners {
				auth := "MD5-PW $1$other$pw"
				for _, a := range c.accept {
					if a == m {
						auth = "MD5-PW $1$abc$xyz"
					}
				}
				srcs = append(srcs, mntner(m, auth))
			}
			d, err := r.rules.Authorise(context.Background(), memDB(t, srcs...), Update{Action: c.action, Object: decode(t, c.obj)}, goodCred(), verifier())
			if err != nil || d.OK != r.want {
				t.Errorf("%s under %s: %s, %v; want ok=%v", c.name, r.rules, d, err, r.want)
			}
		}
	}
}

// Updates Authorise cannot place are refused, whatever the credential.
func TestAuthoriseRefusesTheUnplaceable(t *testing.T) {
	db := memDB(t, mntner("MNT-OWN", "MD5-PW $1$abc$xyz"))
	for _, rules := range []Rules{RIPE, IRRd} {
		for _, u := range []Update{
			{Action: Create},
			{Action: Action(9), Object: decode(t, newPerson)},
		} {
			if d, err := rules.Authorise(context.Background(), db, u, goodCred(), verifier()); err != nil || d.OK {
				t.Errorf("%s %+v: %s, %v; want a refusal", rules, u, d, err)
			}
		}
	}
	if RIPE.String() != "RIPE" || IRRd.String() != "IRRd" || (Rules{}).String() != "RIPE" {
		t.Error("Rules names")
	}
	if Create.String() != "create" || Delete.String() != "delete" || Action(9).String() != "Action(9)" {
		t.Error("Action names")
	}
}

var _ object.Object // the object import is shared with the helpers above
