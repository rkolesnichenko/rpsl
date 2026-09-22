package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// RouteAuthority follows RFC 2725 §4's order: mnt-routes:, then mnt-lower:,
// then mnt-by:.
func TestRouteAuthorityOrder(t *testing.T) {
	prefix := mustPrefix(t, "192.0.2.0/24")
	for _, c := range []struct {
		name string
		src  string
		want []string
	}{
		{"mnt-routes wins", `inetnum: 192.0.2.0 - 192.0.2.255
mnt-routes: MNT-ROUTES
mnt-lower: MNT-LOWER
mnt-by: MNT-BY
source: RIPE
`, []string{"MNT-ROUTES"}},
		{"mnt-lower next", `inetnum: 192.0.2.0 - 192.0.2.255
mnt-lower: MNT-LOWER
mnt-by: MNT-BY
source: RIPE
`, []string{"MNT-LOWER"}},
		{"mnt-by last", `inetnum: 192.0.2.0 - 192.0.2.255
mnt-by: MNT-BY
source: RIPE
`, []string{"MNT-BY"}},
		{"several are all authoritative", `inetnum: 192.0.2.0 - 192.0.2.255
mnt-routes: MNT-A
mnt-routes: MNT-B
source: RIPE
`, []string{"MNT-A", "MNT-B"}},
	} {
		got := RouteAuthority(decode(t, c.src), prefix)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: RouteAuthority = %v, want %v", c.name, got, c.want)
		}
	}
	// A class with no routing authority at all yields nothing.
	if got := RouteAuthority(decode(t, "person: P\nnic-hdl: EX1-RIPE\nmnt-by: M\nsource: RIPE\n"), prefix); got != nil {
		t.Errorf("RouteAuthority of a person = %v, want none", got)
	}
	if got := RouteAuthority(nil, prefix); got != nil {
		t.Errorf("RouteAuthority(nil) = %v", got)
	}
}

// An mnt-routes: scope means what it says: it delegates the prefixes it lists
// and no others, and it does not fall back to mnt-by: for the rest. This is the
// check that stops a narrow delegation becoming a wide one.
func TestRouteAuthorityScope(t *testing.T) {
	src := `inetnum:        192.0.2.0 - 192.0.2.255
mnt-routes:     MNT-DELEGATE {192.0.2.0/25^+}
mnt-by:         MNT-HOLDER
source:         RIPE
`
	o := decode(t, src)
	for _, c := range []struct {
		prefix string
		want   []string
	}{
		{"192.0.2.0/25", []string{"MNT-DELEGATE"}},
		{"192.0.2.0/26", []string{"MNT-DELEGATE"}}, // inside the ^+ scope
		{"192.0.2.128/25", nil},                    // outside it: nobody, not MNT-HOLDER
		{"192.0.2.0/24", nil},                      // the whole block is not delegated
		{"198.51.100.0/24", nil},
	} {
		got := RouteAuthority(o, mustPrefix(t, c.prefix))
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("RouteAuthority(%s) = %v, want %v", c.prefix, got, c.want)
		}
	}
	// ANY, and a bare maintainer with no scope, both cover everything.
	any := decode(t, "inetnum: 192.0.2.0 - 192.0.2.255\nmnt-routes: MNT-A ANY\nmnt-routes: MNT-B\nsource: RIPE\n")
	got := RouteAuthority(any, mustPrefix(t, "198.51.100.0/24"))
	if want := []string{"MNT-A", "MNT-B"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("RouteAuthority with ANY = %v, want %v", got, want)
	}
}

const (
	autNumSrc = `aut-num:        AS64500
as-name:        EXAMPLE
mnt-routes:     MNT-AS
mnt-by:         MNT-AS
source:         RIPE
`
	spaceSrc = `inetnum:        192.0.2.0 - 192.0.2.255
mnt-routes:     MNT-SPACE
mnt-by:         MNT-SPACE
source:         RIPE
`
)

func routeReq(t *testing.T, mntBy []string, origin, space object.Object) RouteRequest {
	t.Helper()
	return RouteRequest{Prefix: mustPrefix(t, "192.0.2.0/24"), MntBy: mntBy, Origin: origin, Space: space}
}

// All three permissions of RFC 2725 §4 must be held.
func TestRouteCreation(t *testing.T) {
	ctx, v := context.Background(), verifier()
	reg := newRegistry(t,
		mntner("MNT-OWN", "MD5-PW $1$abc$xyz"),
		mntner("MNT-AS", "MD5-PW $1$abc$xyz"),
		mntner("MNT-SPACE", "MD5-PW $1$abc$xyz"),
		mntner("MNT-OTHER", "MD5-PW $1$other$pw"),
	)
	origin, space := decode(t, autNumSrc), decode(t, spaceSrc)

	d, err := RouteCreation(ctx, reg, routeReq(t, []string{"MNT-OWN"}, origin, space), goodCred(), v)
	if err != nil {
		t.Fatal(err)
	}
	if !d.OK {
		t.Errorf("a holder of all three maintainers was refused: %v", d)
	}
	if len(d.Reasons) != 3 {
		t.Errorf("Reasons = %v, want one per check", d.Reasons)
	}

	// Holding the wrong credential fails at the first check.
	d, _ = RouteCreation(ctx, reg, routeReq(t, []string{"MNT-OWN"}, origin, space), wrongCred(), v)
	if d.OK || len(d.Reasons) != 1 {
		t.Errorf("a wrong credential gave %v", d)
	}

	// Owning the object but not the AS is not enough — this is the hijack case.
	other := newRegistry(t,
		mntner("MNT-OWN", "MD5-PW $1$abc$xyz"),
		mntner("MNT-AS", "MD5-PW $1$other$pw"),
		mntner("MNT-SPACE", "MD5-PW $1$abc$xyz"),
	)
	d, _ = RouteCreation(ctx, other, routeReq(t, []string{"MNT-OWN"}, origin, space), goodCred(), v)
	if d.OK {
		t.Errorf("a route was authorised without the origin AS's permission: %v", d)
	}
	if !strings.Contains(strings.Join(d.Reasons, " "), "origin AS") {
		t.Errorf("Reasons do not name the failing check: %v", d.Reasons)
	}

	// Owning the object and the AS but not the address space is not enough
	// either — the other half of the same hijack.
	noSpace := newRegistry(t,
		mntner("MNT-OWN", "MD5-PW $1$abc$xyz"),
		mntner("MNT-AS", "MD5-PW $1$abc$xyz"),
		mntner("MNT-SPACE", "MD5-PW $1$other$pw"),
	)
	d, _ = RouteCreation(ctx, noSpace, routeReq(t, []string{"MNT-OWN"}, origin, space), goodCred(), v)
	if d.OK {
		t.Errorf("a route was authorised without the address space's permission: %v", d)
	}
	if !strings.Contains(strings.Join(d.Reasons, " "), "address space") {
		t.Errorf("Reasons do not name the failing check: %v", d.Reasons)
	}
}

// An unknown origin or address space authorises nothing: absence is not consent.
func TestRouteCreationMissingContext(t *testing.T) {
	ctx, v := context.Background(), verifier()
	reg := newRegistry(t, mntner("MNT-OWN", "MD5-PW $1$abc$xyz"), mntner("MNT-AS", "MD5-PW $1$abc$xyz"))
	origin := decode(t, autNumSrc)

	d, _ := RouteCreation(ctx, reg, routeReq(t, []string{"MNT-OWN"}, nil, decode(t, spaceSrc)), goodCred(), v)
	if d.OK || !strings.Contains(strings.Join(d.Reasons, " "), "not in the registry") {
		t.Errorf("an unknown origin AS gave %v", d)
	}
	d, _ = RouteCreation(ctx, reg, routeReq(t, []string{"MNT-OWN"}, origin, nil), goodCred(), v)
	if d.OK || !strings.Contains(strings.Join(d.Reasons, " "), "not in the registry") {
		t.Errorf("an unknown address space gave %v", d)
	}
	// An address space that delegates nothing for this prefix refuses it.
	narrow := decode(t, "inetnum: 192.0.2.0 - 192.0.2.255\nmnt-routes: MNT-SPACE {198.51.100.0/24}\nsource: RIPE\n")
	d, _ = RouteCreation(ctx, reg, routeReq(t, []string{"MNT-OWN"}, origin, narrow), goodCred(), v)
	if d.OK || !strings.Contains(strings.Join(d.Reasons, " "), "delegates no maintainer") {
		t.Errorf("an out-of-scope delegation gave %v", d)
	}
}

// The request builders read a decoded route or route6.
func TestRouteRequestBuilders(t *testing.T) {
	r := decode(t, "route: 192.0.2.0/24\norigin: AS64500\nmnt-by: MNT-OWN\nsource: RIPE\n").(object.Route)
	req := RouteRequestFor(r, nil, nil)
	if req.Prefix.String() != "192.0.2.0/24" || len(req.MntBy) != 1 || req.MntBy[0] != "MNT-OWN" {
		t.Errorf("RouteRequestFor = %+v", req)
	}
	r6 := decode(t, "route6: 2001:db8::/32\norigin: AS64500\nmnt-by: MNT-OWN\nsource: RIPE\n").(object.Route6)
	req = RouteRequestFor6(r6, nil, nil)
	if req.Prefix.String() != "2001:db8::/32" {
		t.Errorf("RouteRequestFor6 = %+v", req)
	}
}
