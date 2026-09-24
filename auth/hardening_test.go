package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
)

// rawOnly is an object the typed layer did not build: only its text is known.
type rawOnly struct{ raw *ast.Object }

func (r rawOnly) Class() string    { return r.raw.Class() }
func (r rawOnly) Raw() *ast.Object { return r.raw }

// An update that adds an mnt-irt: reference needs the irt's consent however
// the objects are passed: as pointers, or as a class the typed layer does not
// know. Reading no reference from a shape it did not recognise used to pass
// the update.
func TestMntIrtPointerAndUnknownShapes(t *testing.T) {
	ctx, v := context.Background(), verifier()
	reg := newIrtRegistry(t, irt("IRT-VICTIM", "MD5-PW $1$other$pw"))
	before := decode(t, inetnum()).(object.Inetnum)
	after := decode(t, inetnum("IRT-VICTIM")).(object.Inetnum)
	before6 := decode(t, "inet6num: 2001:db8::/32\nnetname: X\nsource: RIPE\n").(object.Inet6num)
	after6 := decode(t, "inet6num: 2001:db8::/32\nnetname: X\nmnt-irt: IRT-VICTIM\nsource: RIPE\n").(object.Inet6num)
	for _, c := range []struct {
		name          string
		before, after object.Object
	}{
		{"values", before, after},
		{"pointers", &before, &after},
		{"inet6num pointers", &before6, &after6},
		{"a creation from a pointer", nil, &after},
		{"an object known only by its text", nil, rawOnly{after.Raw()}},
	} {
		d, err := MntIrtChange(ctx, reg, c.before, c.after, goodCred(), v)
		if err != nil {
			t.Fatal(err)
		}
		if d.OK {
			t.Errorf("%s: adding mnt-irt: IRT-VICTIM with the wrong credential was authorised: %v", c.name, d)
		}
	}
}

// RFC 2725 §4: the origin permission comes from the aut-num of the route's own
// origin, and the address-space permission from an object covering the route.
// Any aut-num and any inetnum the caller passed used to do.
func TestRouteCreationChecksOriginAndSpace(t *testing.T) {
	ctx, v := context.Background(), verifier()
	reg := newRegistry(t,
		mntner("MNT-OWN", "MD5-PW $1$abc$xyz"),
		mntner("MNT-EVIL", "MD5-PW $1$abc$xyz"),
	)
	route := decode(t, "route: 192.0.2.0/24\norigin: AS64500\nmnt-by: MNT-OWN\nsource: RIPE\n").(object.Route)
	evilAS := decode(t, "aut-num: AS64999\nas-name: EVIL\nmnt-by: MNT-EVIL\nsource: RIPE\n")
	evilSpace := decode(t, "inetnum: 198.51.100.0 - 198.51.100.255\nnetname: EVIL\nmnt-by: MNT-EVIL\nsource: RIPE\n")
	moreSpecific := decode(t, "route: 192.0.2.0/25\norigin: AS64999\nmnt-by: MNT-EVIL\nsource: RIPE\n")
	goodAS := decode(t, "aut-num: AS64500\nas-name: OK\nmnt-by: MNT-EVIL\nsource: RIPE\n")
	goodSpace := decode(t, "inetnum: 192.0.0.0 - 192.0.3.255\nnetname: OK\nmnt-by: MNT-EVIL\nsource: RIPE\n")

	for _, c := range []struct {
		name string
		req  RouteRequest
		want string
	}{
		{"another AS's aut-num", RouteRequestFor(route, evilAS, goodSpace), "origin AS"},
		{"space that does not cover the route", RouteRequestFor(route, goodAS, evilSpace), "address space"},
		{"a more specific route as the space", RouteRequestFor(route, goodAS, moreSpecific), "address space"},
		{"a request that names no origin", RouteRequest{Prefix: route.Prefix, MntBy: route.MntBy, Origin: goodAS, Space: goodSpace}, "origin AS"},
	} {
		d, err := RouteCreation(ctx, reg, c.req, goodCred(), v)
		if err != nil {
			t.Fatal(err)
		}
		if d.OK || !strings.Contains(strings.Join(d.Reasons, " "), c.want) {
			t.Errorf("%s: %v; want a refusal naming the %s", c.name, d, c.want)
		}
	}
	// The same request with the route's own aut-num and a covering inetnum passes.
	if d, err := RouteCreation(ctx, reg, RouteRequestFor(route, goodAS, goodSpace), goodCred(), v); err != nil || !d.OK {
		t.Errorf("the route's own aut-num and a covering inetnum: %v, %v", d, err)
	}
}

// mnt-lower: guards what is more specific than its object (RFC 2725 §4), not
// the object's own prefix, and an aut-num has no more specifics: its routing
// authority is mnt-routes:, then mnt-by:, as in the RIPE Database.
func TestRouteAuthorityMntLower(t *testing.T) {
	block := decode(t, "inetnum: 192.0.2.0 - 192.0.2.255\nmnt-lower: MNT-LOWER\nmnt-by: MNT-BY\nsource: RIPE\n")
	route := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmnt-lower: MNT-LOWER\nmnt-by: MNT-BY\nsource: RIPE\n")
	as := decode(t, "aut-num: AS64500\nas-name: X\nmnt-lower: MNT-LOWER\nmnt-by: MNT-BY\nsource: RIPE\n")
	for _, c := range []struct {
		name   string
		o      object.Object
		prefix string
		want   string
	}{
		{"an exact inetnum", block, "192.0.2.0/24", "MNT-BY"},
		{"a covering inetnum", block, "192.0.2.0/25", "MNT-LOWER"},
		{"an exact route", route, "192.0.2.0/24", "MNT-BY"},
		{"a less specific route", route, "192.0.2.128/25", "MNT-LOWER"},
		{"an aut-num", as, "192.0.2.0/24", "MNT-BY"},
	} {
		if got := strings.Join(RouteAuthority(c.o, mustPrefix(t, c.prefix)), " "); got != c.want {
			t.Errorf("%s for %s: RouteAuthority = %s, want %s", c.name, c.prefix, got, c.want)
		}
	}
}

// maxDepth bounds the maintainers walked: a chain of exactly maxDepth, root
// included, is whole.
func TestReferralChainDepth(t *testing.T) {
	ctx := context.Background()
	reg := newRegistry(t,
		mntner("MNT-LEAF", "NONE", "MNT-ROOT"),
		mntner("MNT-ROOT", "NONE", "MNT-ROOT"),
		mntner("MNT-SELF", "NONE", "MNT-SELF"),
	)
	if chain, err := ReferralChain(ctx, reg, "MNT-SELF", 1); err != nil || len(chain) != 1 {
		t.Errorf("a self-referential maintainer with maxDepth 1: %d maintainers, %v", len(chain), err)
	}
	if chain, err := ReferralChain(ctx, reg, "MNT-LEAF", 2); err != nil || len(chain) != 2 {
		t.Errorf("a chain of two with maxDepth 2: %d maintainers, %v", len(chain), err)
	}
	if _, err := ReferralChain(ctx, reg, "MNT-LEAF", 1); !errors.Is(err, ErrReferralTooDeep) {
		t.Errorf("a chain of two with maxDepth 1: %v, want ErrReferralTooDeep", err)
	}
}
