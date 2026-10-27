package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
)

// An inetnum whose key is a prefix ("192.0.2.0/24", as LACNIC writes them)
// decodes to the prefix's range, with a Warning, and is authorised as the
// inetnum of that range: its parent's consent for a creation, the stored
// object's maintainers for a deletion, whichever way the key is spelled.
func TestRIPEInetnumPrefixKey(t *testing.T) {
	withWarnings := func(src string) object.Object {
		t.Helper()
		raw, _ := rpsl.ParseObject(src)
		obj, ds := rpsl.Decode(raw)
		if len(ds) == 0 || obj.(*object.Inetnum).Lo.String() != "192.0.2.0" {
			t.Fatalf("%q: want a prefix-key Warning and Lo 192.0.2.0, got %v %v", src, ds, obj.(*object.Inetnum).Lo)
		}
		return obj
	}
	created := "inetnum: 192.0.2.0/24\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n"
	hostBits := "inetnum: 192.0.2.77/24\nnetname: NEW\nmnt-by: MNT-OWN\nsource: RIPE\n"
	for _, c := range []struct {
		name   string
		stored string
		action Action
		obj    string
		accept []string
		ok     bool
		reason string
	}{
		{"create: the parent's mnt-lower", bigInetnum, Create, created, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"create: without the parent", bigInetnum, Create, created, []string{"MNT-OWN"}, false, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"create, host bits: the parent's mnt-lower", bigInetnum, Create, hostBits, []string{"MNT-OWN", "MNT-LOWER"}, true, "parent inetnum 192.0.0.0 - 192.0.255.255"},
		{"delete: the stored lo - hi object", newInetnum, Delete, hostBits, []string{"MNT-OWN"}, true, "stored object's maintainers"},
		{"delete: refused", newInetnum, Delete, hostBits, []string{"MNT-OTHER"}, false, "stored object's maintainers"},
	} {
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
		d, err := RIPE.Authorise(context.Background(), memDB(t, srcs...), Update{Action: c.action, Object: withWarnings(c.obj)}, goodCred(), verifier())
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if d.OK != c.ok || !strings.Contains(d.String(), c.reason) {
			t.Errorf("%s: %s\n  want ok=%v with %q", c.name, d, c.ok, c.reason)
		}
	}
}
