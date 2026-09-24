package auth

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// memDB builds a MemDatabase from RPSL texts.
func memDB(t *testing.T, srcs ...string) *MemDatabase {
	t.Helper()
	objs := make([]object.Object, len(srcs))
	for i, s := range srcs {
		objs[i] = decode(t, s)
	}
	return NewMemDatabase(objs)
}

func keys(t *testing.T, objs []object.Object) string {
	t.Helper()
	var out []string
	for _, o := range objs {
		_, k, _ := primaryKey(o)
		out = append(out, k)
	}
	return strings.Join(out, " | ")
}

func TestMemDatabaseCovering(t *testing.T) {
	db := memDB(t,
		"inetnum: 192.0.0.0 - 192.0.255.255\nnetname: BIG\nsource: TEST\n",
		"inetnum: 192.0.2.0 - 192.0.2.99\nnetname: ODD\nsource: TEST\n", // not a CIDR block
		"inetnum: 192.0.2.0 - 192.0.2.255\nnetname: MID\nsource: TEST\n",
		"inet6num: 2001:db8::/32\nnetname: V6\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n",
	)
	ctx := context.Background()
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	got, _ := db.Covering(ctx, "inetnum", a("192.0.2.10"), a("192.0.2.20"))
	if want := "192.0.2.0 - 192.0.2.99 | 192.0.2.0 - 192.0.2.255 | 192.0.0.0 - 192.0.255.255"; keys(t, got) != want {
		t.Errorf("Covering = %s, want %s", keys(t, got), want)
	}
	got, _ = db.Covering(ctx, "inetnum", a("192.0.2.0"), a("192.0.2.255"))
	if want := "192.0.2.0 - 192.0.2.255 | 192.0.0.0 - 192.0.255.255"; keys(t, got) != want {
		t.Errorf("Covering an exact match = %s, want %s", keys(t, got), want)
	}
	if got, _ := db.Covering(ctx, "INETNUM", a("2001:db8::"), a("2001:db8::1")); len(got) != 0 {
		t.Errorf("an IPv6 range in inetnum: %s", keys(t, got))
	}
	if got, _ := db.Covering(ctx, "route", a("192.0.2.0"), a("192.0.2.127")); len(got) != 2 {
		t.Errorf("both routes of 192.0.2.0/24 cover a /25: %s", keys(t, got))
	}
}

func TestMemDatabaseLookups(t *testing.T) {
	db := memDB(t,
		mntner("MNT-A", "MD5-PW $1$abc$xyz"),
		"route: 192.0.2.0/24\norigin: AS1\nmnt-by: MNT-A\nsource: TEST\n",
		"aut-num: as1\nas-name: X\nsource: TEST\n",
		"as-set: as1:as-foo\nsource: TEST\n",
		"person: Some One\nnic-hdl: so1-test\nsource: TEST\n",
		"as-block: AS1 - AS100\nsource: TEST\n",
		"as-block: AS1 - AS65535\nsource: TEST\n",
	)
	ctx := context.Background()
	if _, err := db.Mntner(ctx, "mnt-a"); err != nil {
		t.Errorf("Mntner(mnt-a): %v", err)
	}
	if _, err := db.Mntner(ctx, "MNT-GONE"); !errors.Is(err, ErrNoMntner) {
		t.Errorf("Mntner(MNT-GONE): %v, want ErrNoMntner", err)
	}
	// A route is known by its prefix and origin together.
	if _, err := db.Current(ctx, decode(t, "route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n")); err != nil {
		t.Errorf("Current(route AS1): %v", err)
	}
	if _, err := db.Current(ctx, decode(t, "route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n")); !errors.Is(err, ErrNotFound) {
		t.Errorf("Current(route AS2): %v, want ErrNotFound", err)
	}
	for _, c := range []struct{ class, key string }{
		{"aut-num", "AS1"}, {"aut-num", "as1"}, {"as-set", "AS1:AS-FOO"}, {"person", "SO1-TEST"},
	} {
		if _, err := db.Object(ctx, c.class, c.key); err != nil {
			t.Errorf("Object(%s, %s): %v", c.class, c.key, err)
		}
	}
	if _, err := db.Object(ctx, "person", "Some One"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a person found by name, not nic-hdl: %v", err)
	}
	blocks, _ := db.ASBlocks(ctx, 50)
	if len(blocks) != 2 || blocks[0].Hi != 100 {
		t.Errorf("ASBlocks(AS50) = %v, want the narrower first", blocks)
	}
	if blocks, _ := db.ASBlocks(ctx, 70000); len(blocks) != 0 {
		t.Errorf("ASBlocks(AS70000) = %v", blocks)
	}
}
