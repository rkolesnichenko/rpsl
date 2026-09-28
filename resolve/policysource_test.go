package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
)

var policyTexts = []string{
	"aut-num: AS1\nas-name: ONE-RIPE\nimport: from AS2 accept ANY\nsource: RIPE\n",
	"aut-num: AS1\nas-name: ONE-PROXY\nsource: RADB\n",
	"aut-num: AS3\nas-name: CLAIMS\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n",
	"inet-rtr: rtr1.example.net\nlocal-as: AS1\nifaddr: 192.0.2.1 masklen 30\nsource: RIPE\n",
}

func checkPolicy(t *testing.T, label string, src resolve.PolicySource) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range []struct {
		source, want string
	}{{"", "ONE-RIPE"}, {"RIPE", "ONE-RIPE"}, {"radb", "ONE-PROXY"}} {
		an, err := src.AutNum(ctx, 1, tc.source)
		if err != nil || an.AsName != tc.want {
			t.Errorf("%s: AutNum(AS1, %q) = %q, %v; want %q", label, tc.source, an.AsName, err, tc.want)
		}
	}
	if an, _ := src.AutNum(ctx, 1, ""); len(an.Imports) != 1 {
		t.Errorf("%s: AS1's import was not decoded: %+v", label, an.Imports)
	}
	if an, err := src.AutNum(ctx, 3, ""); err != nil || an.AsName != "CLAIMS" {
		t.Errorf("%s: a claimant aut-num = %q, %v", label, an.AsName, err)
	}
	for _, missing := range []func() error{
		func() error { _, err := src.AutNum(ctx, 1, "NOSUCH"); return err },
		func() error { _, err := src.AutNum(ctx, 9, ""); return err },
		func() error { _, err := src.InetRtr(ctx, "rtr9.example.net", ""); return err },
	} {
		if err := missing(); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", label, err)
		}
	}
	if ir, err := src.InetRtr(ctx, "RTR1.example.NET", ""); err != nil || ir.LocalAS != 1 {
		t.Errorf("%s: InetRtr = %+v, %v", label, ir, err)
	}
}

func TestPolicySource(t *testing.T) {
	objs := decodeAll(t, policyTexts)
	checkPolicy(t, "NewMemSource", resolve.NewMemSource(objs, "RIPE", "RADB"))
	c := resolve.Corpus{KeepPolicy: true}
	for _, o := range objs {
		c.Put(o)
	}
	checkPolicy(t, "Corpus", c.Source("RIPE", "RADB"))
	checkPolicy(t, "Cache", resolve.NewCache(c.Source("RIPE", "RADB"), 0))
	checkPolicy(t, "rpki.Filter", &rpki.Filter{Src: c.Source("RIPE", "RADB")})

	var plain resolve.Corpus // without KeepPolicy: only the claimant aut-num is held
	for _, o := range objs {
		plain.Put(o)
	}
	if _, err := plain.Source().AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a Corpus without KeepPolicy served AS1: %v", err)
	}
}

func TestPolicyWrappersOverPlainSource(t *testing.T) {
	src := newRefSource(t, nil, nil) // a Source that is not a PolicySource
	for name, ps := range map[string]resolve.PolicySource{
		"Cache":  resolve.NewCache(src, 0),
		"Filter": &rpki.Filter{Src: src},
	} {
		if _, err := ps.AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNoPolicy) {
			t.Errorf("%s: err = %v, want ErrNoPolicy", name, err)
		}
	}
}
