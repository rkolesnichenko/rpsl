package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
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

	// Without KeepPolicy a corpus holds only the aut-nums and inet-rtrs that
	// claim membership of a set, so its MemSource serves no policy objects at
	// all — even the claimant AS3 it holds — rather than a partial answer.
	var plain resolve.Corpus
	for _, o := range objs {
		plain.Put(o)
	}
	for label, src := range map[string]*resolve.MemSource{"Source": plain.Source(), "SourceOf": plain.SourceOf("RIPE")} {
		for _, as := range []types.ASN{1, 3} {
			if an, err := src.AutNum(context.Background(), as, ""); !errors.Is(err, resolve.ErrNoPolicy) {
				t.Errorf("plain Corpus %s: AutNum(%s) = %q, %v; want ErrNoPolicy", label, as, an.AsName, err)
			}
		}
		if _, err := src.InetRtr(context.Background(), "rtr1.example.net", ""); !errors.Is(err, resolve.ErrNoPolicy) {
			t.Errorf("plain Corpus %s: InetRtr = %v; want ErrNoPolicy", label, err)
		}
	}
}

// Review fix round 1, finding 1: a tie between copies of equal rank goes to
// whichever was loaded first, never to a whole (claimant) copy over a
// text-kept one just because it happens to be whole. Corpus and NewMemSource
// over the same objects, in the same load order, must agree.
func TestPolicyTieGoesToLoadOrder(t *testing.T) {
	texts := []string{
		"aut-num: AS1\nas-name: TEXT-RADB\nsource: RADB\n",                              // loaded first, non-claiming: text-kept
		"aut-num: AS1\nas-name: CLAIM-RIPE\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n", // loaded second, claiming: whole
		"inet-rtr: r.example.net\nlocal-as: AS2\nsource: RADB\n",                        // loaded third, non-claiming: text-kept
		"inet-rtr: r.example.net\nlocal-as: AS3\nmember-of: AS-X\nsource: RIPE\n",       // loaded fourth, claiming: whole
	}
	objs := decodeAll(t, texts)
	c := resolve.Corpus{KeepPolicy: true}
	for _, o := range objs {
		c.Put(o)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		label      string
		precedence []string
	}{
		{"no precedence", nil},
		{"unlisted precedence", []string{"ALTDB"}}, // RADB and RIPE both unranked: still a tie
	} {
		for label, src := range map[string]resolve.PolicySource{
			"Corpus":       c.Source(tc.precedence...),
			"NewMemSource": resolve.NewMemSource(objs, tc.precedence...),
		} {
			if an, err := src.AutNum(ctx, 1, ""); err != nil || an.AsName != "TEXT-RADB" {
				t.Errorf("%s (%s): AutNum(AS1, \"\") = %q, %v; want TEXT-RADB (loaded first)", label, tc.label, an.AsName, err)
			}
			if ir, err := src.InetRtr(ctx, "r.example.net", ""); err != nil || ir.LocalAS != 2 {
				t.Errorf("%s (%s): InetRtr(r.example.net, \"\") = %+v, %v; want LocalAS 2 (loaded first)", label, tc.label, ir, err)
			}
		}
	}
}

// Review fix round 1, finding 2: an aut-num whose AS did not decode, or an
// inet-rtr with an empty name, is no AS's and no router's (claimant agrees) —
// NewMemSource must not index it under the AS0 or the empty name its zero
// value defaults to. Corpus already refuses to keep such an object at all
// (Put's own gate), so it is checked here only for parity.
func TestPolicyUndecodedKeyNotServed(t *testing.T) {
	objs := decodeAll(t, []string{
		"aut-num: ASX\nas-name: BAD\nsource: RIPE\n", // AS does not decode: AS field defaults to 0
	})
	src := resolve.NewMemSource(objs)
	ctx := context.Background()
	if _, err := src.AutNum(ctx, 0, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("NewMemSource served an undecoded aut-num's key as AS0: err = %v", err)
	}
	c := resolve.Corpus{KeepPolicy: true}
	for _, o := range objs {
		c.Put(o)
	}
	if _, err := c.Source().AutNum(ctx, 0, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Corpus served an undecoded aut-num's key as AS0: err = %v", err)
	}

	rtrs := decodeAll(t, []string{
		"inet-rtr:\nlocal-as: AS1\nsource: RIPE\n", // name does not decode: Name defaults to ""
	})
	rsrc := resolve.NewMemSource(rtrs)
	if _, err := rsrc.InetRtr(ctx, "", ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("NewMemSource served an undecoded inet-rtr's key as an empty name: err = %v", err)
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

// TestCachePolicyKeyIsCanonical: the Cache keys a policy lookup by the source
// in the canonical form the lookup itself uses, so a name that is not a source
// name — which strings.ToUpper would fold into a valid one ("ripeſ" into
// "RIPES") — never shares, or poisons, the entry of a real registry.
func TestCachePolicyKeyIsCanonical(t *testing.T) {
	objs := decodeAll(t, []string{
		"aut-num: AS1\nas-name: ONE\nsource: RIPES\n",
		"inet-rtr: r.example.net\nlocal-as: AS1\nsource: RIPES\n",
	})
	ctx := context.Background()
	c := resolve.NewCache(resolve.NewMemSource(objs), 0)
	if an, err := c.AutNum(ctx, 1, "ripes"); err != nil || an.AsName != "ONE" {
		t.Fatalf(`AutNum(AS1, "ripes") = %q, %v; want ONE`, an.AsName, err)
	}
	if an, err := c.AutNum(ctx, 1, "ripeſ"); err == nil {
		t.Errorf(`AutNum(AS1, "ripeſ") = %q from the cache; want an invalid source name`, an.AsName)
	}
	if ir, err := c.InetRtr(ctx, "r.example.net", "RIPES"); err != nil || ir.LocalAS != 1 {
		t.Fatalf(`InetRtr(r, "RIPES") = %+v, %v; want LocalAS 1`, ir, err)
	}
	if ir, err := c.InetRtr(ctx, "r.example.net", "ripeſ"); err == nil {
		t.Errorf(`InetRtr(r, "ripeſ") = %+v from the cache; want an invalid source name`, ir)
	}
}

// TestPolicyLookupMissIsNil: a lookup that finds nothing returns a nil
// pointer beside its error, never a zero object.
func TestPolicyLookupMissIsNil(t *testing.T) {
	src := (&resolve.Corpus{KeepPolicy: true}).Source()
	an, err := src.AutNum(context.Background(), 64500, "")
	if err == nil || an != nil {
		t.Errorf("AutNum miss = %v, %v; want nil and an error", an, err)
	}
	ir, err := src.InetRtr(context.Background(), "rtr.example.net", "")
	if err == nil || ir != nil {
		t.Errorf("InetRtr miss = %v, %v; want nil and an error", ir, err)
	}
}
