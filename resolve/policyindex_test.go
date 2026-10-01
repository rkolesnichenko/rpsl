package resolve_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

const indexObjects = `aut-num: AS1
as-name: ONE
import: from AS2 accept ANY
import: from AS1 accept ANY
export: to AS3 OR (AS4 EXCEPT AS5) announce AS1
mp-import: afi ipv6.unicast from AS-PEERS accept ANY
mp-export: to PRNG-X announce AS1
default: to AS6
import-via: AS7 from AS8 accept ANY
mnt-by: MNT-A
source: RIPE

aut-num: AS9
as-name: NINE
export: to AS2 announce AS9
mnt-by: MNT-A
source: RIPE

aut-num: AS10
as-name: TEN
mnt-by: MNT-A
source: RIPE
`

func asns(xs ...uint32) []types.ASN {
	out := []types.ASN{}
	for _, x := range xs {
		out = append(out, types.ASN(x))
	}
	return out
}

func checkNamedBy(t *testing.T, label string, pi resolve.PolicyIndex, want map[types.ASN][]types.ASN) {
	t.Helper()
	for as, w := range want {
		got, err := pi.NamedBy(as)
		if err != nil {
			t.Fatalf("%s: NamedBy(%v): %v", label, as, err)
		}
		if got == nil {
			got = []types.ASN{}
		}
		if !slices.Equal(got, w) {
			t.Errorf("%s: NamedBy(%v) = %v, want %v", label, as, got, w)
		}
	}
}

var indexWant = map[types.ASN][]types.ASN{
	1: asns(), 2: asns(1, 9), 3: asns(1), 4: asns(1), 5: asns(1), 6: asns(1), 7: asns(), 8: asns(), 10: asns(),
}

func autNumList(t *testing.T, pi resolve.PolicyIndex) []types.ASN {
	t.Helper()
	seq, err := pi.AutNums()
	if err != nil {
		t.Fatal(err)
	}
	return slices.Collect(seq)
}

func TestNamedByMemSource(t *testing.T) {
	src := resolve.NewMemSource(decodeAll(t, strings.Split(indexObjects, "\n\n")))
	checkNamedBy(t, "memsource", src, indexWant)
	if got := autNumList(t, src); !slices.Equal(got, asns(1, 9, 10)) {
		t.Errorf("AutNums %v", got)
	}
}

func load(t *testing.T, l *resolve.DumpLoader, text string) {
	t.Helper()
	if err := l.Read(strings.NewReader(text)); err != nil {
		t.Fatal(err)
	}
}

func TestNamedByCorpus(t *testing.T) {
	l := &resolve.DumpLoader{IndexPeers: true} // implies KeepPolicy
	load(t, l, indexObjects)
	src := l.Source()
	checkNamedBy(t, "corpus", src, indexWant)
	if got := autNumList(t, src); !slices.Equal(got, asns(1, 9, 10)) {
		t.Errorf("AutNums %v", got)
	}
	if _, err := src.AutNum(context.Background(), 10, ""); err != nil {
		t.Errorf("IndexPeers does not imply KeepPolicy: %v", err)
	}

	// A replacement drops what the old version named; a delete drops it all.
	load(t, l, "aut-num: AS1\nas-name: ONE\nexport: to AS3 announce AS1\nmnt-by: MNT-A\nsource: RIPE\n")
	checkNamedBy(t, "replaced", l.Source(), map[types.ASN][]types.ASN{2: asns(9), 3: asns(1), 6: asns()})
	l.Corpus().Delete("aut-num", "AS1", "RIPE")
	checkNamedBy(t, "deleted", l.Source(), map[types.ASN][]types.ASN{3: asns()})
	if got := autNumList(t, l.Source()); !slices.Equal(got, asns(9, 10)) {
		t.Errorf("AutNums after delete %v", got)
	}
}

// Ruling R8 (fix round 1): a Corpus kept aut-num's text must start at its
// own first attribute, not at the blank/comment trivia the stream attached
// before it (ast.Object owns that trivia for the *stream's* round-trip, but
// a Corpus entry is later re-decoded on its own, rpsl.ParseObject, whose line
// numbering must not be shifted by trivia that belongs to the object before
// it in the dump).
func TestKeptTextSpanStartsAtOne(t *testing.T) {
	l := &resolve.DumpLoader{KeepPolicy: true}
	load(t, l, "\n# a comment before the object\naut-num: AS1\nas-name: ONE\nmnt-by: MNT-A\nsource: RIPE\n")
	an, err := l.Source().AutNum(context.Background(), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	attrs := an.Raw().Attributes()
	if len(attrs) == 0 {
		t.Fatal("no attributes")
	}
	if got := attrs[0].Span.StartLine; got != 1 {
		t.Errorf("first attribute's StartLine = %d, want 1 (leading trivia leaked into the kept text)", got)
	}
	if attrs[0].Name != "aut-num" {
		t.Errorf("first attribute = %q, want aut-num", attrs[0].Name)
	}
}

func TestNamedByNeedsIndex(t *testing.T) {
	kept := &resolve.DumpLoader{KeepPolicy: true}
	load(t, kept, indexObjects)
	if _, err := kept.Source().NamedBy(2); !errors.Is(err, resolve.ErrNoIndex) {
		t.Errorf("KeepPolicy without IndexPeers: NamedBy err %v, want ErrNoIndex", err)
	}
	if got := autNumList(t, kept.Source()); !slices.Equal(got, asns(1, 9, 10)) {
		t.Errorf("KeepPolicy: AutNums %v", got)
	}
	bare := &resolve.DumpLoader{}
	load(t, bare, indexObjects)
	if _, err := bare.Source().AutNums(); !errors.Is(err, resolve.ErrNoPolicy) {
		t.Errorf("no KeepPolicy: AutNums err %v, want ErrNoPolicy", err)
	}
	if _, err := bare.Source().NamedBy(2); !errors.Is(err, resolve.ErrNoIndex) {
		t.Errorf("no IndexPeers: NamedBy err %v, want ErrNoIndex", err)
	}
}

// Merging a corpus that kept no index into one that does indexes its
// aut-nums from their text.
func TestNamedByMerge(t *testing.T) {
	plain := &resolve.DumpLoader{KeepPolicy: true}
	load(t, plain, indexObjects)
	idx := &resolve.DumpLoader{IndexPeers: true}
	c := idx.Corpus()
	c.IndexPeers = true // a Merge before the first Read: set the corpus's own flag
	c.Merge(plain.Corpus())
	checkNamedBy(t, "merged", idx.Source(), indexWant)
}

// Only the copy precedence picks names anything.
func TestNamedByPrecedence(t *testing.T) {
	l := &resolve.DumpLoader{IndexPeers: true}
	load(t, l, "aut-num: AS1\nas-name: R\nimport: from AS2 accept ANY\nmnt-by: MNT-A\nsource: RIPE\n\n"+
		"aut-num: AS1\nas-name: X\nimport: from AS3 accept ANY\nmnt-by: MNT-A\nsource: RADB\n")
	checkNamedBy(t, "RIPE first", l.Corpus().Source("RIPE", "RADB"), map[types.ASN][]types.ASN{2: asns(1), 3: asns()})
	checkNamedBy(t, "RADB only", l.SourceOf("RADB"), map[types.ASN][]types.ASN{2: asns(), 3: asns(1)})
}

// plain hides every method but PolicySource's.
type plain struct{ resolve.PolicySource }

func TestNamedByPassThrough(t *testing.T) {
	src := resolve.NewMemSource(decodeAll(t, strings.Split(indexObjects, "\n\n")))
	checkNamedBy(t, "cache", resolve.NewCache(src, 0), indexWant)
	checkNamedBy(t, "rpki", &rpki.Filter{Src: src}, indexWant)
	for _, pi := range []resolve.PolicyIndex{resolve.NewCache(plain{src}, 0), &rpki.Filter{Src: plain{src}}} {
		if _, err := pi.NamedBy(2); !errors.Is(err, resolve.ErrNoIndex) {
			t.Errorf("%T over a plain source: NamedBy err %v, want ErrNoIndex", pi, err)
		}
		if _, err := pi.AutNums(); !errors.Is(err, resolve.ErrNoIndex) {
			t.Errorf("%T over a plain source: AutNums err %v, want ErrNoIndex", pi, err)
		}
	}
}

func TestConjunctSpace(t *testing.T) {
	src := resolve.NewMemSource(nil)
	norm := func(s string, afi types.AFI) resolve.NormalFilter {
		t.Helper()
		f, ds := policy.ParseFilter(s)
		if len(ds) > 0 {
			t.Fatalf("%s: %v", s, ds)
		}
		nf, err := (&resolve.Expander{Src: src, AFI: afi}).NormalizeFilter(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		return nf
	}
	nf := norm("{10.0.0.0/8^+} AND NOT {10.1.0.0/16^+}", types.AFIv4)
	if len(nf.Conjuncts) != 1 {
		t.Fatalf("%v: %d conjuncts", nf, len(nf.Conjuncts))
	}
	sp := nf.Conjuncts[0].Space()
	for p, want := range map[string]bool{"10.2.0.0/16": true, "10.0.0.0/8": true, "10.1.0.0/24": false, "10.1.0.0/16": false, "11.0.0.0/8": false} {
		if got := sp.Contains(mustPrefix(t, p)); got != want {
			t.Errorf("Space of %v Contains(%s) = %v, want %v", nf, p, got, want)
		}
	}
	for _, c := range []struct {
		afi  types.AFI
		want types.PrefixSpace
	}{{types.AFIv4, types.FullSpace(types.AFIv4)}, {types.AFIv6, types.FullSpace(types.AFIv6)}, {types.AFIAny, types.FullSpace(types.AFIAny)}} {
		any := norm("ANY", c.afi)
		if got := any.Conjuncts[0].Space(); !got.Equal(c.want) {
			t.Errorf("ANY under %v: Space %v, want %v", c.afi, got, c.want)
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
