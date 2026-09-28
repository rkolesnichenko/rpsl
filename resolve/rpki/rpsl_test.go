package rpki

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestWriteRPSLMatchesIRRd holds WriteRPSL to IRRd's own rendering: the
// expected text of test_valid_process (irrd/rpki/tests/test_importer.py).
func TestWriteRPSLMatchesIRRd(t *testing.T) {
	const want = `route:          192.0.2.0/24
descr:          RPKI ROA for 192.0.2.0/24 / AS64496
remarks:        This AS64496 route object represents routing data retrieved
                from the RPKI. This route object is the result of an automated
                RPKI-to-IRR conversion process performed by IRRd.
max-length:     26
origin:         AS64496
source:         RPKI  # Trust Anchor: APNIC RPKI Root
`
	v := mustVRPs(t, VRP{netip.MustParsePrefix("192.0.2.0/24"), 26, 64496, "APNIC RPKI Root"})
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != want {
		t.Errorf("WriteRPSL:\n%s\nwant:\n%s", b.String(), want)
	}
}

// TestWriteRPSLMatchesRADB holds it to what whois.radb.net served for two ROAs
// (testdata/radb-pseudo.txt, "-s RPKI -x <prefix>", captured 2026-09-27).
func TestWriteRPSLMatchesRADB(t *testing.T) {
	want, err := os.ReadFile("testdata/radb-pseudo.txt")
	if err != nil {
		t.Fatal(err)
	}
	v := mustVRPs(t,
		VRP{netip.MustParsePrefix("1.1.1.0/24"), 24, 13335, "apnic"},
		VRP{netip.MustParsePrefix("2001:470:2a2::/48"), 48, 13335, "arin"},
	)
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("WriteRPSL:\n%s\nwant:\n%s", b.String(), want)
	}
}

// TestWriteRPSLLoads reads the pseudo objects back as a dump: one route per
// (prefix, ASN, maxLength), under the registry RPKI.
func TestWriteRPSLLoads(t *testing.T) {
	v := mustVRPs(t,
		VRP{netip.MustParsePrefix("192.0.2.0/24"), 24, 64496, "a"},
		VRP{netip.MustParsePrefix("192.0.2.0/24"), 24, 64496, "b"}, // same key: no second object
		VRP{netip.MustParsePrefix("192.0.2.0/24"), 25, 64496, "a"}, // another maxLength: its own object, same route
		VRP{netip.MustParsePrefix("2001:db8::/32"), 48, 64496, "a"},
		VRP{netip.MustParsePrefix("198.51.100.0/24"), 24, 0, "a"},
	)
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "\norigin:"); n != 4 {
		t.Errorf("wrote %d objects, want 4:\n%s", n, b.String())
	}
	l := &resolve.DumpLoader{}
	if err := l.Read(strings.NewReader(b.String())); err != nil {
		t.Fatal(err)
	}
	if l.Stats.Diagnosed != 0 || l.Stats.Kept != 4 {
		t.Fatalf("load: %+v", l.Stats)
	}
	ctx := context.Background()
	got, err := l.SourceOf("RPKI").OriginatedRoutes(ctx, 64496, types.AFIAny)
	if err != nil {
		t.Fatal(err)
	}
	// The two pseudo objects of 192.0.2.0/24 (maxLength 24 and 25) are one
	// route to the engine, as "!g" lists a prefix once.
	want := []string{"192.0.2.0/24", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("AS64496 routes %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("route %d = %s, want %s", i, got[i], want[i])
		}
	}
	if as0, _ := l.Source().OriginatedRoutes(ctx, 0, types.AFIAny); len(as0) != 1 {
		t.Errorf("AS0 routes %v, want the AS0 ROA's", as0)
	}
}

// AddTo's pseudo routes answer as WriteRPSL's text read by a DumpLoader
// does, for every AS, under every source selection.
func TestAddToMatchesWriteRPSL(t *testing.T) {
	v := mustVRPs(t,
		VRP{netip.MustParsePrefix("192.0.2.0/24"), 24, 64496, "a"},
		VRP{netip.MustParsePrefix("192.0.2.0/24"), 25, 64496, "a"},
		VRP{netip.MustParsePrefix("2001:db8::/32"), 48, 64496, "a"},
		VRP{netip.MustParsePrefix("198.51.100.0/24"), 24, 0, "a"},
		VRP{netip.MustParsePrefix("203.0.113.0/24"), 24, 64497, "b"},
	)
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	text := &resolve.DumpLoader{}
	if err := text.Read(strings.NewReader(b.String())); err != nil {
		t.Fatal(err)
	}
	typed := &resolve.Corpus{}
	v.AddTo(typed)
	ctx := context.Background()
	for _, srcs := range [][]string{nil, {"RPKI"}, {"rpki"}, {"RIPE"}} {
		a, b := text.Corpus().SourceOf(srcs...), typed.SourceOf(srcs...)
		if srcs == nil {
			a, b = text.Source(), typed.Source()
		}
		for _, as := range []types.ASN{0, 64496, 64497, 64999} {
			ra, _ := a.OriginatedRoutes(ctx, as, types.AFIAny)
			rb, _ := b.OriginatedRoutes(ctx, as, types.AFIAny)
			if fmt.Sprint(ra) != fmt.Sprint(rb) {
				t.Errorf("sources %v, AS%d: text %v, typed %v", srcs, as, ra, rb)
			}
		}
	}
	if text.Corpus().Len() != typed.Len() {
		t.Errorf("text holds %d, typed %d", text.Corpus().Len(), typed.Len())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteRPSLError(t *testing.T) {
	v := mustVRPs(t, vrp("10.0.0.0/8", 1, 8))
	if err := v.WriteRPSL(failWriter{}); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("WriteRPSL to a failing writer: %v", err)
	}
	var b strings.Builder
	if err := (*VRPs)(nil).WriteRPSL(&b); err != nil || b.Len() != 0 {
		t.Errorf("nil VRPs wrote %q, %v", b.String(), err)
	}
}

// TestIrrtestPseudoMatchesRADB holds irrtest's own rendering of IRRd's pseudo
// objects, which the model tests serve, to the same capture.
func TestIrrtestPseudoMatchesRADB(t *testing.T) {
	want, err := os.ReadFile("testdata/radb-pseudo.txt")
	if err != nil {
		t.Fatal(err)
	}
	db := irrtest.New().WithRPKI(
		irrtest.ROA{Prefix: netip.MustParsePrefix("1.1.1.0/24"), ASN: 13335, MaxLength: 24, TA: "apnic"},
		irrtest.ROA{Prefix: netip.MustParsePrefix("2001:470:2a2::/48"), ASN: 13335, MaxLength: 48, TA: "arin"},
	)
	addr := db.Whois(t)
	var got []string
	for _, key := range []string{"1.1.1.0/24", "2001:470:2a2::/48"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "-s RPKI %s\n", key)
		answer, _ := io.ReadAll(c)
		c.Close()
		got = append(got, strings.TrimPrefix(string(answer), "% irrtest\n\n"))
	}
	if strings.Join(got, "\n") != string(want) {
		t.Errorf("irrtest served:\n%s\nwant:\n%s", strings.Join(got, "\n"), want)
	}
}
