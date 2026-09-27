package rpki

import (
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
)

// TestLiveRPKIAgreesWithRADB (opt-in: RPSL_LIVE=1 and RPSL_REALDATA with the
// BELL dump and the VRPs) holds Validate to RADB's RPKI-aware IRRd: of a sample
// of BELL's routes — its dump is not filtered, and most are invalid — RADB must
// hide those Validate finds invalid and serve those it finds valid. A few may
// differ where a ROA or a route changed after the files were fetched.
func TestLiveRPKIAgreesWithRADB(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if os.Getenv("RPSL_LIVE") == "" || dir == "" {
		t.Skip("set RPSL_LIVE=1 and RPSL_REALDATA to run against whois.radb.net")
	}
	f, err := os.Open(filepath.Join(dir, "rpki", "vrps.json"))
	if err != nil {
		t.Skip(err)
	}
	v, err := ReadJSON(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	g, err := os.Open(filepath.Join(dir, "bell", "bell.db.gz"))
	if err != nil {
		t.Skip(err)
	}
	defer g.Close()
	zr, err := gzip.NewReader(g)
	if err != nil {
		t.Fatal(err)
	}
	byState := map[State][]object.Route{}
	for o := range rpsl.Parse(zr) {
		obj, _ := object.Decode(o)
		if r, ok := obj.(object.Route); ok && r.Prefix.IsValid() {
			st := v.Validate(r.Prefix, r.Origin)
			byState[st] = append(byState[st], r)
		}
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	checked, wrong := 0, 0
	for st, n := range map[State]int{Invalid: 20, Valid: 10} {
		pool := byState[st]
		for i := 0; i < n && len(pool) > 0; i++ {
			rt := pool[r.Intn(len(pool))]
			served := radbServes(t, rt)
			checked++
			if served == (st == Invalid) {
				wrong++
				t.Logf("%s %s is %v here, and RADB serves it: %v", rt.Prefix, rt.Origin, st, served)
			}
		}
	}
	if checked < 20 || wrong > checked/10 {
		t.Errorf("RADB disagrees on %d of %d routes", wrong, checked)
	}
}

// radbServes reports whether whois.radb.net serves BELL's route object.
func radbServes(t *testing.T, rt object.Route) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", "whois.radb.net:43", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "-s BELL -x %s\n", rt.Prefix)
	answer, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(answer), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && name == "origin" && strings.EqualFold(strings.TrimSpace(value), rt.Origin.String()) {
			return true
		}
	}
	return false
}

// TestLivePseudoObjectIsCurrent (opt-in: RPSL_LIVE=1) holds WriteRPSL to how
// whois.radb.net renders a pseudo object today: the VRP is read back from the
// object's own max-length: and trust anchor, so only a change in IRRd's
// rendering fails it.
func TestLivePseudoObjectIsCurrent(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to run against whois.radb.net")
	}
	c, err := net.DialTimeout("tcp", "whois.radb.net:43", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprint(c, "-s RPKI -x 1.1.1.0/24\n")
	answer, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	live := strings.TrimRight(string(answer), "\n") + "\n"
	o, _ := rpsl.ParseObject(live)
	ml, _ := o.GetFirst("max-length")
	src, _ := o.GetFirst("source")
	_, ta, _ := strings.Cut(src.Raw, "# Trust Anchor: ")
	var maxLen uint8
	if _, err := fmt.Sscan(ml.Value, &maxLen); err != nil {
		t.Fatalf("no max-length in RADB's answer:\n%s", live)
	}
	v, err := NewVRPs([]VRP{{Prefix: netip.MustParsePrefix("1.1.1.0/24"), MaxLength: maxLen, ASN: 13335, TA: strings.TrimSpace(ta)}})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != live {
		t.Errorf("RADB renders:\n%s\nWriteRPSL:\n%s", live, b.String())
	}
}
