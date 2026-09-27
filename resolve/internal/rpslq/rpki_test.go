package rpslq

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// rpkiROAs: AS2 holds 203.0.113.0/24, so AS3's 203.0.113.128/25 is invalid;
// AS1 has a ROA with no route object, a pseudo route in the registry RPKI;
// and a ROA covers RS-TOP's literal 192.0.2.0/24, which stays.
const rpkiROAs = `{"roas": [
  {"asn": "AS2", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "test"},
  {"asn": "AS1", "prefix": "198.18.0.0/15", "maxLength": 15, "ta": "test"},
  {"asn": "AS64511", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "test"}
]}`

// --rpki makes every backend RPKI-aware as IRRd 4 is: invalid routes are left
// out, and a dump gains the pseudo routes as the registry RPKI.
func TestRpslqRPKI(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dump := write("irr.db", []byte(strings.Join(corpus, "\n")))
	vrps := write("vrps.json", []byte(rpkiROAs))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(rpkiROAs))
	zw.Close()
	zipped := write("vrps.json.gz", gz.Bytes())
	slurm := write("slurm.json", []byte(`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"asn": 2}]}}`))
	db := irrtest.New(corpus...).WithSources("TEST")

	const clean = "198.51.100.0/24\n203.0.113.0/24\n"
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"without --rpki", []string{"--dump", dump, "-P", "AS-TOP"}, clean + "203.0.113.128/25\n"},
		{"a dump, every registry", []string{"--dump", dump, "--rpki", vrps, "-P", "AS-TOP"}, "198.18.0.0/15\n" + clean},
		{"gzipped VRPs", []string{"--dump", dump, "--rpki", zipped, "-P", "AS-TOP"}, "198.18.0.0/15\n" + clean},
		{"-S without RPKI", []string{"--dump", dump, "-S", "TEST", "--rpki", vrps, "-P", "AS-TOP"}, clean},
		{"-S with RPKI", []string{"--dump", dump, "-S", "TEST,RPKI", "--rpki", vrps, "-P", "AS-TOP"}, "198.18.0.0/15\n" + clean},
		{"RPKI::AS1", []string{"--dump", dump, "-S", "TEST", "--rpki", vrps, "-P", "RPKI::AS1"}, "198.18.0.0/15\n"},
		{"a route-set's own prefixes stay", []string{"--dump", dump, "--rpki", vrps, "--ranges", "-P", "RS-TOP"},
			"10.0.0.0/30^+\n192.0.2.0/24\n"},
		{"--slurm drops AS2's ROA", []string{"--dump", dump, "-S", "TEST", "--rpki", vrps, "--slurm", slurm, "-P", "AS-TOP"},
			clean + "203.0.113.128/25\n"},
		{"irrd", []string{"-h", db.IRRd(t), "-S", "TEST", "--rpki", vrps, "-P", "AS-TOP"}, clean},
		{"whois", []string{"--whois", "-h", db.Whois(t), "-S", "TEST", "--rpki", vrps, "-P", "AS-TOP"}, clean},
		{"an AS's routes", []string{"-h", db.IRRd(t), "-S", "TEST", "--rpki", vrps, "-P", "AS3"}, ""},
	} {
		code, out, errs := rpslq(t, c.args...)
		if code != 0 || out != c.want {
			t.Errorf("%s: exit %d, stderr %q\n got %q\nwant %q", c.name, code, errs, out, c.want)
		}
	}

	// An RPKI-aware server leaves out the same routes itself.
	aware := irrtest.New(corpus...).WithSources("TEST").WithRPKI(irrtest.ROA{
		Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASN: types.ASN(2), MaxLength: 24, TA: "test"})
	if code, out, errs := rpslq(t, "-h", aware.IRRd(t), "-S", "TEST", "-P", "AS-TOP"); code != 0 || out != clean {
		t.Errorf("an RPKI-aware server: exit %d, stderr %q, got %q", code, errs, out)
	}

	code, _, errs := rpslq(t, "-d", "--dump", dump, "-S", "TEST", "--rpki", vrps, "-P", "AS-TOP", "TEST::AS3")
	for _, want := range []string{
		"rpslq: debug: rpki: AS3 203.0.113.128/25 is invalid, left out\n",
		"rpslq: debug: rpki: AS3 203.0.113.128/25 is invalid, left out [TEST]\n",
	} {
		if code != 0 || !strings.Contains(errs, want) {
			t.Errorf("-d: exit %d, trace lacks %q:\n%s", code, want, errs)
		}
	}

	for _, c := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"--slurm alone", []string{"--dump", dump, "--slurm", slurm, "AS-TOP"}, 2, "needs --rpki"},
		{"--server-expand", []string{"--rpki", vrps, "--server-expand", "AS-TOP"}, 2, "without their origins"},
		{"no VRP file", []string{"--dump", dump, "--rpki", filepath.Join(dir, "none.json"), "AS-TOP"}, 1, "no such file"},
		{"not VRPs", []string{"--dump", dump, "--rpki", dump, "AS-TOP"}, 1, "invalid JSON"},
		{"not SLURM", []string{"--dump", dump, "--rpki", vrps, "--slurm", vrps, "AS-TOP"}, 1, "slurmVersion"},
	} {
		code, _, errs := rpslq(t, c.args...)
		if code != c.code || !strings.Contains(errs, c.msg) {
			t.Errorf("%s: exit %d, stderr %q; want %d with %q", c.name, code, errs, c.code, c.msg)
		}
	}
}
