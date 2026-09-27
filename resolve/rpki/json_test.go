package rpki

import (
	"net/netip"
	"strings"
	"testing"
)

// importerROAs and importerSLURM are the input of IRRd's test_valid_process
// (irrd/rpki/tests/test_importer.py, v4.5.3).
const importerROAs = `{"roas": [
  {"asn": "64496", "prefix": "192.0.2.0/24", "maxLength": 26, "ta": "APNIC RPKI Root"},
  {"asn": "AS64497", "prefix": "2001:db8::/32", "maxLength": 40, "ta": "RIPE NCC RPKI Root"},
  {"asn": "64498", "prefix": "192.0.2.0/24", "maxLength": 32, "ta": "APNIC RPKI Root"},
  {"asn": "AS64496", "prefix": "203.0.113.0/25", "maxLength": 26, "ta": "APNIC RPKI Root"},
  {"asn": "AS64497", "prefix": "203.0.113.0/26", "maxLength": 26, "ta": "APNIC RPKI Root"},
  {"asn": "AS64497", "prefix": "203.0.113.128/26", "maxLength": 26, "ta": "APNIC RPKI Root"}
]}`

const importerSLURM = `{
  "slurmVersion": 1,
  "validationOutputFilters": {
    "prefixFilters": [
      {"prefix": "203.0.113.0/25", "comment": "All VRPs encompassed by prefix"},
      {"asn": 64498, "comment": "All VRPs matching ASN"},
      {"prefix": "203.0.113.128/25", "asn": 64497, "comment": "All VRPs encompassed by prefix, matching ASN"},
      {"prefix": "192.0.2.0/24", "asn": 64497, "comment": "filters nothing: the ROA has AS64496"},
      {"prefix": "198.51.100.0/24", "asn": 64496, "comment": "must not filter the assertion"}
    ]
  },
  "locallyAddedAssertions": {
    "prefixAssertions": [
      {"asn": 64496, "prefix": "198.51.100.0/24", "comment": "My other important route"},
      {"asn": 64497, "prefix": "2001:DB8::/32", "maxPrefixLength": 48, "comment": "My other important de-aggregated routes"}
    ]
  }
}`

func TestImporterValidProcess(t *testing.T) {
	v, err := ReadJSON(strings.NewReader(importerROAs))
	if err != nil {
		t.Fatal(err)
	}
	if v.Len() != 6 {
		t.Fatalf("read %d VRPs, want 6", v.Len())
	}
	v, err = v.ApplySLURM(strings.NewReader(importerSLURM))
	if err != nil {
		t.Fatal(err)
	}
	// The ROAs IRRd inserts, in its order.
	want := []VRP{
		{netip.MustParsePrefix("192.0.2.0/24"), 26, 64496, "APNIC RPKI Root"},
		{netip.MustParsePrefix("2001:db8::/32"), 40, 64497, "RIPE NCC RPKI Root"},
		{netip.MustParsePrefix("198.51.100.0/24"), 24, 64496, "SLURM file"},
		{netip.MustParsePrefix("2001:db8::/32"), 48, 64497, "SLURM file"},
	}
	assertVRPs(t, v, want)
}

// TestSLURMRFC8416Example applies the example of RFC 8416 §3.5, whose BGPsec
// members are ignored.
func TestSLURMRFC8416Example(t *testing.T) {
	const slurm = `{
  "slurmVersion": 1,
  "validationOutputFilters": {
    "prefixFilters": [
      {"prefix": "192.0.2.0/24", "comment": "All VRPs encompassed by prefix"},
      {"asn": 64496, "comment": "All VRPs matching ASN"},
      {"prefix": "198.51.100.0/24", "asn": 64497, "comment": "All VRPs encompassed by prefix, matching ASN"}
    ],
    "bgpsecFilters": [
      {"asn": 64496, "comment": "All keys for ASN"},
      {"SKI": "<Base 64 of some SKI>", "comment": "Key matching Router SKI"},
      {"asn": 64497, "SKI": "<Base 64 of some SKI>", "comment": "Key for ASN 64497 matching Router SKI"}
    ]
  },
  "locallyAddedAssertions": {
    "prefixAssertions": [
      {"asn": 64496, "prefix": "198.51.100.0/24", "comment": "My other important route"},
      {"asn": 64496, "prefix": "2001:DB8::/32", "maxPrefixLength": 48, "comment": "My other important de-aggregated routes"}
    ],
    "bgpsecAssertions": [
      {"asn": 64496, "comment": "My known key for my important ASN", "SKI": "<some base64 SKI>", "routerPublicKey": "<some base64 public key>"}
    ]
  }
}`
	v := mustVRPs(t,
		vrp("192.0.2.128/25", 64511, 25),   // inside 192.0.2.0/24: dropped
		vrp("192.0.0.0/16", 64511, 24),     // covers the filter, not covered by it: kept
		vrp("203.0.113.0/24", 64496, 24),   // AS64496: dropped
		vrp("198.51.100.0/25", 64497, 25),  // prefix and ASN: dropped
		vrp("198.51.100.0/25", 64498, 25),  // prefix, other ASN: kept
		vrp("2001:db8:ff::/48", 64511, 48), // untouched
	)
	v, err := v.ApplySLURM(strings.NewReader(slurm))
	if err != nil {
		t.Fatal(err)
	}
	assertVRPs(t, v, []VRP{
		vrp("192.0.0.0/16", 64511, 24),
		vrp("198.51.100.0/25", 64498, 25),
		vrp("2001:db8:ff::/48", 64511, 48),
		{netip.MustParsePrefix("198.51.100.0/24"), 24, 64496, "SLURM file"},
		{netip.MustParsePrefix("2001:db8::/32"), 48, 64496, "SLURM file"},
	})
}

// TestSLURMSparesAssertions: a second SLURM file's filters, like IRRd's, do not
// touch VRPs a SLURM file asserted.
func TestSLURMSparesAssertions(t *testing.T) {
	v := mustVRPs(t, VRP{netip.MustParsePrefix("10.0.0.0/8"), 8, 1, SLURMTrustAnchor}, vrp("10.0.0.0/8", 1, 8))
	v, err := v.ApplySLURM(strings.NewReader(`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"asn": 1}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertVRPs(t, v, []VRP{{netip.MustParsePrefix("10.0.0.0/8"), 8, 1, SLURMTrustAnchor}})
}

func TestReadJSONFormats(t *testing.T) {
	for name, in := range map[string]string{
		// rpki-client 9: numeric asn, metadata and other payloads alongside.
		"rpki-client": `{"metadata": {"buildtime": "2026-09-27T08:00:00Z", "vrps": 2},
			"roas": [{"asn": 13335, "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic", "expires": 1790000000},
			         {"asn": 13335, "prefix": "2606:4700::/32", "maxLength": 48, "ta": "arin", "expires": 1790000000}],
			"aspas": [{"customer": 64496, "providers": [64497]}], "bgpsec_keys": []}`,
		// Routinator's json output: "AS"-prefixed strings.
		"routinator": `{"roas": [{"asn": "AS13335", "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic"},
			{"asn": "as13335", "prefix": "2606:4700::/32", "maxLength": "48", "ta": "arin"}]}`,
	} {
		v, err := ReadJSON(strings.NewReader(in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		assertVRPs(t, v, []VRP{
			{netip.MustParsePrefix("1.1.1.0/24"), 24, 13335, "apnic"},
			{netip.MustParsePrefix("2606:4700::/32"), 48, 13335, "arin"},
		})
	}
}

// TestReadJSONErrors covers IRRd's test_invalid_rpki_json and
// test_invalid_data_in_roa, and what IRRd lets through but a ROA cannot say.
func TestReadJSONErrors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`invalid`, "invalid JSON"},
		{`{"invalid root": 42}`, `no "roas"`},
		{`[]`, "not a JSON object"},
		{`{"roas": 42}`, "not an array"},
		{`{"roas": [], "roas": []}`, `"roas" twice`},
		{`{"roas": [{"asn": "AS64496", "prefix": "192.0.2.999/24", "maxLength": 26, "ta": "T"}]}`, "192.0.2.999"},
		{`{"roas": [{"asn": "ASx", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]}`, "ASx"},
		{`{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]}`, `missing "asn"`},
		{`{"roas": [{"asn": 1, "maxLength": 24, "ta": "T"}]}`, `missing "prefix"`},
		{`{"roas": [{"asn": 1, "prefix": "192.0.2.0/24", "ta": "T"}]}`, `missing "maxLength"`},
		{`{"roas": [{"asn": 1, "prefix": "192.0.2.0/24", "maxLength": 24}]}`, `missing "ta"`},
		{`{"roas": [{"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": 22, "ta": "T"}]}`, "max length 22"},
		{`{"roas": [{"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": "xx", "ta": "T"}]}`, "xx"},
		{`{"roas": [{"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": 33, "ta": "T"}]}`, "max length 33"},
		{`{"roas": [{"asn": 1, "prefix": "192.0.2.1/24", "maxLength": 24, "ta": "T"}]}`, "host bits"},
		{`{"roas": [{"asn": 4294967296, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]}`, "4294967296"},
		{`{"roas": [{"asn": -1, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]}`, "-1"},
		{`{"roas": [{"asn": 1.5, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]}`, "1.5"},
		{`{"roas": [{"asn": 1, "prefix": 7, "maxLength": 24, "ta": "T"}]}`, "prefix"},
		{`{"roas": [{"asn": 1, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": 7}]}`, "ta"},
		{`{"roas": [7]}`, "record 0"},
		{`{"roas": [{"asn": 1, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "T"}]} trailing`, "after"},
		{`{"roas": [`, "invalid JSON"},
	} {
		_, err := ReadJSON(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ReadJSON(%s): error %v, want one containing %q", tc.in, err, tc.want)
		}
	}
}

func TestApplySLURMErrors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"slurmVersion": 2}`, "version 2"}, // IRRd's test_invalid_slurm_version
		{`{}`, "version"},
		{`nope`, "invalid JSON"},
		{`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"comment": "neither"}]}}`, "neither"},
		{`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"prefix": "10.0.0.1/8"}]}}`, "host bits"},
		{`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"asn": "x"}]}}`, "asn"},
		{`{"slurmVersion": 1, "locallyAddedAssertions": {"prefixAssertions": [{"prefix": "10.0.0.0/8"}]}}`, `missing "asn"`},
		{`{"slurmVersion": 1, "locallyAddedAssertions": {"prefixAssertions": [{"asn": 1}]}}`, `missing "prefix"`},
		{`{"slurmVersion": 1, "locallyAddedAssertions": {"prefixAssertions": [{"asn": 1, "prefix": "10.0.0.0/8", "maxPrefixLength": 7}]}}`, "max length 7"},
		{`{"slurmVersion": 1, "locallyAddedAssertions": {"prefixAssertions": 3}}`, "prefixAssertions"},
	} {
		_, err := mustVRPs(t).ApplySLURM(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ApplySLURM(%s): error %v, want one containing %q", tc.in, err, tc.want)
		}
	}
}

func assertVRPs(t *testing.T, v *VRPs, want []VRP) {
	t.Helper()
	var got []VRP
	for x := range v.All() {
		got = append(got, x)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d VRPs %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("VRP %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestJSONKeysExact: keys are read as IRRd reads them, with their case.
func TestJSONKeysExact(t *testing.T) {
	if _, err := ReadJSON(strings.NewReader(`{"roas": [{"ASN": 1, "prefix": "10.0.0.0/8", "maxLength": 8, "ta": "T"}]}`)); err == nil {
		t.Error(`ReadJSON accepted "ASN" for "asn"`)
	}
	if _, err := ReadJSON(strings.NewReader(`{"ROAS": []}`)); err == nil {
		t.Error(`ReadJSON accepted "ROAS" for "roas"`)
	}
	if _, err := mustVRPs(t).ApplySLURM(strings.NewReader(`{"SlurmVersion": 1}`)); err == nil {
		t.Error(`ApplySLURM accepted "SlurmVersion"`)
	}
	if _, err := mustVRPs(t).ApplySLURM(strings.NewReader(`{"slurmVersion": 1, "validationOutputFilters": 3}`)); err == nil {
		t.Error("ApplySLURM accepted a non-object validationOutputFilters")
	}
}
