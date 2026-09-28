package rpki

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// SLURMTrustAnchor is the TA of a VRP a SLURM file asserted, as IRRd names it.
const SLURMTrustAnchor = "SLURM file"

// ReadJSON reads VRPs from the JSON export relying-party validators write and
// IRRd's rpki.roa_source reads: an object whose "roas" array holds records
// {"asn", "prefix", "maxLength", "ta"}. Other members (rpki-client's metadata,
// ASPA and BGPsec payloads) are ignored. An asn may be a number, "13335" or
// "AS13335"; a maxLength a number or a numeric string. The array is decoded
// one record at a time, so memory follows the VRPs, not the file.
//
// As in IRRd, one bad record fails the whole read — a missing key, an
// unparsable value, a prefix with host bits set, a maxLength shorter than the
// prefix — and so does a maxLength past the family's length, which IRRd lets
// through.
func ReadJSON(r io.Reader) (*VRPs, error) {
	var vs []VRP
	tas := map[string]string{} // a handful of trust anchors: one copy each
	seen := false
	err := walkObject(json.NewDecoder(r), func(d *json.Decoder, key string) error {
		if key != "roas" {
			return skip(d)
		}
		if seen {
			return errors.New(`"roas" twice`)
		}
		seen = true
		return walkArray(d, "roas", func(i int, raw json.RawMessage) error {
			v, err := decodeROA(raw)
			if err != nil {
				return fmt.Errorf("record %d: %w", i, err)
			}
			if ta, ok := tas[v.TA]; ok {
				v.TA = ta
			} else {
				tas[v.TA] = v.TA
			}
			vs = append(vs, v)
			return nil
		})
	})
	if err == nil && !seen {
		err = errors.New(`no "roas" member`)
	}
	if err != nil {
		return nil, fmt.Errorf("rpki: reading VRPs: %w", err)
	}
	return indexVRPs(vs)
}

func decodeROA(raw json.RawMessage) (VRP, error) {
	// A map, not a struct: encoding/json matches struct fields without regard
	// to case, and IRRd reads exactly these keys.
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rec); err != nil || rec == nil {
		return VRP{}, fmt.Errorf("not an object: %s", raw)
	}
	if err := require(rec, "asn", "prefix", "maxLength", "ta"); err != nil {
		return VRP{}, err
	}
	asn, err := decodeASN(rec["asn"])
	if err != nil {
		return VRP{}, err
	}
	p, err := decodePrefix(rec["prefix"])
	if err != nil {
		return VRP{}, err
	}
	maxLen, err := decodeLength(rec["maxLength"])
	if err != nil {
		return VRP{}, err
	}
	var ta string
	if err := json.Unmarshal(rec["ta"], &ta); err != nil || string(rec["ta"]) == "null" {
		return VRP{}, fmt.Errorf("ta %s: not a string", rec["ta"])
	}
	v := VRP{Prefix: p, MaxLength: maxLen, ASN: asn, TA: ta}
	return v, check(v)
}

// ApplySLURM returns the VRPs amended by an RFC 8416 (version 1) SLURM file,
// as IRRd applies one: a prefixFilters entry drops each VRP whose ASN it
// names, whose prefix is its prefix or more specific, or both, as the entry
// gives one or both; a prefixAssertions entry adds a VRP with TA
// SLURMTrustAnchor, and a maxLength of its prefix's length when it gives no
// maxPrefixLength. Filters never drop an asserted VRP, from this file or an
// earlier one. The filtered VRPs keep their order, and the assertions follow
// them. BGPsec filters and assertions are ignored.
func (s *VRPs) ApplySLURM(r io.Reader) (*VRPs, error) {
	fs, as, err := readSLURM(r)
	if err != nil {
		return nil, fmt.Errorf("rpki: reading SLURM: %w", err)
	}
	var out []VRP
	for v := range s.All() {
		if v.TA == SLURMTrustAnchor || !filtered(fs, v) {
			out = append(out, v)
		}
	}
	return indexVRPs(append(out, as...))
}

type prefixFilter struct {
	prefix netip.Prefix // zero: any prefix
	asn    types.ASN
	hasASN bool
}

func filtered(fs []prefixFilter, v VRP) bool {
	for _, f := range fs {
		if f.hasASN && f.asn != v.ASN {
			continue
		}
		if f.prefix.IsValid() && !covers(f.prefix, v.Prefix) {
			continue
		}
		return true
	}
	return false
}

// covers reports whether p is q or less specific, in q's family.
func covers(p, q netip.Prefix) bool {
	return p.Addr().Is4() == q.Addr().Is4() && p.Bits() <= q.Bits() && p.Contains(q.Addr())
}

func readSLURM(r io.Reader) (fs []prefixFilter, as []VRP, err error) {
	var doc map[string]json.RawMessage
	d := json.NewDecoder(r)
	if err := d.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := atEOF(d); err != nil {
		return nil, nil, err
	}
	if v, ok := doc["slurmVersion"]; !ok || string(v) != "1" {
		if !ok {
			v = json.RawMessage("none")
		}
		return nil, nil, fmt.Errorf("unsupported slurmVersion: version %s, want 1", v)
	}
	filters, err := member(doc, "validationOutputFilters", "prefixFilters")
	if err != nil {
		return nil, nil, err
	}
	assertions, err := member(doc, "locallyAddedAssertions", "prefixAssertions")
	if err != nil {
		return nil, nil, err
	}
	err = eachRecord(filters, "prefixFilters", func(i int, rec map[string]json.RawMessage) error {
		var f prefixFilter
		if raw, ok := rec["asn"]; ok {
			a, err := decodeASN(raw)
			if err != nil {
				return err
			}
			f.asn, f.hasASN = a, true
		}
		if raw, ok := rec["prefix"]; ok {
			p, err := decodePrefix(raw)
			if err != nil {
				return err
			}
			if p != p.Masked() {
				return fmt.Errorf("prefix %s has host bits set", p)
			}
			f.prefix = p
		}
		if !f.hasASN && !f.prefix.IsValid() {
			return errors.New("neither prefix nor asn (RFC 8416 §3.3.1)")
		}
		fs = append(fs, f)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	err = eachRecord(assertions, "prefixAssertions", func(i int, rec map[string]json.RawMessage) error {
		if err := require(rec, "asn", "prefix"); err != nil {
			return err
		}
		a, err := decodeASN(rec["asn"])
		if err != nil {
			return err
		}
		p, err := decodePrefix(rec["prefix"])
		if err != nil {
			return err
		}
		v := VRP{Prefix: p, MaxLength: uint8(p.Bits()), ASN: a, TA: SLURMTrustAnchor}
		if raw, ok := rec["maxPrefixLength"]; ok {
			if v.MaxLength, err = decodeLength(raw); err != nil {
				return err
			}
		}
		if err := check(v); err != nil {
			return err
		}
		as = append(as, v)
		return nil
	})
	return fs, as, err
}

// member returns doc[outer][inner] (absent or null: nil).
func member(doc map[string]json.RawMessage, outer, inner string) (json.RawMessage, error) {
	raw, ok := doc[outer]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: not an object", outer)
	}
	return m[inner], nil
}

// require refuses a record without every one of keys.
func require(rec map[string]json.RawMessage, keys ...string) error {
	for _, k := range keys {
		if _, ok := rec[k]; !ok {
			return fmt.Errorf("missing %q", k)
		}
	}
	return nil
}

// eachRecord calls fn for each object of the JSON array raw (absent or null:
// none).
func eachRecord(raw json.RawMessage, name string, fn func(int, map[string]json.RawMessage) error) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var recs []json.RawMessage
	if err := json.Unmarshal(raw, &recs); err != nil {
		return fmt.Errorf("%s: not an array", name)
	}
	for i, r := range recs {
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(r, &rec); err != nil || rec == nil {
			return fmt.Errorf("%s %d: not an object", name, i)
		}
		if err := fn(i, rec); err != nil {
			return fmt.Errorf("%s %d: %w", name, i, err)
		}
	}
	return nil
}

// decodeASN reads a number, or a string holding one with or without "AS".
func decodeASN(raw json.RawMessage) (types.ASN, error) {
	s := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("asn %s: %w", raw, err)
		}
		if len(s) >= 2 && strings.EqualFold(s[:2], "AS") {
			a, err := types.ParseASN(s)
			if err != nil {
				return 0, fmt.Errorf("asn %q: %w", s, err)
			}
			return a, nil
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("asn %s: not an AS number", raw)
	}
	return types.ASN(n), nil
}

// decodeLength reads a prefix length, a number or a numeric string.
func decodeLength(raw json.RawMessage) (uint8, error) {
	s := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("max length %s: %w", raw, err)
		}
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("max length %s: not a prefix length", raw)
	}
	return uint8(n), nil
}

func decodePrefix(raw json.RawMessage) (netip.Prefix, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return netip.Prefix{}, fmt.Errorf("prefix %s: not a string", raw)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("prefix %q: %w", s, err)
	}
	return p, nil
}

// walkObject reads one JSON object from d, calling member for each key with d
// positioned at its value, which member must consume; then requires EOF.
func walkObject(d *json.Decoder, member func(*json.Decoder, string) error) error {
	tok, err := d.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if tok != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if err := member(d, tok.(string)); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil { // the closing '}'
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return atEOF(d)
}

// walkArray reads the JSON array at d's position, calling elem for each
// element in turn.
func walkArray(d *json.Decoder, name string, elem func(int, json.RawMessage) error) error {
	tok, err := d.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("%q is not an array", name)
	}
	var raw json.RawMessage // reused: elem must not keep it
	for i := 0; d.More(); i++ {
		if err := d.Decode(&raw); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if err := elem(i, raw); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil { // the closing ']'
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// skip consumes the JSON value at d's position.
func skip(d *json.Decoder) error {
	var raw json.RawMessage
	if err := d.Decode(&raw); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// atEOF requires that nothing but white space follows the document.
func atEOF(d *json.Decoder) error {
	if _, err := d.Token(); err != io.EOF {
		rest, _ := io.ReadAll(io.LimitReader(d.Buffered(), 32))
		return fmt.Errorf("invalid JSON: data after the document: %q", bytes.TrimSpace(rest))
	}
	return nil
}
