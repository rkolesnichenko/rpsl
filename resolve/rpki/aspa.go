package rpki

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"

	"github.com/rkolesnichenko/rpsl/types"
)

// ASPA is one validated ASPA payload (draft-ietf-sidrops-aspa-profile-29):
// Customer names the ASes it may send routes to as a customer.
type ASPA struct {
	Customer  types.ASN   // never 0
	Providers []types.ASN // ascending, unique, never Customer; [0] alone: no transit providers
}

// MaxProviders caps one customer's providers, after merging: the top of the
// profile's recommended 4,000 to 10,000 (§5.5).
const MaxProviders = 10_000

// ASPAs is an immutable set of ASPAs, at most one per customer, safe for
// concurrent use. The zero value holds none.
//
// It is the RPKI data the consistency checks (resolve/consist) read. IRRd's
// RPKI-aware mode, which the rest of this package reproduces, has no use for
// it.
type ASPAs struct {
	m map[types.ASN][]types.ASN // customer -> providers, ascending, without AS0; empty: an AS0 ASPA
}

// NewASPAs validates each ASPA as the profile's §3.3 requires — a customer
// other than AS0; providers not empty, ascending, unique, without the
// customer, with AS0 only alone; at most MaxProviders — and merges those of
// one customer into the union of their providers (§5.2), AS0 dropped when
// any other provider is present. It copies its input.
func NewASPAs(as []ASPA) (*ASPAs, error) {
	s := &ASPAs{m: make(map[types.ASN][]types.ASN, len(as))}
	for i, a := range as {
		if err := checkASPA(a); err != nil {
			return nil, fmt.Errorf("rpki: ASPA %d: %w", i, err)
		}
		if err := s.merge(a); err != nil {
			return nil, fmt.Errorf("rpki: ASPA %d: %w", i, err)
		}
	}
	return s, nil
}

// checkASPA applies the profile's §3.3 to one ASPA.
func checkASPA(a ASPA) error {
	if a.Customer == 0 {
		return errors.New("customer AS0")
	}
	if len(a.Providers) == 0 {
		return fmt.Errorf("%s: no providers", a.Customer)
	}
	if len(a.Providers) > MaxProviders {
		return fmt.Errorf("%s: %d providers, more than %d", a.Customer, len(a.Providers), MaxProviders)
	}
	for i, p := range a.Providers {
		switch {
		case p == a.Customer:
			return fmt.Errorf("%s lists itself as a provider", a.Customer)
		case p == 0 && len(a.Providers) > 1:
			return fmt.Errorf("%s: AS0 beside other providers", a.Customer)
		case i > 0 && p <= a.Providers[i-1]:
			return fmt.Errorf("%s: providers not ascending and unique at %s", a.Customer, p)
		}
	}
	return nil
}

// merge adds a checked ASPA to s.
func (s *ASPAs) merge(a ASPA) error {
	ps := a.Providers
	if ps[0] == 0 {
		ps = nil
	}
	old, seen := s.m[a.Customer]
	if !seen {
		s.m[a.Customer] = slices.Clone(ps)
		return nil
	}
	u := union(old, ps)
	if len(u) > MaxProviders {
		return fmt.Errorf("%s: %d providers after merging, more than %d", a.Customer, len(u), MaxProviders)
	}
	s.m[a.Customer] = u
	return nil
}

// union merges two ascending, duplicate-free lists.
func union(a, b []types.ASN) []types.ASN {
	out := make([]types.ASN, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j == len(b) || (i < len(a) && a[i] < b[j]):
			out = append(out, a[i])
			i++
		case i == len(a) || b[j] < a[i]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i, j = i+1, j+1
		}
	}
	return out
}

// Providers returns customer's providers, ascending, and whether it has an
// ASPA at all. ok with no providers is an AS0 ASPA: the customer declares no
// transit providers. The slice is a copy.
func (s *ASPAs) Providers(customer types.ASN) (providers []types.ASN, ok bool) {
	if s == nil {
		return nil, false
	}
	ps, ok := s.m[customer]
	return slices.Clone(ps), ok
}

// Len returns the number of customers with an ASPA.
func (s *ASPAs) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}

// All yields the merged ASPAs, ascending by customer; an AS0 ASPA has
// Providers [0], as the profile writes it.
func (s *ASPAs) All() iter.Seq[ASPA] {
	return func(yield func(ASPA) bool) {
		if s == nil {
			return
		}
		cs := make([]types.ASN, 0, len(s.m))
		for c := range s.m {
			cs = append(cs, c)
		}
		slices.Sort(cs)
		for _, c := range cs {
			ps := slices.Clone(s.m[c])
			if len(ps) == 0 {
				ps = []types.ASN{0}
			}
			if !yield(ASPA{Customer: c, Providers: ps}) {
				return
			}
		}
	}
}

// ReadASPAs reads the ASPAs of a relying-party validator's JSON export: the
// object's top-level "aspas" array, one record at a time, so memory follows
// the ASPAs, not the file; other members ("roas", "metadata", …) are
// skipped. A record names its customer as "customer_asid" (rpki-client 8.5
// and later) or "customer" (Routinator) — exactly one of them — and its
// "providers" as an array; other keys ("expires", "ta", "source") are
// ignored. An AS number may be a JSON number, a numeric string, or "AS"
// followed by one, as ReadJSON reads "asn". Records go through NewASPAs: one
// bad record fails the whole read.
//
// An export without "aspas" is an error, not an empty set — the validator
// was not asked to export ASPAs, and reading none would make every check
// that uses them silently report nothing. So is rpki-client 8.0–8.4's
// per-AFI "provider_authorizations" form, superseded in 8.5.
func ReadASPAs(r io.Reader) (*ASPAs, error) {
	var as []ASPA
	seen, perAFI := false, false
	err := walkObject(json.NewDecoder(r), func(d *json.Decoder, key string) error {
		switch key {
		case "aspas":
			if seen {
				return errors.New(`"aspas" twice`)
			}
			seen = true
			return walkArray(d, "aspas", func(i int, raw json.RawMessage) error {
				a, err := decodeASPA(raw)
				if err == nil {
					err = checkASPA(a)
				}
				if err != nil {
					return fmt.Errorf("record %d: %w", i, err)
				}
				as = append(as, a)
				return nil
			})
		case "provider_authorizations":
			perAFI = true
		}
		return skip(d)
	})
	if err == nil && !seen {
		if perAFI {
			err = errors.New(`"provider_authorizations" is rpki-client 8.0-8.4's per-AFI ASPA form, superseded in 8.5 by "aspas"`)
		} else {
			err = errors.New(`no "aspas" member: the export has no ASPAs (rpki-client writes them unless run with -A; Routinator only with enable-aspa)`)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("rpki: reading ASPAs: %w", err)
	}
	return NewASPAs(as)
}

func decodeASPA(raw json.RawMessage) (ASPA, error) {
	// A map, not a struct: encoding/json matches struct fields without regard
	// to case, and the validators write exactly these keys.
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rec); err != nil || rec == nil {
		return ASPA{}, fmt.Errorf("not an object: %s", raw)
	}
	asid, hasASID := rec["customer_asid"]
	cust, hasCust := rec["customer"]
	switch {
	case hasASID && hasCust:
		return ASPA{}, errors.New(`both "customer_asid" and "customer"`)
	case hasCust:
		asid = cust
	case !hasASID:
		return ASPA{}, errors.New(`missing "customer_asid" (rpki-client) or "customer" (Routinator)`)
	}
	if err := require(rec, "providers"); err != nil {
		return ASPA{}, err
	}
	c, err := decodeASN(asid)
	if err != nil {
		return ASPA{}, fmt.Errorf("customer: %w", err)
	}
	var ps []json.RawMessage
	if err := json.Unmarshal(rec["providers"], &ps); err != nil || ps == nil {
		return ASPA{}, fmt.Errorf("providers %s: not an array", rec["providers"])
	}
	if len(ps) > MaxProviders {
		return ASPA{}, fmt.Errorf("%s: %d providers, more than %d", c, len(ps), MaxProviders)
	}
	a := ASPA{Customer: c, Providers: make([]types.ASN, len(ps))}
	for i, p := range ps {
		if a.Providers[i], err = decodeASN(p); err != nil {
			return ASPA{}, fmt.Errorf("provider %d: %w", i, err)
		}
	}
	return a, nil
}
