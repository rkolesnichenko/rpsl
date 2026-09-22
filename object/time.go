package object

import (
	"fmt"
	"strings"
	"time"
)

// Timestamp is a registry timestamp — the value of created: or last-modified:,
// which RIPE writes as RFC 3339 UTC ("2020-01-01T00:00:00Z"). Raw keeps the
// text as written, so an unparsable or differently spelled stamp still
// round-trips and is never reformatted.
type Timestamp struct {
	Time time.Time
	Raw  string
}

// IsZero reports whether the attribute was absent.
func (t Timestamp) IsZero() bool { return t.Raw == "" }

// Known reports whether the stamp parsed into a usable time.
func (t Timestamp) Known() bool { return !t.Time.IsZero() }

// String returns the timestamp as written.
func (t Timestamp) String() string { return t.Raw }

// ParseTimestamp parses an RFC 3339 registry timestamp. On failure it returns a
// Timestamp carrying only Raw, so the caller can keep the value and warn.
func ParseTimestamp(s string) (Timestamp, error) {
	raw := strings.TrimSpace(s)
	t := Timestamp{Raw: raw}
	if raw == "" {
		return t, fmt.Errorf("rpsl/object: empty timestamp")
	}
	v, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return t, fmt.Errorf("rpsl/object: invalid RFC 3339 timestamp %q", raw)
	}
	t.Time = v
	return t, nil
}

// Changed is one changed: line: who last changed the object, and when
// ("ex@example.net 20200101"). The date is optional in practice, and Raw keeps
// the line as written.
//
// changed: is a legacy attribute — RIPE removed it from its templates — but
// every historical dump is full of them, so the typed layer reads it.
type Changed struct {
	Email string
	Date  time.Time // the zero time when the line carried no usable date
	Raw   string
}

// String returns the changed line as written.
func (c Changed) String() string { return c.Raw }

// ParseChanged parses one changed: value. A line with no date is not an error:
// it is common in real data. An unparsable date returns an error along with a
// Changed that still carries Email and Raw.
func ParseChanged(s string) (Changed, error) {
	raw := strings.TrimSpace(s)
	c := Changed{Raw: raw}
	if raw == "" {
		return c, fmt.Errorf("rpsl/object: empty changed line")
	}
	email, rest, _ := strings.Cut(raw, " ")
	c.Email = email
	date := strings.TrimSpace(rest)
	if date == "" {
		return c, nil
	}
	v, err := time.Parse("20060102", date)
	if err != nil {
		return c, fmt.Errorf("rpsl/object: invalid changed date %q", date)
	}
	c.Date = v
	return c, nil
}
