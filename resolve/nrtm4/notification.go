package nrtm4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"time"
)

// notification is a parsed, validated Update Notification File (§6.3).
type notification struct {
	Timestamp      time.Time
	Source         string
	SessionID      string // lower case
	Version        int64
	Snapshot       fileRef
	Deltas         []fileRef // contiguous versions, ascending
	NextSigningKey string    // PEM, or ""
}

// fileID names a snapshot or delta within a session.
type fileID struct {
	delta   bool
	version int64
}

func (id fileID) String() string {
	if id.delta {
		return fmt.Sprintf("delta %d", id.version)
	}
	return fmt.Sprintf("snapshot %d", id.version)
}

// refs yields every file the notification file references.
func (n *notification) refs() iter.Seq2[fileID, fileRef] {
	return func(yield func(fileID, fileRef) bool) {
		if !yield(fileID{false, n.Snapshot.Version}, n.Snapshot) {
			return
		}
		for _, d := range n.Deltas {
			if !yield(fileID{true, d.Version}, d) {
				return
			}
		}
	}
}

// fileRef is a snapshot or delta entry: its version, its URL relative to the
// notification file, and the SHA-256 of its bytes as served.
type fileRef struct {
	Version int64
	URL     string
	Hash    string // lower-case hex
}

// parseNotification reads a notification file's JWS payload and applies every
// rule of §6.3 that does not depend on the client's state. Keys are read as
// written: a JSON object's keys are case-sensitive.
func parseNotification(payload []byte) (*notification, error) {
	m, err := jsonObject(payload)
	if err != nil {
		return nil, err
	}
	if err := header(m, "notification"); err != nil {
		return nil, err
	}
	n := &notification{}
	if n.Source, err = sourceName(m); err != nil {
		return nil, err
	}
	if n.SessionID, err = sessionID(m); err != nil {
		return nil, err
	}
	if n.Version, err = positive(m, "version"); err != nil {
		return nil, err
	}
	ts, err := str(m, "timestamp")
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(ts, "Z") {
		return nil, fmt.Errorf("timestamp %q: the offset must be \"Z\"", ts)
	}
	if n.Timestamp, err = time.Parse(time.RFC3339, ts); err != nil {
		return nil, fmt.Errorf("timestamp %q: %w", ts, err)
	}
	raw, ok := m["snapshot"]
	if !ok {
		return nil, errors.New(`missing "snapshot"`)
	}
	if n.Snapshot, err = parseRef(raw); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if raw, ok := m["deltas"]; ok && string(raw) != "null" {
		var ds []json.RawMessage
		if err := json.Unmarshal(raw, &ds); err != nil {
			return nil, errors.New(`"deltas" is not an array`)
		}
		for i, d := range ds {
			ref, err := parseRef(d)
			if err != nil {
				return nil, fmt.Errorf("delta %d: %w", i, err)
			}
			if i > 0 && ref.Version != n.Deltas[i-1].Version+1 {
				return nil, fmt.Errorf("delta versions are not contiguous: %d follows %d", ref.Version, n.Deltas[i-1].Version)
			}
			n.Deltas = append(n.Deltas, ref)
		}
	}
	want := n.Snapshot.Version
	if len(n.Deltas) > 0 {
		want = max(want, n.Deltas[len(n.Deltas)-1].Version)
	}
	if n.Version != want {
		return nil, fmt.Errorf("version %d, but the highest snapshot or delta version is %d", n.Version, want)
	}
	if raw, ok := m["next_signing_key"]; ok && string(raw) != "null" && string(raw) != `""` { // null or "": no key announced
		if err := json.Unmarshal(raw, &n.NextSigningKey); err != nil {
			return nil, errors.New(`"next_signing_key" is not a string`)
		}
		if _, err := ParsePublicKey(n.NextSigningKey); err != nil {
			return nil, fmt.Errorf("next_signing_key: %w", err)
		}
	}
	return n, nil
}

func parseRef(raw json.RawMessage) (fileRef, error) {
	m, err := jsonObject(raw)
	if err != nil {
		return fileRef{}, err
	}
	var r fileRef
	if r.Version, err = positive(m, "version"); err != nil {
		return r, err
	}
	if r.URL, err = str(m, "url"); err != nil {
		return r, err
	}
	if r.URL == "" {
		return r, errors.New("empty url")
	}
	h, err := str(m, "hash")
	if err != nil {
		return r, err
	}
	if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
		return r, fmt.Errorf("hash %q is not a hex SHA-256", h)
	}
	r.Hash = strings.ToLower(h)
	return r, nil
}

// fileHeader is the first record of a snapshot or delta file (§7.3, §8.3).
type fileHeader struct {
	Source    string
	SessionID string
	Version   int64
}

func parseFileHeader(rec []byte, typ string) (fileHeader, error) {
	m, err := jsonObject(rec)
	if err != nil {
		return fileHeader{}, err
	}
	if err := header(m, typ); err != nil {
		return fileHeader{}, err
	}
	var h fileHeader
	if h.Source, err = sourceName(m); err != nil {
		return h, err
	}
	if h.SessionID, err = sessionID(m); err != nil {
		return h, err
	}
	h.Version, err = positive(m, "version")
	return h, err
}

// header checks the members every NRTMv4 root object has: nrtm_version 4 and
// its type.
func header(m map[string]json.RawMessage, typ string) error {
	v, ok := m["nrtm_version"]
	if !ok {
		return errors.New(`missing "nrtm_version"`)
	}
	if string(v) != "4" {
		return fmt.Errorf("nrtm_version %s, want 4", v)
	}
	t, err := str(m, "type")
	if err != nil {
		return err
	}
	if t != typ {
		return fmt.Errorf("type %q, want %q", t, typ)
	}
	return nil
}

// sourceName reads "source", which must be an RPSL object name (RFC 2622 §2):
// a letter, then letters, digits, "_" and "-".
func sourceName(m map[string]json.RawMessage) (string, error) {
	s, err := str(m, "source")
	if err != nil {
		return "", err
	}
	for i, c := range s {
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '_' || c == '-')) {
			return "", fmt.Errorf("source %q is not an RPSL object name", s)
		}
	}
	if s == "" {
		return "", errors.New("empty source")
	}
	return s, nil
}

// sessionID reads "session_id", a UUIDv4 (RFC 9562 §5.4), lower-cased.
func sessionID(m map[string]json.RawMessage) (string, error) {
	s, err := str(m, "session_id")
	if err != nil {
		return "", err
	}
	s = strings.ToLower(s)
	ok := len(s) == 36
	for i := 0; ok && i < 36; i++ {
		switch c := s[i]; {
		case i == 8 || i == 13 || i == 18 || i == 23:
			ok = c == '-'
		case i == 14:
			ok = c == '4'
		case i == 19:
			ok = c == '8' || c == '9' || c == 'a' || c == 'b'
		default:
			ok = c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
		}
	}
	if !ok {
		return "", fmt.Errorf("session_id %q is not a UUIDv4", s)
	}
	return s, nil
}

func jsonObject(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("not a JSON object: %.80q", raw)
	}
	return m, nil
}

func str(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || bytes.Equal(raw, []byte("null")) {
		return "", fmt.Errorf("%q is not a string: %.40s", key, raw)
	}
	return s, nil
}

// positive reads an unsigned positive integer: digits only, no fraction,
// exponent or sign.
func positive(m map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing %q", key)
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 1 || raw[0] == '+' || raw[0] == '0' {
		return 0, fmt.Errorf("%q is not a positive integer: %.40s", key, raw)
	}
	return n, nil
}
