package nrtm4

import (
	"strings"
	"testing"
)

const (
	testSession = "ca128382-78d9-41d1-8927-1ecef15275be"
	hashA       = "9a6a1e0c1f5a9c2c2a3dc8e1c4a8fd8a2ad1f1b3c9e45b3d0c1b9f0e8a7d6c86"
	hashB       = "62b7a0a5fdb1df1e8b4a22b2b0dfd5b6e4f1c5d3a7e9f8b6c4d2e0f1a3b5c7a2"
)

// specExample is the payload of §6.3's example, with full-length hashes.
const specExample = `{
  "nrtm_version": 4,
  "timestamp": "2025-12-01T15:00:00Z",
  "type": "notification",
  "source": "EXAMPLE",
  "session_id": "ca128382-78d9-41d1-8927-1ecef15275be",
  "version": 4,
  "snapshot": {"version": 3, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-snapshot.3.04759.json.gz", "hash": "` + hashA + `"},
  "deltas": [
    {"version": 2, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-delta.2.784a2a6.json", "hash": "` + hashB + `"},
    {"version": 3, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-delta.3.0f681f0.json", "hash": "` + hashB + `"},
    {"version": 4, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-delta.4.d9c194a.json", "hash": "` + hashB + `"}
  ],
  "metadata": {}
}`

func TestParseNotificationSpecExample(t *testing.T) {
	n, err := parseNotification([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	if n.Source != "EXAMPLE" || n.Version != 4 || n.Snapshot.Version != 3 || len(n.Deltas) != 3 ||
		n.Deltas[0].Version != 2 || n.SessionID != testSession || n.Timestamp.Year() != 2025 || n.NextSigningKey != "" {
		t.Errorf("parsed %+v", n)
	}
}

// TestParseNotificationRules breaks each rule of §6.3 in turn.
func TestParseNotificationRules(t *testing.T) {
	key := pemOf(t, &newKey(t).PublicKey)
	withKey := strings.Replace(specExample, `"metadata": {}`, `"next_signing_key": `+quote(key), 1)
	if n, err := parseNotification([]byte(withKey)); err != nil || n.NextSigningKey != key {
		t.Fatalf("next_signing_key: %v", err)
	}
	for _, absent := range []string{`"next_signing_key": null`, `"next_signing_key": ""`} {
		if n, err := parseNotification([]byte(strings.Replace(specExample, `"metadata": {}`, absent, 1))); err != nil || n.NextSigningKey != "" {
			t.Errorf("%s: %v", absent, err)
		}
	}
	if n, err := parseNotification([]byte(strings.Replace(specExample, `"deltas": [`, `"x": [`, 1))); err == nil || n != nil {
		// "deltas" gone leaves version 4 with only a snapshot at 3: a mismatch, not a missing key.
		if err == nil {
			t.Error("a version above the snapshot's with no deltas was accepted")
		}
	}
	noDeltas := strings.Replace(strings.Replace(specExample, `"version": 4,`, `"version": 3,`, 1),
		specExample[strings.Index(specExample, `"deltas"`):strings.Index(specExample, `"metadata"`)], "", 1)
	if n, err := parseNotification([]byte(noDeltas)); err != nil || len(n.Deltas) != 0 {
		t.Fatalf("no deltas member: %v", err)
	}
	for _, tc := range []struct{ name, from, to, want string }{
		{"nrtm_version 3", `"nrtm_version": 4`, `"nrtm_version": 3`, "nrtm_version"},
		{"nrtm_version as a string", `"nrtm_version": 4`, `"nrtm_version": "4"`, "nrtm_version"},
		{"no nrtm_version", `"nrtm_version": 4,`, ``, "nrtm_version"},
		{"type snapshot", `"type": "notification"`, `"type": "snapshot"`, "type"},
		{"a local time", `"2025-12-01T15:00:00Z"`, `"2025-12-01T16:00:00+01:00"`, "offset"},
		{"not a time", `"2025-12-01T15:00:00Z"`, `"yesterday Z"`, "timestamp"},
		{"a bad source", `"source": "EXAMPLE"`, `"source": "EX AMPLE"`, "source"},
		{"a source starting with a digit", `"source": "EXAMPLE"`, `"source": "1EXAMPLE"`, "source"},
		{"an empty source", `"source": "EXAMPLE"`, `"source": ""`, "source"},
		{"a UUIDv1", `"session_id": "ca128382-78d9-41d1-8927`, `"session_id": "ca128382-78d9-11d1-8927`, "UUIDv4"},
		{"a bad UUID variant", `"session_id": "ca128382-78d9-41d1-8927`, `"session_id": "ca128382-78d9-41d1-c927`, "UUIDv4"},
		{"no session", `"session_id": "ca128382-78d9-41d1-8927-1ecef15275be",`, ``, "session_id"},
		{"version 0", `"version": 4,`, `"version": 0,`, "version"},
		{"version negative", `"version": 4,`, `"version": -4,`, "version"},
		{"version a fraction", `"version": 4,`, `"version": 4.0,`, "version"},
		{"version zero-padded", `"version": 4,`, `"version": 04,`, "version"},
		{"version a string", `"version": 4,`, `"version": "4",`, "version"},
		{"version not the highest", `"version": 4,`, `"version": 5,`, "highest"},
		{"no snapshot", `"snapshot": {`, `"snapshop": {`, "snapshot"},
		{"a snapshot without a hash", `, "hash": "` + hashA + `"}`, `}`, "hash"},
		{"a short hash", hashA, hashA[:62], "SHA-256"},
		{"a hash not hex", hashA, "z" + hashA[1:], "SHA-256"},
		{"an empty url", `"url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-snapshot.3.04759.json.gz"`, `"url": ""`, "url"},
		{"deltas not contiguous", `{"version": 3, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-delta`, `{"version": 5, "url": "ca128382-78d9-41d1-8927-1ecef15275be/nrtm-delta`, "contiguous"},
		{"deltas out of order", `{"version": 2, "url"`, `{"version": 3, "url"`, "contiguous"},
		{"deltas not an array", `"deltas": [`, `"deltas": "x", "y": [`, "array"},
		{"a bad next key", `"metadata": {}`, `"next_signing_key": "nope"`, "next_signing_key"},
		{"next key not a string", `"metadata": {}`, `"next_signing_key": 7`, "next_signing_key"},
		{"keys are case-sensitive", `"source": "EXAMPLE"`, `"Source": "EXAMPLE"`, "source"},
	} {
		in := strings.Replace(specExample, tc.from, tc.to, 1)
		if in == specExample {
			t.Fatalf("%s: the replacement changed nothing", tc.name)
		}
		if _, err := parseNotification([]byte(in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one about %q", tc.name, err, tc.want)
		}
	}
	for _, in := range []string{``, `[]`, `null`, `{"nrtm_version": 4`} {
		if _, err := parseNotification([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseFileHeader(t *testing.T) {
	const snap = `{"nrtm_version": 4, "type": "snapshot", "source": "EXAMPLE", "session_id": "` + testSession + `", "version": 3}`
	h, err := parseFileHeader([]byte(snap), "snapshot")
	if err != nil || h.Source != "EXAMPLE" || h.Version != 3 || h.SessionID != testSession {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := parseFileHeader([]byte(snap), "delta"); err == nil {
		t.Error("a snapshot header read as a delta's")
	}
	if _, err := parseFileHeader([]byte(`{"object": "route: 192.0.2.0/24"}`), "snapshot"); err == nil {
		t.Error("an object read as a header")
	}
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"`
}
