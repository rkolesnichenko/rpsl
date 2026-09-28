# src-members and PolicySource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Registry-scoped set members (draft-ietf-grow-rpsl-registry-scoped-members-00) end to end, and a `PolicySource` that serves aut-nums and inet-rtrs, breaking `resolve.Source` once, for v0.20.0.

**Architecture:** A comparable `types.SetRef{source, name}` becomes the engine's reference and graph key; `object` decodes `src-members:` and owns the draft's member-selection rule (`DirectMembers`); `Source.GetSet` takes a `SetRef` and every backend resolves a scoped ref in that registry only. `PolicySource` is an additive sibling interface; the Corpus keeps aut-nums as text and decodes on demand.

**Tech Stack:** Go 1.23 floor, standard library only, multi-module repo wired by `go.work` (`lexer`, `ast`, `types`, `resolve` are modules; `object`, `policy`, `auth`, `rpsl` are the root module).

**Spec:** `docs/superpowers/specs/2026-09-28-src-members-policysource-design.md` — read it first; this plan argues from it and cites its sections as "spec §N".

## Global Constraints

- `go.mod` floors stay at `go 1.23`; no new third-party dependencies anywhere.
- `types` depends only on itself: `cd types && go list -deps ./... | grep rkolesnichenko` prints only `github.com/rkolesnichenko/rpsl/types`.
- Engine purity: `cd resolve && go list -deps . | grep -x net` prints nothing.
- Never slice a string at an offset found in a transformed copy of it (`strings.ToUpper` can lengthen UTF-8). Validate ASCII first, then fold.
- Lossless round trip is untouched: `go test -run 'TestRoundTrip|TestStreamRoundTrip' .` stays green after every task.
- Every diagnostic rule emitted is listed in `docs/diagnostics.md` (`TestDiagnosticRulesAreDocumented`).
- If `object/profiles.go` lists an attribute on a class, the class's decoder must read it into its own field (`TestEveryAttributeLandsInItsOwnField`).
- rpslq-only command-line options are long options; bgpq4's letters are never reused.
- `go test ./...` covers only the root module. Run a module's tests from its directory (`cd resolve && go test ./...`); run everything with `scripts/check.sh`.
- Commit after each task on branch `src-members-policysource-spec` (already checked out), message style `area: what changed` (e.g. `types: add SetRef`).

## Review Focus

1. **A set named in members: without a registry and in src-members: with one, where the registry's copy is missing.** Expected: the scoped fetch is missing and the unscoped copy is *not* used (the draft's Figure 1 note: "This would happen even if there was no RS-SECOND object found in RIPE"). Pinned in Task 5 (`TestScopedMissDoesNotFallBack`).
2. **A Source that ignores the scope and answers from another registry.** Expected: the fetch fails with an error naming both registries; nothing is expanded from the wrong copy. Pinned in Task 5 (`TestCheckSetRefusesWrongRegistry`).
3. **`2001:db8::/32` in a route-set's src-members:** — it contains `::`. Expected: a prefix member, never a scoped set with source `2001:db8`. Pinned in Task 2 (`TestParseSrcMemberIPv6IsAPrefix`).
4. **Mixed case and whitespace in a scoped reference** (`ripe::as-foo`, `RIPE :: AS-FOO`, `ＲＩＰＥ::AS-FOO`). Expected: the first is `RIPE::AS-FOO`; the other two are errors, never a panic or a silently different registry. Pinned in Task 1 (`TestParseSetRef`) and the fuzz target.
5. **The same set reachable both as `RIPE::AS-X` and as `AS-X` in one expansion, where precedence picks another registry for `AS-X`.** Expected: both copies contribute (two nodes), and `Missing()` names whichever of the two was absent with its scope. Pinned in Task 5 (`TestSameNameTwoScopes`).

---

### Task 1: `types.SetRef` and `types.ParseSourceName`

**Files:**
- Create: `types/setref.go`
- Create: `types/setref_test.go`
- Modify: `types/fuzz_test.go` (append a fuzz target)

**Interfaces:**
- Consumes: `types.SetName`, `types.ParseSetName`, the unexported `isAlnum` in `types/setname.go`.
- Produces:
  - `type SetRef struct{ /* unexported: source string; name SetName */ }` — comparable.
  - `func Ref(name SetName) SetRef`
  - `func NewSetRef(source string, name SetName) (SetRef, error)`
  - `func ParseSetRef(s string) (SetRef, error)`
  - `func (r SetRef) Source() string`, `Name() SetName`, `IsScoped() bool`, `IsZero() bool`, `String() string`
  - `func ParseSourceName(s string) (string, error)`
  - `const MaxSourceNameLen = 64`

- [ ] **Step 1: Write the failing tests**

`types/setref_test.go`:

```go
package types

import "testing"

func TestParseSourceName(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"RIPE", "RIPE", true},
		{"ripe-nonauth", "RIPE-NONAUTH", true},
		{"Level3_x", "LEVEL3_X", true},
		{"", "", false},
		{"RI PE", "", false},
		{"RIPE,RADB", "", false},
		{"RIPE\n!q", "", false},
		{"ＲＩＰＥ", "", false},         // full-width letters are not ASCII
		{string(make([]byte, 65)), "", false}, // over MaxSourceNameLen (and NULs)
	} {
		got, err := ParseSourceName(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseSourceName(%q) = %q, %v; want %q, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParseSetRef(t *testing.T) {
	for _, tc := range []struct {
		in, want, source string
		ok, scoped       bool
	}{
		{"AS-FOO", "AS-FOO", "", true, false},
		{"as-foo", "AS-FOO", "", true, false},
		{"RIPE::AS-FOO", "RIPE::AS-FOO", "RIPE", true, true},
		{"ripe::as-foo", "RIPE::AS-FOO", "RIPE", true, true},
		{"  RIPE::AS1:RS-X  ", "RIPE::AS1:RS-X", "RIPE", true, true},
		{"RIPE :: AS-FOO", "", "", false, false},
		{"RIPE:: AS-FOO", "", "", false, false},
		{"RIPE ::AS-FOO", "", "", false, false},
		{"::AS-FOO", "", "", false, false},
		{"RIPE::", "", "", false, false},
		{"RIPE::AS1", "", "", false, false}, // an AS number is not a set
		{"ＲＩＰＥ::AS-FOO", "", "", false, false},
		{"RIPE::RADB::AS-FOO", "", "", false, false},
	} {
		r, err := ParseSetRef(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseSetRef(%q) error = %v; want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if r.String() != tc.want || r.Source() != tc.source || r.IsScoped() != tc.scoped {
			t.Errorf("ParseSetRef(%q) = %q (source %q, scoped %v); want %q (%q, %v)",
				tc.in, r, r.Source(), r.IsScoped(), tc.want, tc.source, tc.scoped)
		}
	}
}

func TestSetRefIsComparable(t *testing.T) {
	a, _ := ParseSetRef("ripe::as-foo")
	b, _ := ParseSetRef("RIPE::AS-FOO")
	c, _ := ParseSetRef("AS-FOO")
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
	if a == c {
		t.Errorf("scoped %v == unscoped %v", a, c)
	}
	if c != Ref(c.Name()) {
		t.Errorf("Ref(%v) differs from the parsed unscoped ref", c.Name())
	}
	m := map[SetRef]bool{a: true}
	if !m[b] || m[c] {
		t.Error("SetRef map keys do not follow ==")
	}
}

func TestNewSetRef(t *testing.T) {
	n, _ := ParseSetName("AS-FOO")
	if r, err := NewSetRef("", n); err != nil || r.IsScoped() || r.Name() != n {
		t.Errorf(`NewSetRef("", AS-FOO) = %v, %v`, r, err)
	}
	if r, err := NewSetRef("radb", n); err != nil || r.String() != "RADB::AS-FOO" {
		t.Errorf(`NewSetRef("radb", AS-FOO) = %v, %v`, r, err)
	}
	if _, err := NewSetRef("RA DB", n); err == nil {
		t.Error(`NewSetRef("RA DB", …) accepted a bad source`)
	}
	if _, err := NewSetRef("RIPE", SetName{}); err == nil {
		t.Error("NewSetRef accepted a zero SetName")
	}
	if !(SetRef{}).IsZero() || Ref(n).IsZero() {
		t.Error("IsZero is wrong")
	}
}
```

Append to `types/fuzz_test.go`:

```go
// FuzzParseSetRef: never panics; what it accepts round-trips through String
// to an equal ref, and its source is safe to put in a query.
func FuzzParseSetRef(f *testing.F) {
	for _, s := range []string{
		"AS-FOO", "RIPE::AS-FOO", "ripe::as1:rs-x^+", "RIPE :: AS-FOO", "::", "ɐ::AS-X",
		"RIPE::ɐ", "ＲＩＰＥ::AS-FOO", "2001:db8::/32", "A::B::C",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseSetRef(s)
		if err != nil {
			return
		}
		back, err := ParseSetRef(r.String())
		if err != nil || back != r {
			t.Fatalf("ParseSetRef(%q) = %q, which parses back to %q, %v", s, r, back, err)
		}
		for i := 0; i < len(r.Source()); i++ {
			c := r.Source()[i]
			if !('A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				t.Fatalf("ParseSetRef(%q) source %q has byte %q", s, r.Source(), c)
			}
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd types && go test -run 'TestParseSourceName|TestParseSetRef|TestSetRef|TestNewSetRef' .`
Expected: FAIL — `undefined: ParseSourceName` (and the other new names).

- [ ] **Step 3: Implement**

`types/setref.go`:

```go
package types

import (
	"fmt"
	"strings"
)

// MaxSourceNameLen is the longest IRR source name ParseSourceName accepts, in
// bytes. Real names ("RIPE-NONAUTH", "LEVEL3") are a dozen bytes.
const MaxSourceNameLen = 64

// ParseSourceName validates and canonicalizes an IRR source name — the value of
// a source: attribute, or the registry of a scoped reference: ASCII letters,
// digits, '-' and '_', upper-cased. Such a name cannot carry another command or
// argument, so it is safe in an IRRd "!s" or a whois "-s" query.
func ParseSourceName(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("rpsl/types: invalid source name: empty")
	}
	if len(s) > MaxSourceNameLen {
		return "", fmt.Errorf("rpsl/types: invalid source name: longer than %d bytes", MaxSourceNameLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '-' && c != '_' {
			return "", fmt.Errorf("rpsl/types: invalid source name %q", s)
		}
	}
	return strings.ToUpper(s), nil // ASCII only, so no byte offsets move
}

// SetRef is a reference to a set, optionally scoped to one registry
// (draft-ietf-grow-rpsl-registry-scoped-members: "RIPE::AS-FOO"). It is opaque
// and canonical, as SetName is: the source is upper-cased, so every spelling of
// a reference is == and one map key. An unscoped ref leaves the choice of
// registry to the Source's precedence.
type SetRef struct {
	source string // "" or a canonical source name
	name   SetName
}

// Ref returns the unscoped reference to name.
func Ref(name SetName) SetRef { return SetRef{name: name} }

// NewSetRef returns name scoped to source, which ParseSourceName validates. An
// empty source gives the unscoped reference.
func NewSetRef(source string, name SetName) (SetRef, error) {
	if name.IsZero() {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference: no set name")
	}
	if source == "" {
		return Ref(name), nil
	}
	s, err := ParseSourceName(source)
	if err != nil {
		return SetRef{}, err
	}
	return SetRef{source: s, name: name}, nil
}

// ParseSetRef parses "AS-FOO" or "RIPE::AS-FOO". Surrounding whitespace is
// trimmed; whitespace around "::" is an error.
func ParseSetRef(s string) (SetRef, error) {
	t := strings.Trim(s, " \t")
	src, rest, scoped := strings.Cut(t, "::")
	if !scoped {
		n, err := ParseSetName(t)
		if err != nil {
			return SetRef{}, err
		}
		return Ref(n), nil
	}
	if rest == "" || rest[0] == ' ' || rest[0] == '\t' {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference %q", s)
	}
	n, err := ParseSetName(rest)
	if err != nil {
		return SetRef{}, err
	}
	if src == "" {
		return SetRef{}, fmt.Errorf("rpsl/types: invalid set reference %q: empty source", s)
	}
	return NewSetRef(src, n)
}

// Source returns the registry the reference is scoped to, "" when unscoped.
func (r SetRef) Source() string { return r.source }

// Name returns the set name.
func (r SetRef) Name() SetName { return r.name }

// IsScoped reports whether the reference names a registry.
func (r SetRef) IsScoped() bool { return r.source != "" }

// IsZero reports whether r is the zero SetRef.
func (r SetRef) IsZero() bool { return r.name.IsZero() }

// String returns "RIPE::AS-FOO", or "AS-FOO" when unscoped.
func (r SetRef) String() string {
	if r.source == "" {
		return r.name.String()
	}
	return r.source + "::" + r.name.String()
}
```

Note: `"RIPE::RADB::AS-FOO"` fails because `ParseSetName("RADB::AS-FOO")` rejects the empty component between the two colons.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd types && go test . && go test -run '^$' -fuzz FuzzParseSetRef -fuzztime 15s .`
Expected: PASS; fuzzing finds nothing.

- [ ] **Step 5: Check leaf isolation and commit**

Run: `cd types && go list -deps ./... | grep rkolesnichenko`
Expected: exactly `github.com/rkolesnichenko/rpsl/types`.

```bash
git add types/setref.go types/setref_test.go types/fuzz_test.go
git commit -m "types: add SetRef and ParseSourceName"
```

---

### Task 2: `object.ParseSrcMember` and `SetMember.Source`

**Files:**
- Modify: `object/members.go:42-49` (add the `Source` field and doc line; add `Ref`)
- Create: `object/srcmembers.go`
- Create: `object/srcmembers_test.go`
- Modify: `decode_fuzz_test.go` (root; add seeds) and create `object/srcmembers_fuzz_test.go`

**Interfaces:**
- Consumes: `types.SetRef`, `types.NewSetRef`, `types.Ref`, `types.ParseSourceName` (Task 1); `ParseSetMember`'s helpers `withLength` in `object/members.go`.
- Produces:
  - `SetMember.Source string` — the registry of a `MemberSet` from `src-members:`, `""` otherwise.
  - `func (m SetMember) Ref() types.SetRef` — for `MemberSet`; the zero `SetRef` for any other kind.
  - `func ParseSrcMember(item string, container types.SetClass) (SetMember, error)`

- [ ] **Step 1: Write the failing tests**

`object/srcmembers_test.go`:

```go
package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseSrcMember(t *testing.T) {
	as, rs := types.ClassAsSet, types.ClassRouteSet
	for _, tc := range []struct {
		item      string
		container types.SetClass
		kind      MemberKind
		ref       string // m.Ref().String() for sets, m.Range.String() for prefixes, m.AS.String() for ASNs
		op        string
		ok        bool
	}{
		// as-set (draft §2.1): an ASN or REG::as-set, no operators.
		{"AS65000", as, MemberAS, "AS65000", "", true},
		{"RIPE::AS-FOO", as, MemberSet, "RIPE::AS-FOO", "", true},
		{"ripe::as-foo", as, MemberSet, "RIPE::AS-FOO", "", true},
		{"AS-FOO", as, 0, "", "", false},           // a set needs a registry
		{"RIPE::RS-FOO", as, 0, "", "", false},     // an as-set lists as-sets
		{"192.0.2.0/24", as, 0, "", "", false},     // no prefixes in an as-set
		{"AS65000^24", as, 0, "", "", false},       // no operators in an as-set
		{"RIPE::AS-FOO^+", as, 0, "", "", false},
		// route-set (draft §2.2).
		{"192.0.2.0/24", rs, MemberPrefixRange, "192.0.2.0/24", "", true},
		{"192.0.2.0/24^+", rs, MemberPrefixRange, "192.0.2.0/24^+", "", true},
		{"RIPE::RS-FOO", rs, MemberSet, "RIPE::RS-FOO", "", true},
		{"RIPE::RS-FOO^24-32", rs, MemberSet, "RIPE::RS-FOO", "^24-32", true},
		{"RIPE::AS-FOO", rs, MemberSet, "RIPE::AS-FOO", "", true},
		{"AS65000", rs, MemberAS, "AS65000", "", true},
		{"RIPE::AS-FOO^+", rs, 0, "", "", false},   // no operator on a scoped as-set
		{"AS65000^24", rs, 0, "", "", false},       // no operator on an ASN
		{"RS-FOO", rs, 0, "", "", false},           // a set needs a registry
		{"RIPE::FLTR-FOO", rs, 0, "", "", false},   // not a class a route-set lists
		{"RI PE::RS-FOO", rs, 0, "", "", false},
		{"", rs, 0, "", "", false},
	} {
		m, err := ParseSrcMember(tc.item, tc.container)
		if (err == nil) != tc.ok {
			t.Errorf("ParseSrcMember(%q, %s) error = %v; want ok=%v", tc.item, tc.container, err, tc.ok)
			continue
		}
		if m.Raw != tc.item {
			t.Errorf("ParseSrcMember(%q).Raw = %q", tc.item, m.Raw)
		}
		if !tc.ok {
			if m.Kind != MemberInvalid {
				t.Errorf("ParseSrcMember(%q) failed but Kind = %s", tc.item, m.Kind)
			}
			continue
		}
		var got string
		switch m.Kind {
		case MemberSet:
			got = m.Ref().String()
		case MemberPrefixRange:
			got = m.Range.String()
		case MemberAS:
			got = m.AS.String()
		}
		op := ""
		if !m.Op.IsZero() {
			op = m.Op.String()
		}
		if m.Kind != tc.kind || got != tc.ref || op != tc.op {
			t.Errorf("ParseSrcMember(%q) = %s %q op %q; want %s %q op %q", tc.item, m.Kind, got, op, tc.kind, tc.ref, tc.op)
		}
	}
}

// TestParseSrcMemberIPv6IsAPrefix: "::" in an IPv6 prefix is not a registry
// separator (Review Focus 3).
func TestParseSrcMemberIPv6IsAPrefix(t *testing.T) {
	for _, item := range []string{"2001:db8::/32", "2001:db8::/32^+", "::/0^48", "2001:db8::1"} {
		m, err := ParseSrcMember(item, types.ClassRouteSet)
		if err != nil || m.Kind != MemberPrefixRange || m.Source != "" {
			t.Errorf("ParseSrcMember(%q) = %+v, %v; want an IPv6 prefix member", item, m, err)
		}
	}
	if _, err := ParseSrcMember("2001:db8::/32", types.ClassAsSet); err == nil {
		t.Error("an IPv6 prefix was accepted in an as-set's src-members")
	}
}

func TestSetMemberRef(t *testing.T) {
	m, _ := ParseSetMember("AS-FOO", types.ClassAsSet)
	if r := m.Ref(); r.IsScoped() || r.String() != "AS-FOO" {
		t.Errorf("members: AS-FOO Ref = %v", r)
	}
	s, _ := ParseSrcMember("RIPE::AS-FOO", types.ClassAsSet)
	if r := s.Ref(); r.Source() != "RIPE" || r.Name().String() != "AS-FOO" {
		t.Errorf("src-members: RIPE::AS-FOO Ref = %v", r)
	}
	a, _ := ParseSetMember("AS1", types.ClassAsSet)
	if !a.Ref().IsZero() {
		t.Errorf("an AS member's Ref is %v, want zero", a.Ref())
	}
}
```

`object/srcmembers_fuzz_test.go`:

```go
package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// FuzzParseSrcMember: never panics; an accepted set member's Ref round-trips
// through types.ParseSetRef, and a failed parse is MemberInvalid with Raw kept.
func FuzzParseSrcMember(f *testing.F) {
	for _, s := range []string{
		"RIPE::AS-FOO", "RIPE::RS-FOO^+", "2001:db8::/32", "AS1", "192.0.2.0/24^24-32",
		"ɐ::RS-X", "RIPE::ɐ", "::", "RIPE::RS-FOO^", "RIPE::AS-FOO^+",
	} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, item string, routeSet bool) {
		c := types.ClassAsSet
		if routeSet {
			c = types.ClassRouteSet
		}
		m, err := ParseSrcMember(item, c)
		if m.Raw != item {
			t.Fatalf("Raw = %q, want %q", m.Raw, item)
		}
		if err != nil {
			if m.Kind != MemberInvalid {
				t.Fatalf("ParseSrcMember(%q) failed with Kind %s", item, m.Kind)
			}
			return
		}
		if m.Kind == MemberSet {
			back, err := types.ParseSetRef(m.Ref().String())
			if err != nil || back != m.Ref() || !back.IsScoped() {
				t.Fatalf("ParseSrcMember(%q).Ref() = %v, parses back to %v, %v", item, m.Ref(), back, err)
			}
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestParseSrcMember|TestSetMemberRef' ./object`
Expected: FAIL — `undefined: ParseSrcMember`, `m.Ref undefined`.

- [ ] **Step 3: Implement**

In `object/members.go`, replace the struct at lines 42-49 with:

```go
type SetMember struct {
	Kind   MemberKind
	AS     types.ASN
	Set    types.SetName
	Source string // the registry of a MemberSet from src-members: ("RIPE"); "" from members:/mp-members:
	Range  types.PrefixRange
	Op     types.RangeOperator
	Raw    string
}

// Ref returns the reference a MemberSet names, scoped to Source when it has
// one, and the zero SetRef for a member of any other kind.
func (m SetMember) Ref() types.SetRef {
	if m.Kind != MemberSet {
		return types.SetRef{}
	}
	r, err := types.NewSetRef(m.Source, m.Set)
	if err != nil { // a hand-built member with a bad Source
		return types.SetRef{}
	}
	return r
}
```

Keep the existing doc comment above the struct and add one sentence to it: `Source is set only on a set member from src-members: (draft-ietf-grow-rpsl-registry-scoped-members).`

`object/srcmembers.go`:

```go
package object

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/rkolesnichenko/rpsl/types"
)

// ParseSrcMember parses one src-members: list item for a set of class
// container (draft-ietf-grow-rpsl-registry-scoped-members-00 §2.1, §2.2).
// An as-set lists an ASN or REG::as-set; a route-set also a prefix range and
// REG::route-set, which alone may carry a range operator. A set reference
// without a registry, a nested set of a class the container may not list, and
// an operator on an ASN or a scoped as-set are errors. On failure it returns a
// MemberInvalid member carrying Raw, as ParseSetMember does.
func ParseSrcMember(item string, container types.SetClass) (SetMember, error) {
	bad := SetMember{Raw: item}
	s := strings.TrimSpace(item)
	if s == "" || strings.ContainsFunc(s, unicode.IsSpace) {
		return bad, fmt.Errorf("invalid %s src-members item %q", container, item)
	}
	routeSet := container == types.ClassRouteSet
	// A prefix first: "2001:db8::/32" contains "::" too.
	if pr, err := types.ParsePrefixRange(withLength(s)); err == nil {
		if !routeSet {
			return bad, fmt.Errorf("prefix-range %q not valid in %s src-members", item, container)
		}
		return SetMember{Kind: MemberPrefixRange, Range: pr, Raw: item}, nil
	}
	base, opText, hasOp := strings.Cut(s, "^")
	var op types.RangeOperator
	if hasOp {
		o, err := types.ParseRangeOperator(opText)
		if err != nil {
			return bad, fmt.Errorf("invalid range operator in %s src-members item %q", container, item)
		}
		op = o
	}
	if as, err := types.ParseASN(base); err == nil {
		if hasOp {
			return bad, fmt.Errorf("range operator not valid on an AS number in src-members: %q", item)
		}
		return SetMember{Kind: MemberAS, AS: as, Raw: item}, nil
	}
	src, name, scoped := strings.Cut(base, "::")
	if !scoped {
		if _, err := types.ParseSetName(base); err == nil {
			return bad, fmt.Errorf("set %q in src-members needs a registry, as in RIPE::%s", item, base)
		}
		return bad, fmt.Errorf("invalid %s src-members item %q", container, item)
	}
	ref, err := types.ParseSetRef(src + "::" + name)
	if err != nil {
		return bad, fmt.Errorf("invalid %s src-members item %q: %v", container, item, err)
	}
	cls := ref.Name().Class()
	if !nestable(container, cls) {
		return bad, fmt.Errorf("%s src-members item %q is a %s", container, item, cls)
	}
	if hasOp && !(routeSet && cls == types.ClassRouteSet) {
		return bad, fmt.Errorf("range operator not valid on a scoped %s in src-members: %q", cls, item)
	}
	return SetMember{Kind: MemberSet, Set: ref.Name(), Source: ref.Source(), Op: op, Raw: item}, nil
}
```

(`nestable` is the existing unexported function in `object/members.go`: as-set lists as-sets; route-set lists route-sets and as-sets.)

In root `decode_fuzz_test.go`, add to `FuzzDecode`'s seed list:

```go
	f.Add("as-set: AS-X\nmembers: AS1, AS-Y\nsrc-members: RIPE::AS-Y, AS1, ARIN::AS-Y\nsource: RIPE\n")
	f.Add("route-set: RS-X\nmp-members: 2001:db8::/32, RS-Y\nsrc-members: 2001:db8::/32, RIPE::RS-Y^+, RIPE::AS-Z^+\nsource: RIPE\n")
```

(Place them beside the existing `f.Add` seeds; match their form — if the target seeds with `[]byte`, wrap in `[]byte(...)`.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./object && go test -run '^$' -fuzz FuzzParseSrcMember -fuzztime 15s ./object`
Expected: PASS; fuzzing finds nothing.

- [ ] **Step 5: Commit**

```bash
git add object/members.go object/srcmembers.go object/srcmembers_test.go object/srcmembers_fuzz_test.go decode_fuzz_test.go
git commit -m "object: parse src-members items"
```

---

### Task 3: Decode `src-members:`, diagnose it, and admit it in a profile

**Files:**
- Modify: `object/classes.go:318-374` (fields and decoders of `AsSet`, `RouteSet`)
- Modify: `object/sets.go:26-31, 55-90` (`Set` interface, `SetSrcMembers` methods)
- Modify: `object/srcmembers.go` (append `memberKey`, `keyOf`, `(*decoder).srcMembers`)
- Modify: `object/profiles.go` (append `WithSrcMembers`)
- Modify: `object/drift_test.go:94` and `:165` (marker, profile list)
- Create: `object/testdata/src-members-draft.txt`
- Create: `object/srcmembers_decode_test.go`
- Modify: `docs/diagnostics.md` (six rows)

**Interfaces:**
- Consumes: `ParseSrcMember`, `SetMember.Source` (Task 2).
- Produces:
  - `AsSet.SrcMembers []SetMember`, `RouteSet.SrcMembers []SetMember`
  - `Set` interface gains `SetSrcMembers() []SetMember` (a method named `SrcMembers` would clash with the field)
  - unexported `type memberKey struct{ kind MemberKind; as types.ASN; set types.SetName; rng types.PrefixRange }` and `func keyOf(m SetMember) (memberKey, bool)` — used again by Task 4
  - `func WithSrcMembers(p Profile) Profile`
  - rules `object/as-set-src-members`, `object/as-set-src-members-unlisted`, `object/as-set-src-members-conflict`, and the three `object/route-set-…` twins

- [ ] **Step 1: Add the draft's examples verbatim**

`object/testdata/src-members-draft.txt` (the figures of draft-ietf-grow-rpsl-registry-scoped-members-00, verbatim; `=== ` lines separate them and are not RPSL):

```
=== figure-1
route-set: RS-FIRST
members: RS-SECOND
mp-members: RS-LEGACY
src-members: RIPE::RS-SECOND
source: EXAMPLE

route-set: RS-SECOND
members: RS-THIRD
source: RIPE

route-set: RS-SECOND
members: AS65002
source: OTHER

route-set: RS-THIRD
members: AS65000
source: OTHER

route-set: RS-LEGACY
members: AS65001
source: OTHER
=== figure-2
route-set: RS-EXAMPLE
members: 192.0.2.0/24
mp-members: 2001:db8::/32
mp-members: RS-OTHER
src-members: 192.0.2.0/24, RIPE::RS-OTHER, 2001:db8::/32
source: EXAMPLE
=== figure-3
route-set: RS-EXAMPLE
members: 192.0.2.0/24
mp-members: 2001:db8::/36
mp-members: RS-OTHER, RS-MPMBRONLY
src-members: 192.0.2.0/24, RIPE::RS-OTHER
src-members: NTTCOM::RS-SRCMBRONLY, 2001:db8::/32
source: EXAMPLE
=== figure-4
as-set: AS-EXAMPLE
members: AS-OTHER
src-members: RIPE::AS-OTHER, ARIN::AS-OTHER
source: EXAMPLE
```

Figure 4 in the draft is a fragment (`src-members: RIPE::AS-OTHER, ARIN::AS-OTHER`); the `as-set:`, `members:` and `source:` lines around it are ours, so the fragment decodes as an object. Say so in a comment in the test that reads the file.

- [ ] **Step 2: Write the failing tests**

`object/srcmembers_decode_test.go`:

```go
package object

import (
	"os"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// draftFigures returns the objects of each figure in
// testdata/src-members-draft.txt, keyed "figure-N". Figure 4 is a fragment in
// the draft; the file wraps it in an as-set of ours.
func draftFigures(t *testing.T) map[string][]*ast.Object {
	t.Helper()
	b, err := os.ReadFile("testdata/src-members-draft.txt")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*ast.Object{}
	for _, block := range strings.Split(string(b), "=== ")[1:] {
		name, body, _ := strings.Cut(block, "\n")
		for _, text := range strings.Split(strings.TrimSpace(body), "\n\n") {
			out[name] = append(out[name], parse(text+"\n"))
		}
	}
	return out
}

func rulesOf(diags []ast.Diagnostic) map[string]int {
	m := map[string]int{}
	for _, d := range diags {
		m[d.Rule]++
	}
	return m
}

func TestDraftFigure2DecodesClean(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-2"][0])
	if len(diags) != 0 {
		t.Fatalf("figure 2 diagnostics: %+v", diags)
	}
	rs := obj.(RouteSet)
	if len(rs.SrcMembers) != 3 || rs.SrcMembers[1].Ref().String() != "RIPE::RS-OTHER" {
		t.Errorf("figure 2 SrcMembers = %+v", rs.SrcMembers)
	}
}

func TestDraftFigure3IsUnlistedTwice(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-3"][0])
	r := rulesOf(diags)
	if r["object/route-set-src-members-unlisted"] != 2 || len(diags) != 2 {
		t.Fatalf("figure 3 diagnostics = %+v; want exactly two unlisted warnings", diags)
	}
	for _, d := range diags {
		if d.Severity != ast.Warning {
			t.Errorf("%s is %v, want Warning", d.Rule, d.Severity)
		}
		if !strings.Contains(d.Message, "RS-SRCMBRONLY") && !strings.Contains(d.Message, "2001:db8::/32") {
			t.Errorf("unexpected unlisted item: %s", d.Message)
		}
	}
	if n := len(obj.(RouteSet).SrcMembers); n != 4 { // unlisted members are kept: the resolver follows them
		t.Errorf("figure 3 kept %d SrcMembers, want 4", n)
	}
}

func TestDraftFigure4IsAConflict(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-4"][0])
	if rulesOf(diags)["object/as-set-src-members-conflict"] != 2 {
		t.Fatalf("figure 4 diagnostics = %+v; want a conflict error at each of the two items", diags)
	}
	if n := len(obj.(AsSet).SrcMembers); n != 0 {
		t.Errorf("figure 4 kept %d SrcMembers; both conflicting entries must be dropped", n)
	}
}

func TestSrcMembersDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, src, rule string }{
		{"unscoped set", "as-set: AS-X\nmembers: AS-Y\nsrc-members: AS-Y\n", "object/as-set-src-members"},
		{"operator on ASN", "route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1^24\n", "object/route-set-src-members"},
		{"prefix in as-set", "as-set: AS-X\nsrc-members: 192.0.2.0/24\n", "object/as-set-src-members"},
	} {
		_, diags := Decode(parse(tc.src))
		if rulesOf(diags)[tc.rule] != 1 {
			t.Errorf("%s: diagnostics = %+v; want one %s", tc.name, diags, tc.rule)
		}
	}
}

func TestSrcMembersSameRegistryTwiceIsKeptOnce(t *testing.T) {
	obj, diags := Decode(parse("as-set: AS-X\nmembers: AS-Y\nsrc-members: RIPE::AS-Y, ripe::as-y\n"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	if n := len(obj.(AsSet).SrcMembers); n != 1 {
		t.Errorf("kept %d, want 1", n)
	}
}

func TestSrcMembersKeyIgnoresOperatorOnASN(t *testing.T) {
	// members: AS1^24 lists AS1 (spec §5.2), so src-members: AS1 is not unlisted.
	_, diags := Decode(parse("route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1\n"))
	if len(diags) != 0 {
		t.Errorf("diagnostics: %+v", diags)
	}
}

func TestWithSrcMembers(t *testing.T) {
	p := WithSrcMembers(RIPE)
	if p.Name() != "RIPE+src-members" {
		t.Errorf("Name = %q", p.Name())
	}
	for _, class := range []string{"as-set", "route-set"} {
		spec, _ := p.Class(class)
		if a, ok := spec.Attrs["src-members"]; !ok || a.Required || a.Single {
			t.Errorf("%s src-members spec = %+v, %v; want optional, multi-valued", class, a, ok)
		}
		orig, _ := RIPE.Class(class)
		if _, ok := orig.Attrs["src-members"]; ok {
			t.Errorf("WithSrcMembers changed RIPE's own %s table", class)
		}
	}
	o := parse("as-set: AS-X\nmembers: AS-Y\nsrc-members: RIPE::AS-Y\ntech-c: X-RIPE\nadmin-c: X-RIPE\nmnt-by: M\nsource: RIPE\n")
	if r := rulesOf(RIPE.Validate(o)); r["dict/unknown-attr"] != 1 {
		t.Errorf("RIPE did not flag src-members: %v", r)
	}
	if r := rulesOf(p.Validate(o)); r["dict/unknown-attr"] != 0 {
		t.Errorf("RIPE+src-members flagged src-members: %v", r)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test -run 'TestDraftFigure|TestSrcMembers|TestWithSrcMembers' ./object`
Expected: FAIL — `rs.SrcMembers undefined`, `undefined: WithSrcMembers`.

- [ ] **Step 4: Implement**

In `object/classes.go`, add `SrcMembers []SetMember // src-members: (draft-ietf-grow-rpsl-registry-scoped-members)` after `MpMembers` in both `AsSet` and `RouteSet`, and rewrite the two decoders:

```go
func decodeAsSet(d *decoder) AsSet {
	members := d.members("members", "object/as-set-members", types.ClassAsSet)
	mp := d.members("mp-members", "object/as-set-mp-members", types.ClassAsSet)
	return AsSet{
		Common:     d.common("as-set"),
		Registry:   d.registry("as-set"),
		Name:       d.setKey("as-set", "object/as-set-name", types.ClassAsSet),
		Members:    members,
		MpMembers:  mp,
		SrcMembers: d.srcMembers("object/as-set-src-members", types.ClassAsSet, members, mp),
		MbrsByRef:  d.list("mbrs-by-ref"),
		raw:        d.o,
	}
}
```

and the same for `decodeRouteSet` with `"route-set"`, `types.ClassRouteSet` and rule `"object/route-set-src-members"`. (Decoding order does not change diagnostics order visibly: each diagnostic carries its span; `Decode` sorts or not exactly as today — check `TestDecode*` stay green.)

In `object/sets.go`, add to the `Set` interface:

```go
	SetSrcMembers() []SetMember // src-members:, as written (draft-ietf-grow-rpsl-registry-scoped-members)
```

and the two methods beside `SetMembers`:

```go
// SetSrcMembers returns the as-set's src-members:, as written.
func (s AsSet) SetSrcMembers() []SetMember { return append([]SetMember(nil), s.SrcMembers...) }

// SetSrcMembers returns the route-set's src-members:, as written.
func (s RouteSet) SetSrcMembers() []SetMember { return append([]SetMember(nil), s.SrcMembers...) }
```

Append to `object/srcmembers.go` (add `"github.com/rkolesnichenko/rpsl/ast"` to its imports):

```go
// memberKey is a member's primary key with the registry removed (spec §5.2):
// the set name, the AS number, or the prefix range itself. The draft compares
// members by it (§2.3 step 2, §3.1, §3.3).
type memberKey struct {
	kind MemberKind
	as   types.ASN
	set  types.SetName
	rng  types.PrefixRange
}

// keyOf returns m's key, and false for a MemberInvalid member.
func keyOf(m SetMember) (memberKey, bool) {
	switch m.Kind {
	case MemberAS:
		return memberKey{kind: MemberAS, as: m.AS}, true
	case MemberSet:
		return memberKey{kind: MemberSet, set: m.Set}, true
	case MemberPrefixRange:
		return memberKey{kind: MemberPrefixRange, rng: m.Range}, true
	}
	return memberKey{}, false
}

// srcMembers decodes src-members: for a set of class container whose
// members:/mp-members: are listed. An item that does not parse is an Error
// (rule) and left out. One set name under two registries (§3.3) is an Error at
// each item (rule-conflict), and both are left out, so the name resolves
// through members: by precedence. An item missing from members:/mp-members:
// (§3.1) is a Warning (rule-unlisted) and kept: the resolver follows it. An
// item repeated under the same registry is kept once.
func (d *decoder) srcMembers(rule string, container types.SetClass, listed ...[]SetMember) []SetMember {
	type parsed struct {
		m  SetMember
		it listItem
	}
	var ps []parsed
	registries := map[types.SetName]map[string]bool{}
	for _, it := range d.listItems("src-members") {
		m, err := ParseSrcMember(it.Value, container)
		if err != nil {
			d.diagAt(ast.Error, it.span(), rule, err.Error())
			continue
		}
		ps = append(ps, parsed{m, it})
		if m.Kind == MemberSet {
			if registries[m.Set] == nil {
				registries[m.Set] = map[string]bool{}
			}
			registries[m.Set][m.Source] = true
		}
	}
	in := map[memberKey]bool{}
	for _, l := range listed {
		for _, m := range l {
			if k, ok := keyOf(m); ok {
				in[k] = true
			}
		}
	}
	var out []SetMember
	kept := map[memberKey]bool{}
	for _, p := range ps {
		if p.m.Kind == MemberSet && len(registries[p.m.Set]) > 1 {
			d.diagAt(ast.Error, p.it.span(), rule+"-conflict", fmt.Sprintf(
				"%s is named under %d registries; src-members: may name a set once (draft-ietf-grow-rpsl-registry-scoped-members §3.3), so it is resolved through members: instead",
				p.m.Set, len(registries[p.m.Set])))
			continue
		}
		k, _ := keyOf(p.m)
		if !in[k] {
			d.diagAt(ast.Warning, p.it.span(), rule+"-unlisted", fmt.Sprintf(
				"src-members: item %q is not in members: or mp-members: (draft-ietf-grow-rpsl-registry-scoped-members §3.1); it is still resolved",
				p.it.Value))
		}
		if !kept[k] {
			kept[k] = true
			out = append(out, p.m)
		}
	}
	return out
}
```

Append to `object/profiles.go`:

```go
// WithSrcMembers returns p that also admits src-members: (optional,
// multi-valued) on as-set and route-set, named p.Name()+"+src-members".
// draft-ietf-grow-rpsl-registry-scoped-members adds the attribute; no registry
// has deployed it yet, so the built-in profiles, each pinned to what its
// registry runs, leave it out.
func WithSrcMembers(p Profile) Profile {
	classes := make(map[string]ClassSpec, len(p.classes))
	for class, spec := range p.classes {
		c := spec.clone()
		if class == "as-set" || class == "route-set" {
			if c.Attrs == nil {
				c.Attrs = map[string]AttrSpec{}
			}
			c.Attrs["src-members"] = AttrSpec{}
		}
		classes[class] = c
	}
	return Profile{name: p.name + "+src-members", classes: classes}
}
```

In `object/drift_test.go`: line 94 becomes `case "members", "mp-members", "src-members":`; the profile list at line 165 becomes `[]Profile{RIPE, RFCStrict, IRRd, ARIN, WithSrcMembers(RFCStrict)}`. If `TestAttributeTypesAgreeAcrossClasses` iterates a profile list, add `WithSrcMembers(RFCStrict)` there too.

In `docs/diagnostics.md`, add six rows in the same table and format as the existing `object/as-set-members` rows (rule, severity, meaning):

| Rule | Severity | Meaning |
|---|---|---|
| `object/as-set-src-members` | Error | A src-members: item that does not parse: a set without a registry, an operator, a prefix |
| `object/as-set-src-members-unlisted` | Warning | A src-members: item not in members:/mp-members: (draft §3.1); still resolved |
| `object/as-set-src-members-conflict` | Error | One set name under two registries (draft §3.3); both left out |
| `object/route-set-src-members` | Error | As for as-set; an operator is allowed only on a prefix range and a scoped route-set |
| `object/route-set-src-members-unlisted` | Warning | As for as-set |
| `object/route-set-src-members-conflict` | Error | As for as-set |

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./object ./... && go test -run 'TestRoundTrip|TestStreamRoundTrip' .`
Expected: PASS, including `TestEveryAttributeLandsInItsOwnField` and `TestDiagnosticRulesAreDocumented` (root module).

- [ ] **Step 6: Commit**

```bash
git add object/ docs/diagnostics.md
git commit -m "object: decode src-members, diagnose it per the draft, WithSrcMembers"
```

---

### Task 4: `object.DirectMembers`

**Files:**
- Modify: `object/srcmembers.go` (append `DirectMembers`)
- Modify: `object/srcmembers_test.go` (append tests)

**Interfaces:**
- Consumes: `memberKey`, `keyOf`, `Set.SetSrcMembers` (Task 3).
- Produces: `func DirectMembers(s Set) []SetMember` — what the engine (Task 5) follows.

- [ ] **Step 1: Write the failing tests**

Append to `object/srcmembers_test.go`:

```go
func refsOf(ms []SetMember) []string {
	var out []string
	for _, m := range ms {
		switch m.Kind {
		case MemberSet:
			s := m.Ref().String()
			if !m.Op.IsZero() {
				s += m.Op.String()
			}
			out = append(out, s)
		case MemberAS:
			s := m.AS.String()
			if !m.Op.IsZero() {
				s += m.Op.String()
			}
			out = append(out, s)
		case MemberPrefixRange:
			out = append(out, m.Range.String())
		}
	}
	return out
}

func TestDirectMembers(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"no src-members", "route-set: RS-X\nmembers: RS-A, AS1\n", []string{"RS-A", "AS1"}},
		{"draft figure 1", "route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\n",
			[]string{"RIPE::RS-SECOND", "RS-LEGACY"}},
		{"src operator wins", "route-set: RS-X\nmembers: RS-Y^-\nsrc-members: RIPE::RS-Y^+\n", []string{"RIPE::RS-Y^+"}},
		{"ASN key ignores operator", "route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1\n", []string{"AS1"}},
		{"prefix key keeps operator", "route-set: RS-X\nmembers: 192.0.2.0/24^+\nsrc-members: 192.0.2.0/24\n",
			[]string{"192.0.2.0/24", "192.0.2.0/24^+"}},
		{"unlisted is followed", "as-set: AS-X\nmembers: AS1\nsrc-members: RIPE::AS-Z\n", []string{"RIPE::AS-Z", "AS1"}},
		{"conflict falls back to members", "as-set: AS-X\nmembers: AS-O\nsrc-members: RIPE::AS-O, ARIN::AS-O\n", []string{"AS-O"}},
	} {
		obj, _ := Decode(parse(tc.src))
		got := refsOf(DirectMembers(obj.(Set)))
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s: DirectMembers = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A set built by hand, bypassing the decoder, gets the same conflict rule.
func TestDirectMembersConflictOnHandBuiltSet(t *testing.T) {
	o, _ := ParseSetMember("AS-O", types.ClassAsSet)
	a, _ := ParseSrcMember("RIPE::AS-O", types.ClassAsSet)
	b, _ := ParseSrcMember("ARIN::AS-O", types.ClassAsSet)
	set := AsSet{Members: []SetMember{o}, SrcMembers: []SetMember{a, b}}
	if got := refsOf(DirectMembers(set)); strings.Join(got, " ") != "AS-O" {
		t.Errorf("DirectMembers = %v, want [AS-O]", got)
	}
}
```

(Add `"strings"` to the test file's imports.)

- [ ] **Step 2: Run to verify failure**

Run: `go test -run TestDirectMembers ./object`
Expected: FAIL — `undefined: DirectMembers`.

- [ ] **Step 3: Implement**

Append to `object/srcmembers.go`:

```go
// DirectMembers returns the members a resolver follows
// (draft-ietf-grow-rpsl-registry-scoped-members §2.3 steps 1-2): every
// src-members: member, then each members:/mp-members: member whose key (spec
// §5.2) no src-members: member has. A set name under two registries in
// src-members: is left out of it, as the decoder leaves it out, so that name
// is followed through members:. It reads one object and does no I/O.
func DirectMembers(s Set) []SetMember {
	src, listed := s.SetSrcMembers(), s.SetMembers()
	if len(src) == 0 {
		return listed
	}
	registries := map[types.SetName]map[string]bool{}
	for _, m := range src {
		if m.Kind == MemberSet {
			if registries[m.Set] == nil {
				registries[m.Set] = map[string]bool{}
			}
			registries[m.Set][m.Source] = true
		}
	}
	have := map[memberKey]bool{}
	out := make([]SetMember, 0, len(src)+len(listed))
	for _, m := range src {
		if m.Kind == MemberSet && len(registries[m.Set]) > 1 {
			continue
		}
		if k, ok := keyOf(m); ok && !have[k] {
			have[k] = true
			out = append(out, m)
		}
	}
	for _, m := range listed {
		if k, ok := keyOf(m); ok && have[k] {
			continue
		}
		out = append(out, m)
	}
	return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./object`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add object/srcmembers.go object/srcmembers_test.go
git commit -m "object: DirectMembers applies the draft's member selection"
```

---

### Task 5: The `Source` break — the engine keys everything by `types.SetRef`

This is the one breaking change to `resolve.Source` (spec §6). Every implementer and caller in the repo moves in this task, so the tree compiles at the end of it. Backends get scoped lookups for real in Tasks 6-8; until then `MemSource`, `irrd.Source` and `whois.Source` *refuse* a scoped ref with an error (loud, never a silent precedence answer).

**Files:**
- Modify: `resolve/source.go` (interface, `ErrNotFound`, `SetTooLargeError.Name`)
- Modify: `resolve/expander.go` (entry points, discovery, `checkSet`, `members`, `nestedNames`→`nestedRefs`, `ordered`, evaluator)
- Modify: `resolve/expand_more.go` (`ExpandRouters`, `ExpandPeerings`, `ExpandFilterSet`, `filterEval`)
- Modify: `resolve/result.go` (`Missing()` types, `sortedNames`→`sortedRefs`)
- Modify: `resolve/cache.go` (`GetSet`, claim keys)
- Modify: `resolve/memsource.go:84-90` (`GetSet` signature; refuse scoped)
- Modify: `resolve/rpki/filter.go:40-42`
- Modify: `resolve/irrd/irrd.go:177` and `resolve/whois/whois.go:102` (signature; refuse scoped)
- Modify: `resolve/internal/rpslq/sources.go`, `resolve/internal/rpslq/rpslq.go` (call sites, `warnMissing`)
- Modify: `examples/bulk-ripe/bulk/bulk.go` and every `*_test.go` / `example_test.go` calling the changed APIs (mechanical, Step 5)
- Create: `resolve/scoped_test.go`

**Interfaces:**
- Consumes: `types.SetRef`, `types.Ref` (Task 1); `object.DirectMembers`, `SetMember.Ref` (Tasks 2, 4).
- Produces (later tasks and all callers rely on these exact signatures):
  - `Source.GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error)`
  - `(*Expander).ExpandAS(ctx, types.SetRef) (ASNSet, error)`, `ExpandPrefixRanges(ctx, types.SetRef) (RangeSet, error)`, `ExpandPrefixes(ctx, types.SetRef) (PrefixSet, error)`, `ExpandRouters(ctx, types.SetRef) (RouterSet, error)`, `ExpandPeerings(ctx, types.SetRef) (PeeringSet, error)`, `ExpandFilterSet(ctx, types.SetRef) (RangeSet, error)`
  - `Missing() []types.SetRef` on `ASNSet`, `PrefixSet`, `RangeSet`, `RouterSet`, `PeeringSet`
  - `SetTooLargeError.Name types.SetRef`; `AnySetError.Name` stays `types.SetName`
  - `ErrNotFound` message `"resolve: not found"` (same value)

- [ ] **Step 1: Write the failing engine tests**

`resolve/scoped_test.go`:

```go
package resolve_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// refSource answers GetSet from sets keyed by SetRef.String(): "RIPE::RS-B"
// answers only the scoped lookup, "RS-B" only the unscoped one. It records
// every lookup, and serves routes from a fixed table.
type refSource struct {
	sets   map[string]object.NamedSet
	routes map[types.ASN][]netip.Prefix
	calls  []string
}

func newRefSource(t *testing.T, sets map[string]string, routes map[types.ASN]string) *refSource {
	t.Helper()
	s := &refSource{sets: map[string]object.NamedSet{}, routes: map[types.ASN][]netip.Prefix{}}
	for key, text := range sets {
		objs := decodeAll(t, []string{text})
		s.sets[key] = objs[0].(object.NamedSet)
	}
	for as, p := range routes {
		s.routes[as] = append(s.routes[as], netip.MustParsePrefix(p))
	}
	return s
}

func (s *refSource) GetSet(_ context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.calls = append(s.calls, ref.String())
	if set, ok := s.sets[ref.String()]; ok {
		return set, nil
	}
	return nil, resolve.ErrNotFound
}

func (s *refSource) OriginatedRoutes(_ context.Context, as types.ASN, _ types.AFI) ([]netip.Prefix, error) {
	return s.routes[as], nil
}

func (s *refSource) MembersByRef(context.Context, object.NamedSet) ([]object.Object, error) { return nil, nil }

func mustRef(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatalf("ParseSetRef(%q): %v", s, err)
	}
	return r
}

func refStrings(rs []types.SetRef) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return out
}

// The draft's Figure 1: RS-FIRST resolves to AS65000's and AS65001's routes,
// and OTHER's RS-SECOND is never looked up.
func TestDraftFigure1Engine(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"RS-FIRST":        "route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\nsource: EXAMPLE\n",
		"RIPE::RS-SECOND": "route-set: RS-SECOND\nmembers: RS-THIRD\nsource: RIPE\n",
		"RS-SECOND":       "route-set: RS-SECOND\nmembers: AS65002\nsource: OTHER\n",
		"RS-THIRD":        "route-set: RS-THIRD\nmembers: AS65000\nsource: OTHER\n",
		"RS-LEGACY":       "route-set: RS-LEGACY\nmembers: AS65001\nsource: OTHER\n",
	}, map[types.ASN]string{65000: "10.0.0.0/24", 65001: "10.0.1.0/24", 65002: "10.0.2.0/24"})
	got, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), mustRef(t, "RS-FIRST"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/24 10.0.1.0/24]" {
		t.Errorf("RS-FIRST = %v, want [10.0.0.0/24 10.0.1.0/24]", got)
	}
	if slices.Contains(src.calls, "RS-SECOND") {
		t.Errorf("OTHER's RS-SECOND was looked up: %v", src.calls)
	}
}

// Review Focus 1: a scoped miss never falls back to the unscoped copy.
func TestScopedMissDoesNotFallBack(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"RS-TOP": "route-set: RS-TOP\nmembers: RS-B\nsrc-members: RIPE::RS-B\nsource: EXAMPLE\n",
		"RS-B":   "route-set: RS-B\nmembers: 10.0.0.0/8\nsource: OTHER\n",
	}, nil)
	got, err := (&resolve.Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 0 || !slices.Equal(refStrings(got.Missing()), []string{"RIPE::RS-B"}) {
		t.Errorf("RS-TOP = %v missing %v; want nothing, missing [RIPE::RS-B]", got, got.Missing())
	}
	if slices.Contains(src.calls, "RS-B") {
		t.Errorf("the unscoped RS-B was looked up: %v", src.calls)
	}
}

// Review Focus 2: a Source that answers a scoped lookup from another registry
// fails the expansion.
func TestCheckSetRefusesWrongRegistry(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-TOP":      "as-set: AS-TOP\nmembers: AS-B\nsrc-members: RIPE::AS-B\nsource: EXAMPLE\n",
		"RIPE::AS-B":  "as-set: AS-B\nmembers: AS1\nsource: OTHER\n", // wrong registry
	}, nil)
	_, err := (&resolve.Expander{Src: src}).ExpandAS(context.Background(), mustRef(t, "AS-TOP"))
	if err == nil || !strings.Contains(err.Error(), "RIPE::AS-B") || !strings.Contains(err.Error(), "OTHER") {
		t.Fatalf("err = %v; want a refusal naming RIPE::AS-B and OTHER", err)
	}
	if errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a wrong-registry answer is a Source fault, not a missing set: %v", err)
	}
}

// Review Focus 5: one name reached scoped and unscoped is two nodes.
func TestSameNameTwoScopes(t *testing.T) {
	// RS-TOP reaches RS-A scoped (src-members:) and, through RS-B, unscoped.
	src := newRefSource(t, map[string]string{
		"RS-TOP":     "route-set: RS-TOP\nmembers: RS-A, RS-B\nsrc-members: RIPE::RS-A\nsource: EXAMPLE\n",
		"RIPE::RS-A": "route-set: RS-A\nmembers: 10.0.0.0/8\nsource: RIPE\n",
		"RS-A":       "route-set: RS-A\nmembers: 172.16.0.0/12\nsource: RADB\n",
		"RS-B":       "route-set: RS-B\nmembers: RS-A\nsource: RADB\n",
	}, nil)
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/8 172.16.0.0/12]" {
		t.Errorf("RS-TOP = %v; want both copies of RS-A", got)
	}
	delete(src.sets, "RS-A")
	got, err = e.ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/8]" || !slices.Equal(refStrings(got.Missing()), []string{"RS-A"}) {
		t.Errorf("RS-TOP = %v missing %v; want [10.0.0.0/8] missing [RS-A]", got, got.Missing())
	}
}

func TestScopedTop(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-X":       "as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"RIPE::AS-X": "as-set: AS-X\nmembers: AS1, AS-Y\nsource: RIPE\n",
		"AS-Y":       "as-set: AS-Y\nmembers: AS3\nsource: RADB\n",
	}, nil)
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustRef(t, "RIPE::AS-X"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[AS1 AS3]" {
		t.Errorf("RIPE::AS-X = %v, want [AS1 AS3]", got)
	}
	if slices.Contains(src.calls, "RIPE::AS-Y") || !slices.Contains(src.calls, "AS-Y") {
		t.Errorf("the scope cascaded: %v", src.calls)
	}
	_, err = e.ExpandAS(context.Background(), mustRef(t, "ARIN::AS-X"))
	if !errors.Is(err, resolve.ErrNotFound) || !strings.Contains(err.Error(), "ARIN::AS-X") {
		t.Errorf("missing scoped top: err = %v", err)
	}
}

func TestCacheKeysScopes(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-X":       "as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"RIPE::AS-X": "as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
	}, nil)
	c := resolve.NewCache(src, 0)
	a, _ := c.GetSet(context.Background(), mustRef(t, "RIPE::AS-X"))
	b, _ := c.GetSet(context.Background(), mustRef(t, "AS-X"))
	if a.SetSource() != "RIPE" || b.SetSource() != "RADB" {
		t.Errorf("Cache mixed scopes: %q, %q", a.SetSource(), b.SetSource())
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go vet ./... 2>&1 | head`
Expected: compile errors — `refSource does not implement resolve.Source (wrong type for method GetSet)`.

- [ ] **Step 3: Change the core engine**

`resolve/source.go`:
- `var ErrNotFound = errors.New("resolve: not found")`; its doc: "returned by a Source when a requested object does not exist".
- `SetTooLargeError.Name` becomes `types.SetRef`; `Error()` is unchanged in text (`e.Name.IsZero()`, `%s` of `e.Name`).
- The interface method becomes (doc from spec §6.1, verbatim):

```go
	// GetSet fetches the set ref names. An unscoped ref is resolved by the
	// Source's precedence. A scoped ref is resolved only in that registry —
	// any registry the Source holds, even one its default list leaves out —
	// and a registry it does not know is ErrNotFound
	// (draft-ietf-grow-rpsl-registry-scoped-members §2.3 step 1). For a scoped
	// ref the returned set's SetSource() must be ref.Source(). It returns
	// ErrNotFound (wrapped is fine) when the set does not exist; a nil set with
	// a nil error is treated the same way.
	GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error)
```

- Add to `OriginatedRoutes`' doc: `Routes are never scoped: a scoped set's member ASes' routes come from the default precedence, as bgpq4 does for SOURCE::SET.`

`resolve/expander.go` — replace name-keyed state with ref-keyed state:

```go
// setGraph is the part of the IRR reachable from one top-level set.
type setGraph struct {
	top     types.SetRef
	nodes   map[types.SetRef]*setNode    // fetched sets, by the reference that reached them
	missing []types.SetRef               // nested sets that were not found
	routes  map[types.ASN][]netip.Prefix // originated routes (prefix expansions only)
	ex      excluded                     // what the expansion leaves out
}
```

```go
// discover fetches every set reachable from top breadth-first, so each set is
// fetched once and first reached at its shortest distance. It follows only the
// nested sets RFC 2622 allows (see nestable), so from an as-set only as-sets. A
// reference scoped to a registry is its own node: RIPE::AS-X and AS-X are
// fetched separately (the scope selects where, draft §2.3, and never
// cascades: a node's nested references come from its own object).
func (e *Expander) discover(ctx context.Context, top types.SetRef) (*setGraph, error) {
	g := &setGraph{top: top, nodes: map[types.SetRef]*setNode{}, ex: e.excluded()}
	seen := map[types.SetRef]bool{top: true}
	for level, depth := []types.SetRef{top}, 0; len(level) > 0; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, n := range level {
			if isAnySet(n.Name()) {
				return nil, &AnySetError{Name: n.Name()}
			}
		}
		got, err := e.fetchLevel(ctx, level)
		if err != nil {
			return nil, err
		}
		var next []types.SetRef
		for i, n := range level {
			res := got[i]
			if res.err != nil {
				if !errors.Is(res.err, ErrNotFound) {
					return nil, res.err
				}
				if depth == 0 {
					return nil, fmt.Errorf("expand %s: %w", top, ErrNotFound)
				}
				g.missing = append(g.missing, n)
				continue
			}
			g.nodes[n] = &setNode{set: res.set, claims: res.claims}
			for _, ref := range nestedRefs(res.set) {
				if seen[ref] || g.ex.set(ref.Name()) {
					continue
				}
				if depth+1 > e.maxDepth() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitDepth, Max: e.maxDepth(), Count: depth + 1}
				}
				if len(seen) >= e.maxVisited() {
					return nil, &SetTooLargeError{Name: top, Limit: LimitVisited, Max: e.maxVisited(), Count: len(seen) + 1}
				}
				seen[ref] = true
				next = append(next, ref)
			}
		}
		level = next
	}
	sort.Slice(g.missing, func(i, j int) bool { return g.missing[i].String() < g.missing[j].String() })
	return g, nil
}
```

`fetchLevel(ctx, refs []types.SetRef)` and `fetchOne(ctx, ref types.SetRef)` change only their parameter types (`go func(i int, ref types.SetRef)`); `fetchOne` calls `e.Src.GetSet(ctx, ref)` and `checkSet(ref, set)`.

```go
// checkSet returns set, as a value, if it is the set ref asks for. A set of
// another name, or for a scoped ref one from another registry, is a fault of
// the Source, which has answered a different question: a backend that ignored
// the scope must not be expanded as if it had honoured it. A set whose class
// is not the one its name denotes ("route-set: AS-EVIL") is invalid data, and
// is treated as not found: expanded under its name's rules it would let an
// as-set pull in prefixes, or claims, that its class does not allow.
func checkSet(ref types.SetRef, set object.NamedSet) (object.NamedSet, error) {
	if set == nil {
		return nil, ErrNotFound // a Source that returns neither a set nor an error
	}
	set = setValue(set)
	name := ref.Name()
	if got := set.SetName(); got != name {
		return nil, fmt.Errorf("resolve: asked for %s, the Source returned %s", ref, got)
	}
	if ref.IsScoped() && !equalFoldASCII(strings.TrimSpace(set.SetSource()), ref.Source()) {
		return nil, fmt.Errorf("resolve: asked for %s, the Source returned %s from %q", ref, name, set.SetSource())
	}
	if set.Class() != name.Class().String() {
		return nil, fmt.Errorf("resolve: %s is a %s: %w", ref, set.Class(), ErrNotFound)
	}
	return set, nil
}
```

(Add `"strings"` to expander.go's imports; `equalFoldASCII` is in `claims.go`.)

```go
// ordered returns the graph's nodes in a stable order — the top set first,
// then the rest by reference — so a result built by walking them does not
// depend on map iteration order.
func (g *setGraph) ordered() []*setNode {
	refs := make([]types.SetRef, 0, len(g.nodes))
	for r := range g.nodes {
		if r != g.top {
			refs = append(refs, r)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	out := make([]*setNode, 0, len(g.nodes))
	if nd, ok := g.nodes[g.top]; ok {
		out = append(out, nd)
	}
	for _, r := range refs {
		out = append(out, g.nodes[r])
	}
	return out
}

// members returns the members a resolver follows of a set whose members are
// ASNs, prefix ranges and nested sets — an as-set or a route-set — src-members:
// first (object.DirectMembers), and nothing for any other class.
func members(set object.NamedSet) []object.SetMember {
	if s, ok := set.(object.Set); ok {
		return object.DirectMembers(s)
	}
	return nil
}
```

Rename `nestedNames` to `nestedRefs`, returning `[]types.SetRef`: the `object.Set` case iterates `object.DirectMembers(s)` and appends `m.Ref()` when `m.Kind == object.MemberSet && nestable(parent, m.Set.Class()) && !m.Ref().IsZero()`; the `RouterSet` case appends `types.Ref(m.Set)`; the `PeeringGroup` case `types.Ref(ref.Name)`. Keep its doc and add: `A src-members: reference is scoped (object.DirectMembers); every other is not.`

Evaluator:

```go
type evalState struct {
	set types.SetRef
	ops opStack
}

func (v *evaluator) walk(ref types.SetRef, ops opStack) error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	v.done[evalState{ref, ops}] = true
	if v.visits++; v.visits > v.e.maxVisited() {
		return &SetTooLargeError{Name: v.g.top, Limit: LimitVisited, Max: v.e.maxVisited(), Count: v.visits}
	}
	nd := v.g.nodes[ref]
	for _, m := range members(nd.set) {
		switch m.Kind {
		case object.MemberPrefixRange:
			if err := v.add(m.Range, &ops); err != nil {
				return err
			}
		case object.MemberAS:
			if err := v.addRoutes(v.g.routes[m.AS], ops.push(m.Op)); err != nil {
				return err
			}
		case object.MemberSet:
			if !nestable(ref.Name().Class(), m.Set.Class()) {
				continue // e.g. a route-set listed in an as-set, even if reachable elsewhere
			}
			if v.g.ex.set(m.Set) {
				continue // excluded, even the top set listing itself
			}
			child := m.Ref()
			if _, ok := v.g.nodes[child]; !ok {
				continue // missing (reported)
			}
			next := ops.push(m.Op)
			if v.done[evalState{child, next}] {
				continue // already walked, or on the current path: its ranges are already counted
			}
			if err := v.walk(child, next); err != nil {
				return err
			}
		}
	}
	// … the claims loop is unchanged …
}
```

Entry points: `ExpandAS(ctx, ref types.SetRef)`, `expandAS(ctx, ref)`, `ExpandPrefixRanges(ctx, ref)`, `expandRanges(ctx, ref, maxRanges)`, `ExpandPrefixes(ctx, ref)`: each class check reads `ref.Name().Class()` and names `ref` in its error; `discover(ctx, ref)`; `v.walk(ref, opStack{})`. Add to each doc comment: `A scoped ref (RIPE::AS-FOO) looks the named set up in that registry only; the scope does not cascade to what it lists.`

`resolve/result.go`: every `missing []types.SetName` becomes `missing []types.SetRef`; every `Missing() []types.SetName` becomes `Missing() []types.SetRef` (doc: "sorted by String(); a scoped reference prints as RIPE::AS-FOO"); replace `sortedNames` with:

```go
// sortedRefs returns a copy of rs sorted by String().
func sortedRefs(rs []types.SetRef) []types.SetRef {
	out := make([]types.SetRef, len(rs))
	copy(out, rs)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
```

`resolve/expand_more.go`:
- `ExpandRouters(ctx, ref types.SetRef)`, `ExpandPeerings(ctx, ref types.SetRef)`: class checks on `ref.Name().Class()`, `discover(ctx, ref)`.
- `filterEval` gains `top types.SetRef // the filter-set ExpandFilterSet names, fetched in its scope` and `missing []types.SetRef`.
- `ExpandFilterSet(ctx, ref types.SetRef)`: class check on `ref.Name()`; `ev.top = ref`; `ev.filterSet(ref.Name())`; errors name `ref`; `ev.run(policy.FilterSetRef{Name: ref.Name()})`. Doc addition: `A scoped ref fetches the filter-set from that registry; the filter-sets and sets its filter names are unscoped, as filter syntax has no registry.`
- `filterSet(n)`:

```go
	ref := types.Ref(n)
	if !ev.top.IsZero() && n == ev.top.Name() {
		ref = ev.top // one filter-set per name per call: a cycle back to the top reuses its copy
	}
	set, err := ev.e.Src.GetSet(ev.ctx, ref)
	if err == nil {
		set, err = checkSet(ref, set)
	}
```

- `note(r types.SetRef)`; its callers passing a `types.SetName` pass `types.Ref(n)` (filter-set not found in `filterSetValue`, set not found in `setRef` and `asExpr`); the loops over `rs.Missing()` / `set.Missing()` pass the element as is.
- `result`: `out.missing = sortedRefs(ev.missing)`.
- Every `&SetTooLargeError{Name: ev.cur, …}` becomes `Name: types.Ref(ev.cur)` (a zero `SetName` gives a zero `SetRef`); in `cap`, `Name: types.Ref(n)` after the existing `if n.IsZero() { n = ev.cur }`.
- `prefixRanges(n)`: `ev.e.expandRanges(ev.ctx, types.Ref(n), ev.e.maxPrefixes())`; `asSet(n)`: `ev.e.expandAS(ev.ctx, types.Ref(n))`.

- [ ] **Step 4: Move the wrappers and backends to the new signature**

`resolve/cache.go`:

```go
// GetSet returns the set ref names, from the cache when it is there and fresh.
// A scoped and an unscoped reference to one name are cached apart.
func (c *Cache) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	e, err := c.lookup(ctx, cacheKey{kind: kindSet, name: ref.String()}, func(ctx context.Context, e *cacheEntry) {
		e.set, e.err = c.Src.GetSet(ctx, ref)
	})
	if err != nil {
		return nil, err
	}
	return e.set, e.err
}
```

and in `MembersByRef` the key becomes `cacheKey{kind: kindClaims, name: strings.ToUpper(strings.TrimSpace(set.SetSource())) + "::" + set.SetName().String()}` with the comment `// two same-named sets of two registries have different claimants`. (Add `"strings"` to cache.go's imports.) Update `cacheKey.name`'s comment: `the set reference, or (set source, set name) for claims; "" for a route lookup`.

`resolve/memsource.go`:

```go
// GetSet returns the set ref names or ErrNotFound.
func (s *MemSource) GetSet(_ context.Context, ref types.SetRef) (object.NamedSet, error) {
	if ref.IsScoped() {
		return nil, fmt.Errorf("resolve: MemSource: scoped lookup of %s is not supported", ref)
	}
	if set, ok := s.sets[ref.Name().String()]; ok {
		return set, nil
	}
	return nil, ErrNotFound
}
```

(Task 6 replaces this with real scoped lookups.)

`resolve/rpki/filter.go`: `func (f *Filter) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) { return f.Src.GetSet(ctx, ref) }`.

`resolve/irrd/irrd.go` and `resolve/whois/whois.go`: change the method to `GetSet(ctx context.Context, ref types.SetRef)`, add as its first statements

```go
	if ref.IsScoped() {
		return nil, fmt.Errorf("irrd: scoped lookup of %s is not supported", ref) // whois: "whois: …"
	}
	name := ref.Name()
```

and leave the rest of the body as it is. (Tasks 7 and 8 replace this.)

rpslq, `resolve/internal/rpslq/sources.go`:

```go
func (s *topSource) GetSet(ctx context.Context, ref types.SetRef) (rpslobj.NamedSet, error) {
	if !ref.IsScoped() && ref.Name() == s.top {
		return s.own.GetSet(ctx, ref)
	}
	return s.Source.GetSet(ctx, ref)
}
```

`traceSource.GetSet` takes `ref types.SetRef`, passes it on and prints `ref` where it printed the name. In `rpslq.go`, `ExpandAS(ctx, o.set)` / `ExpandPrefixRanges(ctx, o.set)` become `…(ctx, types.Ref(o.set))`, and `warnMissing`'s parameter becomes `[]types.SetRef` (it prints `String()`, unchanged text for unscoped refs).

- [ ] **Step 5: Move every caller (mechanical)**

Rewrite the calls in tests, examples and the bulk example:

```bash
cd /Users/roman/DEV/rpsl
FILES=$(grep -rlE 'Expand(AS|Prefixes|PrefixRanges|Routers|Peerings|FilterSet)\(|\.GetSet\(' --include='*.go' resolve examples | grep -E '_test\.go$|examples/' | grep -v 'resolve/scoped_test.go')
for m in ExpandAS ExpandPrefixes ExpandPrefixRanges ExpandRouters ExpandPeerings ExpandFilterSet GetSet; do
  gofmt -r "a.$m(b, c) -> a.$m(b, types.Ref(c))" -w $FILES
done
```

Then fix what the compiler reports, each by the rule given:
- A test type implementing `Source` (`grep -rn 'func (.*) GetSet(ctx context.Context, [a-z]* types.SetName)' --include='*_test.go' resolve`): change the parameter to `ref types.SetRef`, use `ref.Name()` where the body used the name, and pass `ref` where it forwarded the call. If the rewrite above wrapped a forwarded call as `types.Ref(ref)`, unwrap it.
- A file now missing the `types` import: add `"github.com/rkolesnichenko/rpsl/types"`.
- `resolve/model_test.go`'s `names` helper: change its parameter to `[]types.SetRef` (body unchanged — it calls `String()`).
- A comparison of `Missing()` with a `[]types.SetName` literal: compare `names(got.Missing())` (or `refStrings`) with the expected `[]string` instead.
- A test reading `SetTooLargeError.Name` as a `SetName`: compare `.Name.String()` or `.Name.Name()`.

- [ ] **Step 6: Run everything in the resolve module and the bulk example**

Run: `cd resolve && go vet ./... && go test ./... && cd ../examples/bulk-ripe && go test ./...`
Expected: PASS — including the new `resolve/scoped_test.go` and every existing expansion, bgpq4-differential and rpslq test (if bgpq4 is installed they run; they must stay green). `cd resolve && go list -deps . | grep -x net` prints nothing.

- [ ] **Step 7: Commit**

```bash
git add -A resolve examples
git commit -m "resolve: Source.GetSet and expansions take a types.SetRef; the engine keys sets by reference"
```

---

### Task 6: `MemSource` and `Corpus` resolve scoped refs; `SourceOf` restricts only unscoped lookups

**Files:**
- Modify: `resolve/memsource.go` (struct, `NewMemSource`, `GetSet`, `MembersByRef`, a `newMemSource` with a default filter)
- Modify: `resolve/corpus.go:283-316` (`Source`, `SourceOf`, `build`)
- Modify: `resolve/dump.go:90-96` (`SourceOf` doc)
- Create: `resolve/memsource_scoped_test.go` (package `resolve_test`, beside `model_test.go`'s `decodeAll` and Task 5's `mustRef`)
- Modify: `resolve/corpus_test.go`

**Interfaces:**
- Consumes: Task 5's `GetSet(ctx, types.SetRef)`.
- Produces:
  - `MemSource.GetSet`: unscoped → first copy by precedence among the default sources; scoped → the copy whose source is `ref.Source()`, any held source; else `ErrNotFound`.
  - `Corpus.SourceOf(sources...)`/`DumpLoader.SourceOf`: unscoped lookups and routes see only `sources`; scoped lookups and claims see every held source.
  - unexported `func newMemSource(objs []object.Object, precedence []string, dflt func(source string) bool) *MemSource` — `NewMemSource` is `newMemSource(objs, precedence, nil)`.

- [ ] **Step 1: Write the failing tests**

`resolve/memsource_scoped_test.go`:

```go
package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestMemSourceScoped(t *testing.T) {
	objs := decodeAll(t, []string{
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n",
		"route: 172.16.0.0/12\norigin: AS1\nsource: RADB\n",
	})
	ctx := context.Background()
	src := resolve.NewMemSource(objs, "RIPE", "RADB")
	for ref, want := range map[string]string{"AS-X": "RIPE", "RIPE::AS-X": "RIPE", "radb::as-x": "RADB"} {
		set, err := src.GetSet(ctx, mustRef(t, ref))
		if err != nil || set.SetSource() != want {
			t.Errorf("GetSet(%s) = %v, %v; want the %s copy", ref, set, err, want)
		}
	}
	if _, err := src.GetSet(ctx, mustRef(t, "ARIN::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: err = %v", err)
	}

	var c resolve.Corpus
	for _, o := range objs {
		c.Put(o)
	}
	only := c.SourceOf("RADB")
	if set, _ := only.GetSet(ctx, mustRef(t, "AS-X")); set == nil || set.SetSource() != "RADB" {
		t.Errorf("SourceOf(RADB) unscoped = %v; want RADB's", set)
	}
	if set, _ := only.GetSet(ctx, mustRef(t, "RIPE::AS-X")); set == nil || set.SetSource() != "RIPE" {
		t.Errorf("SourceOf(RADB) scoped RIPE = %v; want RIPE's (a scoped ref reaches every held source)", set)
	}
	if ps, _ := only.OriginatedRoutes(ctx, 1, types.AFIAny); len(ps) != 1 || ps[0].String() != "172.16.0.0/12" {
		t.Errorf("SourceOf(RADB) routes = %v; want RADB's only", ps)
	}
}
```

In `resolve/corpus_test.go`, extend `sameAnswers` with a `scopes []string` parameter: for every set name it already checks, also call `GetSet` with `types.NewSetRef(scope, name)` for each scope plus `"NOSUCH"`, comparing error nil-ness and `reflect.DeepEqual` exactly as the unscoped check does, and `MembersByRef` for each scoped answer found. Pass `[]string{"RIPE", "RADB"}` in the three existing `Source`/`NewMemSource` comparisons, and `[]string{"RIPE"}` in the `SourceOf("ripe")` comparison (the RIPE-only `NewMemSource` cannot hold RADB's copies, which the Corpus's `SourceOf` now serves to scoped lookups; the RADB scope is covered by `TestMemSourceScoped`).

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go test -run 'TestMemSourceScoped|TestCorpusMatchesMemSource' .`
Expected: FAIL — `scoped lookup of RIPE::AS-X is not supported`.

- [ ] **Step 3: Implement**

`resolve/memsource.go`:

```go
type MemSource struct {
	sets   map[types.SetName][]memSet    // every held copy, precedence order (winner first)
	dflt   func(source string) bool      // the sources unscoped lookups and routes see; nil: all
	routes map[types.ASN][]netip.Prefix  // origin AS -> originated prefixes, default sources only
	claims map[string][]object.Object    // canonical set name -> member-of claimants, every source
}

// memSet is one copy of a set and its upper-case source.
type memSet struct {
	set    object.NamedSet
	source string
}

// NewMemSource … (keep the existing doc, and add:) A scoped reference
// (RIPE::AS-FOO) finds the copy whose source: is that registry, whatever the
// precedence; one no object's source: names is ErrNotFound.
func NewMemSource(objs []object.Object, sourcePrecedence ...string) *MemSource {
	return newMemSource(objs, sourcePrecedence, nil)
}

// newMemSource is NewMemSource whose unscoped lookups and routes see only the
// sources dflt admits (nil: all). Scoped lookups and claims see every source.
func newMemSource(objs []object.Object, sourcePrecedence []string, dflt func(string) bool) *MemSource {
	s := &MemSource{
		sets:   map[types.SetName][]memSet{},
		dflt:   dflt,
		routes: map[types.ASN][]netip.Prefix{},
		claims: map[string][]object.Object{},
	}
	rank := func(source string) int {
		for i, src := range sourcePrecedence {
			if equalFoldASCII(source, strings.TrimSpace(src)) {
				return i
			}
		}
		return len(sourcePrecedence)
	}
	for _, o := range objs {
		if o = value(o); o == nil {
			continue
		}
		if set, ok := o.(object.NamedSet); ok {
			n := set.SetName()
			s.sets[n] = append(s.sets[n], memSet{set, strings.ToUpper(strings.TrimSpace(set.SetSource()))})
		}
		if p, origin, ok := routeOf(o); ok && s.admits(sourceOf(o)) {
			s.routes[origin] = append(s.routes[origin], p)
		}
		s.indexClaims(o)
	}
	for _, copies := range s.sets {
		// Stable: ties keep load order, so the object loaded first wins.
		sort.SliceStable(copies, func(i, j int) bool { return rank(copies[i].source) < rank(copies[j].source) })
	}
	return s
}

func (s *MemSource) admits(source string) bool {
	return s.dflt == nil || s.dflt(strings.ToUpper(strings.TrimSpace(source)))
}

// GetSet returns the set ref names or ErrNotFound: for an unscoped ref the
// copy the precedence puts first among the default sources, for a scoped one
// the copy of that registry.
func (s *MemSource) GetSet(_ context.Context, ref types.SetRef) (object.NamedSet, error) {
	for _, c := range s.sets[ref.Name()] {
		if ref.IsScoped() {
			if c.source == ref.Source() {
				return c.set, nil
			}
		} else if s.admits(c.source) {
			return c.set, nil
		}
	}
	return nil, ErrNotFound
}
```

`sourceOf(o)` returns the object's `source:` — add it to `claims.go` beside `claimant`:

```go
// sourceOf returns o's source: attribute ("" for a class without Common).
func sourceOf(o object.Object) string {
	switch t := value(o).(type) {
	case object.Route:
		return t.Source
	case object.Route6:
		return t.Source
	case object.AutNum:
		return t.Source
	case object.InetRtr:
		return t.Source
	}
	if set, ok := o.(object.NamedSet); ok {
		return set.SetSource()
	}
	return ""
}
```

(Add `"sort"` to memsource.go's imports.) `indexClaims` and `MembersByRef` are unchanged: claims from every source are indexed and `ClaimAllowed` keeps only the set's own source.

`resolve/corpus.go`:

```go
// Source builds a MemSource over the corpus: the one NewMemSource builds
// over the same objects, with the same source precedence.
func (c *Corpus) Source(sourcePrecedence ...string) *MemSource {
	return c.build(nil, sourcePrecedence)
}

// SourceOf builds a MemSource whose unscoped lookups and routes see only the
// objects of the given sources (compared without regard to case), in the
// precedence given; an object without a source: is left out of them. A scoped
// lookup (RIPE::AS-FOO) and the claims of a set it finds see every source the
// corpus holds, as bgpq4's -S list does not limit a SOURCE:: object. It is
// DumpLoader.SourceOf's meaning.
func (c *Corpus) SourceOf(sources ...string) *MemSource {
	want := map[string]bool{}
	for _, s := range sources {
		want[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	return c.build(func(s string) bool { return s != "" && want[s] }, sources)
}

func (c *Corpus) build(dflt func(string) bool, precedence []string) *MemSource {
	hs := c.ordered(nil) // every source: scoped lookups and claims see them all
	objs := make([]object.Object, len(hs))
	for i, h := range hs {
		objs[i] = h.obj
	}
	s := newMemSource(objs, precedence, dflt)
	for rk := range c.routes {
		if dflt == nil || dflt(rk.source) {
			s.routes[rk.origin] = append(s.routes[rk.origin], rk.prefix)
		}
	}
	for _, ps := range s.routes {
		sort.Slice(ps, func(i, j int) bool { return prefixLess(ps[i], ps[j]) })
	}
	return s
}
```

`resolve/dump.go`: give `DumpLoader.SourceOf` the same doc sentence about scoped lookups.

- [ ] **Step 4: Run to verify pass**

Run: `cd resolve && go test ./...`
Expected: PASS — `TestMemSourceScoped`, the extended `TestCorpusMatchesMemSource`, and every existing test (MemSource answers for unscoped refs are unchanged).

- [ ] **Step 5: Commit**

```bash
git add resolve/memsource.go resolve/corpus.go resolve/dump.go resolve/claims.go resolve/memsource_test.go resolve/corpus_test.go
git commit -m "resolve: MemSource and Corpus resolve scoped refs; SourceOf restricts unscoped lookups only"
```

---

### Task 7: irrtest speaks IRRd's unknown-source replies; `whois.Source` resolves scoped refs

Deviation from spec §7.5, on purpose: irrtest needs no separate "draft mode". It already returns object text verbatim over `!m` and whois, so `src-members:` reach the client untouched, and its `!i` ignores them exactly as IRRd does. What it lacks is IRRd's replies to an unknown source, which this task adds. The oracle for src-members is the random-IRR model (Task 9), which stays independent of the engine.

**Files:**
- Modify: `resolve/internal/irrtest/irrtest.go` (`!s` reply text; whois `-s` validation)
- Modify: `resolve/whois/whois.go` (`GetSet`, `MembersByRef`, `queryObjects`, drop `validSourceName`)
- Create: `resolve/whois/scoped_test.go`

**Interfaces:**
- Consumes: `types.ParseSourceName` (Task 1), `GetSet(ctx, types.SetRef)` (Task 5).
- Produces: `whois.Source.GetSet` resolves scoped refs with `-s <REG>`; an unknown registry is `resolve.ErrNotFound` for a scoped lookup and `*ServerError` for the default `Sources`.

- [ ] **Step 1: Make irrtest answer as IRRd does**

In `irrtest.go`'s `!s` case, replace `fmt.Fprintf(c, "F Unknown source %s\n", bad)` with `fmt.Fprint(c, "F One or more selected sources are unavailable.\n")` (IRRd's reply, verified against whois.radb.net on 2026-09-28; `bad` becomes a bool). In `whoisAnswer`'s `-s` branch, after building `sel`, add:

```go
		for _, s := range sel {
			if !contains(db.sources(), s) {
				return "%% ERROR: One or more selected sources are unavailable.\n" // IRRd's whois reply
			}
		}
```

Run: `cd resolve && go test ./...`
Expected: PASS (no test depends on the old text: `grep -rn 'Unknown source' resolve` finds only irrtest.go before the change). A test that now fails because it gives a `whois.Source` a `Sources` name its irrtest data never mentions was relying on the old silent "no entries": register the name with `.WithSources(...)` on its `irrtest.DB`, which is what the model tests already do.

- [ ] **Step 2: Write the failing whois tests**

`resolve/whois/scoped_test.go`:

```go
package whois_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

func ref(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScopedGetSet(t *testing.T) {
	db := irrtest.New(
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nmbrs-by-ref: ANY\nsource: RADB\n",
		"aut-num: AS3\nas-name: X\nmember-of: AS-X\nmnt-by: M\nsource: RADB\n",
	)
	src := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	ctx := context.Background()
	set, err := src.GetSet(ctx, ref(t, "RADB::AS-X"))
	if err != nil || set.SetSource() != "RADB" {
		t.Fatalf("RADB::AS-X = %v, %v; want RADB's copy although Sources is RIPE", set, err)
	}
	claims, err := src.MembersByRef(ctx, set)
	if err != nil || len(claims) != 1 {
		t.Errorf("claimants of RADB's AS-X = %v, %v; want AS3 (queried in RADB, outside Sources)", claims, err)
	}
	if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: err = %v, want ErrNotFound", err)
	}
	bad := &whois.Source{Addr: db.Whois(t), Sources: []string{"NOSUCH"}, Timeout: 5 * time.Second}
	var se *whois.ServerError
	if _, err := bad.GetSet(ctx, ref(t, "AS-X")); !errors.As(err, &se) {
		t.Errorf("an unknown source in Sources: err = %v, want a *ServerError", err)
	}
}

// RIPE answers an unknown source with %ERROR:102 (verified 2026-09-28).
func TestScopedGetSetRIPEUnknownSource(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			_, _ = bufio.NewReader(s).ReadString('\n')
			_, _ = io.WriteString(s, "%ERROR:102: unknown source\n%\n% \"NOSUCH\" is not a known source.\n")
		}()
		return c, nil
	}
	src := &whois.Source{Addr: "whois.example:43", Dial: dial, Timeout: 5 * time.Second}
	if _, err := src.GetSet(context.Background(), ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cd resolve && go test -run 'TestScopedGetSet' ./whois`
Expected: FAIL — `whois: scoped lookup of RADB::AS-X is not supported`.

- [ ] **Step 4: Implement**

In `resolve/whois/whois.go`:

```go
// GetSet fetches a set object of any class by name. An unscoped ref is looked
// up in Sources (the copy from the source listed first wins; without Sources,
// the first the server returns). A scoped ref (RIPE::AS-FOO) is looked up in
// that registry alone, with "-s", whatever Sources lists; a registry the server
// does not know is resolve.ErrNotFound.
func (s *Source) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	name := ref.Name()
	if name.IsZero() {
		return nil, errors.New("whois: empty set name")
	}
	sources := s.Sources
	if ref.IsScoped() {
		sources = []string{ref.Source()}
	}
	class := name.Class().String()
	objs, err := s.queryObjectsIn(ctx, sources, "-r -T "+class+" "+name.String())
	if err != nil {
		if ref.IsScoped() && unknownSource(err) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	var best object.NamedSet
	bestRank := len(sources)
	for _, o := range objs {
		set, ok := o.(object.NamedSet)
		if !ok || set.SetName() != name || set.Class() != class {
			continue
		}
		rank := slices.IndexFunc(sources, func(n string) bool { return strings.EqualFold(n, strings.TrimSpace(set.SetSource())) })
		if rank < 0 {
			if ref.IsScoped() {
				continue // not the registry asked for
			}
			rank = len(sources)
		}
		if best == nil || rank < bestRank {
			best, bestRank = set, rank
		}
	}
	if best == nil {
		return nil, resolve.ErrNotFound
	}
	return best, nil
}

// unknownSource reports a server's refusal of a source it does not have:
// RIPE's "%ERROR:102: unknown source", IRRd's "%% ERROR: One or more selected
// sources are unavailable."
func unknownSource(err error) bool {
	var se *ServerError
	return errors.As(err, &se) && (se.Code == 102 || strings.Contains(se.Message, "sources are unavailable"))
}
```

`MembersByRef`: replace `s.queryObjects(ctx, q)` with

```go
	sources := s.Sources
	if src, err := types.ParseSourceName(strings.TrimSpace(set.SetSource())); err == nil {
		sources = []string{src} // ClaimAllowed keeps only the set's own source's claims
	}
	objs, err := s.queryObjectsIn(ctx, sources, q)
```

Rename `queryObjects(ctx, q)` to `queryObjectsIn(ctx, sources []string, q string)`: validate each name with `types.ParseSourceName` (returning `fmt.Errorf("whois: invalid source name %q", n)` on error) and prefix `"-s " + strings.Join(canonical, ",") + " "`; `OriginatedRoutes` calls it with `s.Sources`. Delete `validSourceName`.

- [ ] **Step 5: Run to verify pass**

Run: `cd resolve && go test ./whois ./... `
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add resolve/internal/irrtest/irrtest.go resolve/whois
git commit -m "whois: resolve scoped refs with -s; irrtest answers unknown sources as IRRd does"
```

---

### Task 8: `irrd.Source` resolves scoped refs, and reads `src-members:` on request

**Files:**
- Modify: `resolve/irrd/irrd.go` (struct fields, `GetSet`, `selectSources`, `sourceList`, `Close`; drop `validSourceName`)
- Create: `resolve/irrd/scoped_test.go`

**Interfaces:**
- Consumes: `types.ParseSourceName`; `object.AsSet.SrcMembers`, `Set.SetSrcMembers` (Task 3).
- Produces:
  - `irrd.Source.SrcMembers bool`
  - scoped `GetSet` through a per-registry sub-source sharing the parent's `MaxConns`; unknown registry → `resolve.ErrNotFound`.

- [ ] **Step 1: Write the failing tests**

`resolve/irrd/scoped_test.go`:

```go
package irrd_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/types"
)

func ref(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func scopedDB() *irrtest.DB {
	return irrtest.New(
		"as-set: AS-X\nmembers: AS1, AS-Y\nsrc-members: RIPE::AS-Y\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
	)
}

func TestScopedGetSet(t *testing.T) {
	for _, pipeline := range []int{0, 4} {
		db := scopedDB()
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true, Timeout: 5 * time.Second}
		ctx := context.Background()
		set, err := src.GetSet(ctx, ref(t, "RIPE::AS-X"))
		if err != nil || set.SetSource() != "RIPE" {
			t.Fatalf("pipeline %d: RIPE::AS-X = %v, %v; want RIPE's copy", pipeline, set, err)
		}
		if got, _ := src.GetSet(ctx, ref(t, "AS-X")); got.(object.AsSet).Members[0].AS != 2 {
			t.Errorf("pipeline %d: unscoped AS-X = %v; want RADB's", pipeline, got)
		}
		if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("pipeline %d: unknown registry: err = %v", pipeline, err)
		}
		if _, err := src.GetSet(ctx, ref(t, "AS-X")); err != nil {
			t.Errorf("pipeline %d: the unscoped connection broke after the scoped refusal: %v", pipeline, err)
		}
		src.Close()
	}
}

func TestSrcMembersOption(t *testing.T) {
	db := scopedDB()
	ctx := context.Background()
	off := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	set, err := off.GetSet(ctx, ref(t, "AS-X"))
	if err != nil || len(set.(object.AsSet).SrcMembers) != 0 {
		t.Fatalf("SrcMembers off: %v, %v; want no src-members read", set, err)
	}
	on := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, SrcMembers: true, Timeout: 5 * time.Second}
	set, err = on.GetSet(ctx, ref(t, "AS-X"))
	if err != nil {
		t.Fatal(err)
	}
	as := set.(object.AsSet)
	if len(as.SrcMembers) != 1 || as.SrcMembers[0].Ref().String() != "RIPE::AS-Y" || as.SetSource() != "RIPE" {
		t.Errorf("SrcMembers on: %+v (source %q); want [RIPE::AS-Y] from RIPE", as.SrcMembers, as.SetSource())
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go test -run 'TestScopedGetSet|TestSrcMembersOption' ./irrd`
Expected: FAIL — `irrd: scoped lookup of RIPE::AS-X is not supported`; `unknown field SrcMembers`.

- [ ] **Step 3: Implement**

Add to `Source` (after `Pipeline`), with the spec §7.3 doc:

```go
	// SrcMembers, when set, also fetches each as-set and route-set whole
	// ("!m") to read its src-members: (draft-ietf-grow-rpsl-registry-scoped-
	// members) and source:. Members still come from "!i", which folds in
	// indirect members. Off by default: IRRd does not implement the draft,
	// and it doubles the queries for sets.
	SrcMembers bool

	scoped map[string]*Source // registry -> sub-source restricted to it, made on first use (under mu)
	parent *Source            // for a sub-source: the Source whose MaxConns budget it shares
```

Add the sentinel beside `errQuery`:

```go
// errUnknownSource marks a server's refusal of a "!s" source list: IRRd
// answers "F One or more selected sources are unavailable."
var errUnknownSource = errors.New("irrd: unknown source")
```

In `selectSources`, the non-`errNotFound` branch becomes:

```go
		if errors.Is(err, errQuery) {
			return fmt.Errorf("irrd: selecting sources %q: %w: %w", list, errUnknownSource, err)
		}
		return fmt.Errorf("irrd: selecting sources %q: %w", list, err)
```

`sourceList` validates with `types.ParseSourceName` (error `fmt.Errorf("irrd: invalid source name %q", n)`) and joins the canonical names; delete `validSourceName`.

The sub-source and the new `GetSet`:

```go
// in returns the sub-source restricted to registry: the same server, limits
// and pipelining, on connections of its own that select only that registry
// ("!s" is per connection, and switching it on a shared pipelined connection
// would race with the queries in flight). It shares s's MaxConns budget, and
// Close closes it.
func (s *Source) in(registry string) *Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sub, ok := s.scoped[registry]; ok {
		return sub
	}
	if s.slots == nil && s.MaxConns >= 0 {
		s.slots = make(chan struct{}, s.maxConns())
	}
	sub := &Source{
		Addr: s.Addr, Sources: []string{registry}, Timeout: s.Timeout, MaxResponse: s.MaxResponse,
		Dial: s.Dial, KeepAlive: s.KeepAlive, MaxConns: s.MaxConns, Pipeline: s.Pipeline,
		SrcMembers: s.SrcMembers, parent: s, slots: s.slots,
	}
	if s.scoped == nil {
		s.scoped = map[string]*Source{}
	}
	s.scoped[registry] = sub
	return sub
}

// GetSet fetches a set. An unscoped ref is looked up in Sources' priority; a
// scoped ref (RIPE::AS-FOO) in that registry alone, through a connection that
// selects only it, and a registry the server does not have is
// resolve.ErrNotFound. For an as-set or route-set it asks for the one-level
// membership via "!i" and synthesizes a typed set object (with SrcMembers set,
// it also fetches the object, "!m", for its src-members: and source:). IRRd
// answers "!i" alike for a missing set and for one with no members, so on that
// answer GetSet asks for the object itself: a set that exists is returned
// empty, and a missing one maps to resolve.ErrNotFound. A set of any other
// class is fetched with "!m" and decoded.
func (s *Source) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	if ref.IsZero() {
		return nil, errors.New("irrd: empty set name")
	}
	if !ref.IsScoped() {
		return s.getSet(ctx, ref.Name(), "")
	}
	set, err := s.in(ref.Source()).getSet(ctx, ref.Name(), ref.Source())
	if errors.Is(err, errUnknownSource) {
		return nil, resolve.ErrNotFound
	}
	return set, err
}

// getSet is GetSet on this Source's own sources; source, when set, is the
// registry they are (a scoped lookup), which a synthesized set carries.
func (s *Source) getSet(ctx context.Context, name types.SetName, source string) (object.NamedSet, error) {
	if c := name.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
		return s.fetchSet(ctx, name)
	}
	whole := "!m" + name.Class().String() + "," + name.String()
	payload, err := s.do(ctx, "!i"+name.String())
	var obj []byte
	haveObj := false
	if errors.Is(err, errNotFound) {
		obj, err = s.do(ctx, whole)
		payload, haveObj = nil, true
	}
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	var src []object.SetMember
	if s.SrcMembers {
		if !haveObj {
			if obj, err = s.do(ctx, whole); err != nil && !errors.Is(err, errNotFound) {
				return nil, err
			}
		}
		if len(obj) > 0 {
			raw, _ := rpsl.ParseObject(string(obj))
			if o, _ := object.Decode(raw); o != nil {
				if full, ok := o.(object.Set); ok && full.SetName() == name {
					src = full.SetSrcMembers()
					if source == "" {
						source = strings.TrimSpace(full.SetSource())
					}
				}
			}
		}
	}
	members := parseMembers(string(payload), name.Class())
	common := object.Common{Source: source}
	if name.Class() == types.ClassAsSet {
		return object.AsSet{Common: common, Name: name, Members: members, SrcMembers: src}, nil
	}
	return object.RouteSet{Common: common, Name: name, Members: members, SrcMembers: src}, nil
}
```

`Close` also closes each sub-source: after taking `s.idle, s.pipes`, take `subs := s.scoped; s.scoped = nil` under the same lock, and after the existing loops `for _, sub := range subs { sub.Close() }`. A sub-source must not close the shared semaphore (it never does: `slots` is only created, never closed).

(Two sequential `s.do` calls, not one pipelined pair: on a `Pipeline` source concurrent fetches already share connections, and `Expander.Concurrency` supplies the parallelism.)

- [ ] **Step 4: Run to verify pass**

Run: `cd resolve && go test ./irrd ./... && go test -race ./irrd`
Expected: PASS, race-clean.

- [ ] **Step 5: Commit**

```bash
git add resolve/irrd
git commit -m "irrd: resolve scoped refs on per-registry connections; SrcMembers reads src-members via !m"
```

---

### Task 9: The random-IRR model learns `src-members:`; every backend is held to it

**Files:**
- Modify: `resolve/model_test.go` (model types, generator, rendering, oracle, `checkModel`, both tests)
- Modify: `resolve/engine_test.go` (`graph.corpus`: scoped refs), `resolve/infra_test.go` (nothing, if the graph change suffices)
- Create: `resolve/draft_figure1_test.go`

**Interfaces:**
- Consumes: everything from Tasks 5-8; `irrd.Source.SrcMembers`.
- Produces: no API; the oracle.

- [ ] **Step 1: Extend the model (types, generation, rendering)**

In `model_test.go`:
- `mMember` gains `scope string // registry of a src-members: set reference ("" elsewhere)`.
- `mSet` gains `src []mMember // src-members:, as written`.
- `randomModel(r, compat)`: after `newSet` builds `s.members`, when `!compat && r.IntN(3) == 0`, build `s.src`:

```go
	if !compat && r.IntN(3) == 0 {
		s.src = srcMembers(r, s, class, asNames, rsNames)
	}
```

with, beside `newSet`:

```go
// srcMembers draws a src-members: list for s (draft §2.1-2.2): scoped copies
// of some of its set members — in RIPE, RADB, or NOSUCH, a registry no backend
// holds — some of its AS and prefix members, sometimes an entry members: lacks
// (§3.1, still followed), and sometimes one name under two registries (§3.3,
// dropped).
func srcMembers(r *rand.Rand, s *mSet, class types.SetClass, asNames, rsNames []string) []mMember {
	scopes := []string{"RIPE", "RADB", "NOSUCH"}
	allowed := func(set string) bool {
		c := setClass(set)
		return c == types.ClassAsSet || class == types.ClassRouteSet && c == types.ClassRouteSet
	}
	scoped := func(set, op string) mMember {
		sc := scopes[r.IntN(len(scopes))]
		if class != types.ClassRouteSet || setClass(set) != types.ClassRouteSet {
			op = "" // an operator only on a scoped route-set
		}
		return mMember{kind: "set", set: set, scope: sc, op: op, text: sc + "::" + set + op}
	}
	var out []mMember
	for _, mm := range s.members {
		if r.IntN(2) == 0 {
			continue
		}
		switch mm.kind {
		case "set":
			if allowed(mm.set) {
				out = append(out, scoped(mm.set, mm.op))
			}
		case "as":
			out = append(out, mMember{kind: "as", as: mm.as, text: mm.as.String()}) // no operator on an ASN
		case "pfx":
			out = append(out, mm) // a prefix keeps its operator
		}
	}
	pool := asNames
	if class == types.ClassRouteSet && r.IntN(2) == 0 {
		pool = rsNames
	}
	if r.IntN(4) == 0 && len(pool) > 0 {
		out = append(out, scoped(pool[r.IntN(len(pool))], ""))
	}
	if r.IntN(6) == 0 && len(out) > 0 && out[0].kind == "set" {
		c := out[0]
		c.scope = map[string]string{"RIPE": "RADB", "RADB": "RIPE", "NOSUCH": "RIPE"}[c.scope]
		c.text = c.scope + "::" + c.set + c.op
		out = append(out, c)
	}
	return out
}
```

(`asNames` and `rsNames` are the generator's existing pools of as-set and route-set names; a set member naming `AS-ANY`, `RS-ANY` or a `-MISS` set may be scoped too — the oracle and the engine both look at the name part for `ANY`, and a scoped missing set is reported with its scope.)

- `texts(r)`: after the `members:`/`mp-members:` lines of a set, when `len(s.src) > 0`, write `src-members: ` + the `text`s joined by `", "` (use the same `list()` helper so it may split across repeated lines).

- [ ] **Step 2: Extend the oracle**

The oracle's node is a reference string, `"SCOPE::NAME"` or `"NAME"`. Add to `oracle`:

```go
	byScope map[string]*mSet // "SOURCE::NAME" -> that source's copy
	noSrc   bool             // ignore src-members: (what IRRd, and irrd.Source without SrcMembers, see)
```

Fill `byScope` in `newOracle` for every set (`s.source + "::" + s.name`). Add:

```go
// resolveRef is the set a reference denotes: a scoped one only its source's
// copy, an unscoped one the precedence winner.
func (o *oracle) resolveRef(ref string) (*mSet, bool) {
	if src, name, ok := strings.Cut(ref, "::"); ok {
		s, found := o.byScope[src+"::"+name]
		return s, found
	}
	s, found := o.sets[ref]
	return s, found
}

// direct is the draft's §2.3 member selection, from the model: src-members:
// first (a name under two scopes dropped), then each members: entry whose key
// src-members: lacks. Keys: set name, AS number, prefix with its operator.
func (o *oracle) direct(s *mSet) []mMember {
	if o.noSrc || len(s.src) == 0 {
		return s.members
	}
	key := func(m mMember) string {
		switch m.kind {
		case "set":
			return "set " + m.set
		case "as":
			return "as " + m.as.String()
		case "pfx":
			return "pfx " + m.pfx.String() + m.op
		}
		return ""
	}
	scopes := map[string]map[string]bool{}
	for _, m := range s.src {
		if m.kind == "set" {
			if scopes[m.set] == nil {
				scopes[m.set] = map[string]bool{}
			}
			scopes[m.set][m.scope] = true
		}
	}
	have := map[string]bool{}
	var out []mMember
	for _, m := range s.src {
		if m.kind == "set" && len(scopes[m.set]) > 1 || have[key(m)] {
			continue
		}
		have[key(m)] = true
		out = append(out, m)
	}
	for _, m := range s.members {
		if k := key(m); k != "" && have[k] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// refOf is the reference a set member denotes.
func refOf(m mMember) string {
	if m.scope != "" {
		return m.scope + "::" + m.set
	}
	return m.set
}
```

Rewrite `reach`, `missing`, `asns` and `prefixes` to walk references: every `o.sets[name]` becomes `o.resolveRef(ref)`; every `s.members` becomes `o.direct(s)`; every nested member's key `mm.set` becomes `refOf(mm)`; the `nested(...)` class test and `exS` test still read `mm.set` (the name). `missing(top)` returns the sorted refs in `reach(top)` that `resolveRef` does not find. `honored(s, c)` is unchanged (claims already require `c.source == s.source`).

- [ ] **Step 3: Scoped tops and the comparisons in `checkModel`**

In `checkModel`, the tops become the sorted keys of `o.sets` **plus** the sorted keys of `o.byScope` (scoped tops, `"RIPE::AS-S0"`), each parsed with `types.ParseSetRef` (use `mustRef`); an as-set top runs `ExpandAS`, every top `ExpandPrefixes` for v4, v6 and Any, exactly as today. `names(got.Missing())` already compares strings (Task 5).

In `TestModelMemSource`, nothing else changes: `NewMemSource(…, "RIPE", "RADB")` must match the oracle including src-members.

In `TestModelBackends`:
- the two `irrd.Source` values get `SrcMembers: true`;
- add a third irrd check without `SrcMembers` against `o2 := newOracle(m); o2.noSrc = true` (Review: "off means today");
- whois is unchanged (it reads whole objects).
- add `resolve.NewCache(resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB"), 0)` as a checked backend.

- [ ] **Step 4: Scoped refs in the concurrency graph**

In `engine_test.go`, `graph.corpus`: give each set `source: RIPE`, and render each nested edge, with probability 1/3, also as a `src-members: RIPE::AS-S<j>` line (the edge stays in `members:` too). The graph's oracle is unchanged (the scoped copy is the same object). `TestConcurrencyDoesNotChangeResults` then exercises scoped nodes serially and in parallel.

- [ ] **Step 5: The draft's Figure 1 over every backend**

`resolve/draft_figure1_test.go` (package `resolve_test`):

```go
package resolve_test

import (
	"context"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
)

var figure1 = []string{
	"route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\nsource: EXAMPLE\n",
	"route-set: RS-SECOND\nmembers: RS-THIRD\nsource: RIPE\n",
	"route-set: RS-SECOND\nmembers: AS65002\nsource: OTHER\n",
	"route-set: RS-THIRD\nmembers: AS65000\nsource: OTHER\n",
	"route-set: RS-LEGACY\nmembers: AS65001\nsource: OTHER\n",
	"route: 10.0.0.0/24\norigin: AS65000\nsource: OTHER\n",
	"route: 10.0.1.0/24\norigin: AS65001\nsource: OTHER\n",
	"route: 10.0.2.0/24\norigin: AS65002\nsource: OTHER\n",
}

// TestDraftFigure1Backends: RS-FIRST resolves to AS65000 and AS65001 in every
// backend, with OTHER outranking RIPE so that only src-members: keeps OTHER's
// RS-SECOND (and AS65002) out.
func TestDraftFigure1Backends(t *testing.T) {
	db := irrtest.New(figure1...)
	sources := []string{"EXAMPLE", "OTHER", "RIPE"}
	backends := map[string]resolve.Source{
		"memsource": resolve.NewMemSource(decodeAll(t, figure1), sources...),
		"whois":     &whois.Source{Addr: db.Whois(t), Sources: sources, Timeout: 5 * time.Second},
		"irrd":      &irrd.Source{Addr: db.IRRd(t), Sources: sources, SrcMembers: true, Timeout: 5 * time.Second},
	}
	for name, src := range backends {
		got, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), mustRef(t, "RS-FIRST"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.String() != "[10.0.0.0/24 10.0.1.0/24]" {
			t.Errorf("%s: RS-FIRST = %v, want [10.0.0.0/24 10.0.1.0/24]", name, got)
		}
	}
}
```

(OTHER outranks RIPE in `sources`, so an unscoped lookup of RS-SECOND would return OTHER's copy and add 10.0.2.0/24; the exact result proves the scope was honoured.)

- [ ] **Step 6: Run the model**

Run: `cd resolve && go test -run 'TestModel|TestCorpusMatchesMemSource|TestConcurrency|TestDraftFigure1' -race .`
Expected: PASS. If a seed fails, print its texts (`t.Log(strings.Join(texts, "\n"))`) and decide from the draft which side is wrong: the oracle is the draft read from the model; the engine must agree with it.

- [ ] **Step 7: Commit**

```bash
git add resolve/model_test.go resolve/engine_test.go resolve/draft_figure1_test.go
git commit -m "resolve: the random-IRR model and every backend cover src-members"
```

---

### Task 10: rpslq — `SOURCE::SET` is a scoped ref, `--src-members`, the divergence pinned

**Files:**
- Modify: `resolve/internal/rpslq/sources.go` (delete `topSource`)
- Modify: `resolve/internal/rpslq/rpslq.go` (`expander`, `parseObjects`/`validRegistry`, `source`, config, usage)
- Modify: `resolve/internal/rpslq/getopt.go:24-28` (`longArgs`)
- Modify: `resolve/bgpq4_test.go` (`TestBgpq4KnownDivergences` case), `resolve/testdata/bgpq4/divergences.md`
- Modify: `resolve/internal/rpslq/rpslq_test.go` (new tests)
- Modify: `docs/rpslq.md`

**Interfaces:**
- Consumes: `types.NewSetRef`, `types.ParseSourceName`; scoped `GetSet` in every backend (Tasks 6-8); `irrd.Source.SrcMembers`.
- Produces: the `--src-members` long option.

- [ ] **Step 1: Write the failing tests**

Append to `resolve/internal/rpslq/rpslq_test.go`:

```go
// TestSrcMembersOption: over IRRd, --src-members makes rpslq follow
// src-members:; without it, it sees what IRRd serves.
func TestSrcMembersOption(t *testing.T) {
	addr := irrtest.New(
		"as-set: AS-SRC\nmembers: AS-DUP\nsrc-members: RADB::AS-DUP\nsource: RIPE\n",
		"as-set: AS-DUP\nmembers: AS64601\nsource: RIPE\n",
		"as-set: AS-DUP\nmembers: AS64602\nsource: RADB\n",
	).IRRd(t)
	_, without, _ := rpslq(t, "-h", addr, "-S", "RIPE,RADB", "-f", "1", "AS-SRC")
	_, with, _ := rpslq(t, "-h", addr, "-S", "RIPE,RADB", "--src-members", "-f", "1", "AS-SRC")
	if !strings.Contains(without, "64601") || strings.Contains(without, "64602") {
		t.Errorf("without --src-members: %q; want RIPE's AS-DUP (precedence)", without)
	}
	if !strings.Contains(with, "64602") || strings.Contains(with, "64601") {
		t.Errorf("with --src-members: %q; want RADB's AS-DUP (src-members:)", with)
	}
	if code, _, errs := rpslq(t, "--whois", "-h", addr, "--src-members", "AS-SRC"); code == 0 || !strings.Contains(errs, "--src-members") {
		t.Errorf("--src-members with --whois: exit %d, %q; want a usage error", code, errs)
	}
}
```

(`rpslq(t, args...)` is the file's helper: it runs `Run` and returns the exit code, stdout and stderr.)

Add a case to `TestBgpq4KnownDivergences` (`resolve/bgpq4_test.go`), written in the same form as the existing as-set cases (`route-set-in-as-set`):

```go
		{
			id: "src-members",
			objects: []string{
				"as-set: AS-SRC\nmembers: AS-DUP\nsrc-members: RADB::AS-DUP\nsource: RIPE\n",
				"as-set: AS-DUP\nmembers: AS64601\nsource: RIPE\n",
				"as-set: AS-DUP\nmembers: AS64602\nsource: RADB\n",
			},
			set: "AS-SRC", ours: "AS64602", bgp4: "AS64601",
		},
```

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go test -run 'TestSrcMembersOption' ./internal/rpslq && go test -run TestBgpq4KnownDivergences .`
Expected: FAIL — `unknown option --src-members`; the divergence case fails only if bgpq4 is installed (it is skipped otherwise), and on the engine side it already passes after Task 6.

- [ ] **Step 3: Implement**

- Delete `topSource` from `sources.go`. In `rpslq.go`, delete `(*query).expander`; every `q.expander(o).ExpandAS(ctx, types.Ref(o.set))` / `…ExpandPrefixRanges(…)` becomes `q.e.ExpandAS(ctx, o.ref())` / `q.e.ExpandPrefixRanges(ctx, o.ref())`, with

```go
// ref is the set o names: scoped to its SOURCE:: registry when it has one, as
// draft-ietf-grow-rpsl-registry-scoped-members §2.3.2 and bgpq4 mean it — the
// set is looked up in that registry, what it lists by the default sources.
func (o object) ref() types.SetRef {
	r, _ := types.NewSetRef(o.registry, o.set) // registry was validated by parseObjects
	return r
}
```

  `restricted` and `own` stay: `prefixes` still uses them for `SOURCE::AS`, whose routes bgpq4 fetches from that registry.
- `parseObjects`: replace `validRegistry(reg)` + `strings.ToUpper(reg)` with `reg, err := types.ParseSourceName(reg)` (same usage error on failure); delete `validRegistry`.
- `getopt.go` `longArgs`: add `"src-members": false`. `config` gains `srcMembers bool`; `parse`: `case "src-members": c.srcMembers = true`; `check`: `case c.srcMembers && (c.whois || len(c.dumps) > 0): return usagef("--src-members applies to an IRRd server: --whois and --dump read src-members: from the objects themselves")`.
- `source(...)` gains a `srcMembers bool` parameter (call site at `rpslq.go:447`: pass `c.srcMembers`) and sets `SrcMembers: srcMembers` on every `irrd.Source` it builds (the default one and the `restrict` ones).
- Usage text, in the Source section beside `--server-expand`:

```
  --src-members   over an IRRd server, also fetch each set whole to follow its
                  src-members: (draft-ietf-grow-rpsl-registry-scoped-members);
                  --whois and --dump always do
```

- `divergences.md`, the first table, new row:

```
| src-members | AS-SRC lists AS-DUP and has `src-members: RADB::AS-DUP`; RIPE and RADB both hold AS-DUP | AS64602 (RADB's, as src-members: asks) | AS64601 (RIPE's, by -S precedence) | Neither bgpq4 nor IRRd implements draft-ietf-grow-rpsl-registry-scoped-members; the engine does. rpslq over IRRd agrees with bgpq4 unless given --src-members |
```

- `docs/rpslq.md`: document `--src-members` in the options list, and in the `SOURCE::` section add: `SOURCE::SET looks the set up in that registry and what it lists in the -S sources, as bgpq4 does; it is the same scoped reference as a src-members: entry.`
- `-d` traces: the top set's lookup now prints as `RIPE::AS-X` on the default source instead of `AS-X [RIPE]` on a restricted one. Update any expectation in `rpslq_test.go` that pins the old trace line.

- [ ] **Step 4: Run to verify pass**

Run: `cd resolve && go test ./internal/rpslq . `
Expected: PASS — including `TestRpslqMatchesBgpq4` and `TestRpslqSourceDivergences` (when bgpq4 is installed; install it with `brew install bgpq4` to run them). Deleting `topSource` does change two pinned `SOURCE::` outcomes, `source-cycle` and `source-with-depth`, because the scope no longer cascades: a self-reference now resolves unscoped and joins another registry's copy, as bgpq4 already does, so `source-cycle` newly agrees with bgpq4 (`source-with-depth` still diverges, with a new count) — both pinned in `TestRpslqSourceDivergences`. `TestRpslqSourcePrefixMatchesBgpq4`, the random `SOURCE::` differential, is the proof that nothing else changed.

- [ ] **Step 5: Commit**

```bash
git add resolve/internal/rpslq resolve/bgpq4_test.go resolve/testdata/bgpq4/divergences.md docs/rpslq.md
git commit -m "rpslq: SOURCE::SET is a scoped reference; --src-members; pin the src-members divergence"
```

---

### Task 11: `PolicySource` — interface, `MemSource`, `Corpus.KeepPolicy`, `Cache`, `rpki.Filter`

**Files:**
- Create: `resolve/policysource.go`
- Modify: `resolve/memsource.go` (policy indexes, `rank`, `finish`)
- Modify: `resolve/corpus.go` (`KeepPolicy` field, `held.text`, `Put`, `build`)
- Modify: `resolve/cache.go` (policy kinds and methods)
- Modify: `resolve/rpki/filter.go` (pass-through methods)
- Create: `resolve/policysource_test.go`
- Modify: `resolve/corpus_test.go` (`sameAnswers` policy comparisons)

**Interfaces:**
- Consumes: `types.ParseSourceName`; `newMemSource` (Task 6); root `rpsl.ParseObject`, `object.Decode`.
- Produces:
  - `type PolicySource interface { Source; AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error); InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) }`
  - `var ErrNoPolicy = errors.New("resolve: source serves no policy objects")`
  - `Corpus.KeepPolicy bool`
  - `*MemSource`, `*Cache`, `*rpki.Filter` implement `PolicySource`.

- [ ] **Step 1: Write the failing tests**

`resolve/policysource_test.go`:

```go
package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
)

var policyTexts = []string{
	"aut-num: AS1\nas-name: ONE-RIPE\nimport: from AS2 accept ANY\nsource: RIPE\n",
	"aut-num: AS1\nas-name: ONE-PROXY\nsource: RADB\n",
	"aut-num: AS3\nas-name: CLAIMS\nmember-of: AS-X\nmnt-by: M\nsource: RIPE\n",
	"inet-rtr: rtr1.example.net\nlocal-as: AS1\nifaddr: 192.0.2.1 masklen 30\nsource: RIPE\n",
}

func checkPolicy(t *testing.T, label string, src resolve.PolicySource) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range []struct {
		source, want string
	}{{"", "ONE-RIPE"}, {"RIPE", "ONE-RIPE"}, {"radb", "ONE-PROXY"}} {
		an, err := src.AutNum(ctx, 1, tc.source)
		if err != nil || an.AsName != tc.want {
			t.Errorf("%s: AutNum(AS1, %q) = %q, %v; want %q", label, tc.source, an.AsName, err, tc.want)
		}
	}
	if an, _ := src.AutNum(ctx, 1, ""); len(an.Imports) != 1 {
		t.Errorf("%s: AS1's import was not decoded: %+v", label, an.Imports)
	}
	if an, err := src.AutNum(ctx, 3, ""); err != nil || an.AsName != "CLAIMS" {
		t.Errorf("%s: a claimant aut-num = %q, %v", label, an.AsName, err)
	}
	for _, missing := range []func() error{
		func() error { _, err := src.AutNum(ctx, 1, "NOSUCH"); return err },
		func() error { _, err := src.AutNum(ctx, 9, ""); return err },
		func() error { _, err := src.InetRtr(ctx, "rtr9.example.net", ""); return err },
	} {
		if err := missing(); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", label, err)
		}
	}
	if ir, err := src.InetRtr(ctx, "RTR1.example.NET", ""); err != nil || ir.LocalAS != 1 {
		t.Errorf("%s: InetRtr = %+v, %v", label, ir, err)
	}
}

func TestPolicySource(t *testing.T) {
	objs := decodeAll(t, policyTexts)
	checkPolicy(t, "NewMemSource", resolve.NewMemSource(objs, "RIPE", "RADB"))
	c := resolve.Corpus{KeepPolicy: true}
	for _, o := range objs {
		c.Put(o)
	}
	checkPolicy(t, "Corpus", c.Source("RIPE", "RADB"))
	checkPolicy(t, "Cache", resolve.NewCache(c.Source("RIPE", "RADB"), 0))
	checkPolicy(t, "rpki.Filter", &rpki.Filter{Src: c.Source("RIPE", "RADB")})

	var plain resolve.Corpus // without KeepPolicy: only the claimant aut-num is held
	for _, o := range objs {
		plain.Put(o)
	}
	if _, err := plain.Source().AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a Corpus without KeepPolicy served AS1: %v", err)
	}
}

func TestPolicyWrappersOverPlainSource(t *testing.T) {
	src := newRefSource(t, nil, nil) // a Source that is not a PolicySource
	for name, ps := range map[string]resolve.PolicySource{
		"Cache":  resolve.NewCache(src, 0),
		"Filter": &rpki.Filter{Src: src},
	} {
		if _, err := ps.AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNoPolicy) {
			t.Errorf("%s: err = %v, want ErrNoPolicy", name, err)
		}
	}
}
```

In `corpus_test.go`'s `sameAnswers`, when both sources are `PolicySource`s built from a `Corpus{KeepPolicy: true}` and `NewMemSource`, compare `AutNum` for every ASN it already enumerates × `{"", "RIPE", "RADB", "NOSUCH"}`: error nil-ness equal, and on success `Raw().String()`, `AS`, `AsName` and `Source` equal (a decode from text has different spans, so do not `DeepEqual`). In `TestCorpusMatchesMemSource`, build the corpus under comparison with `KeepPolicy: true` in one of the three comparisons (the `Source("RIPE", "RADB")` one).

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go test -run 'TestPolicy' .`
Expected: FAIL — `undefined: resolve.PolicySource`.

- [ ] **Step 3: Implement**

`resolve/policysource.go`:

```go
package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// PolicySource is a Source that also serves the objects routing policy names
// outside sets: aut-nums, whose import/export/default policies a policy
// evaluator reads, and inet-rtrs, which router expressions and peerings name.
// source scopes a lookup as a SetRef does: "" is the Source's precedence, and a
// registry it does not hold is ErrNotFound. Filter-sets, rtr-sets and
// peering-sets keep coming from GetSet.
type PolicySource interface {
	Source
	AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error)
	InetRtr(ctx context.Context, name, source string) (object.InetRtr, error)
}

// ErrNoPolicy is returned by a wrapper (Cache, rpki.Filter) whose inner Source
// is not a PolicySource.
var ErrNoPolicy = errors.New("resolve: source serves no policy objects")

// policyEntry is an aut-num or inet-rtr a MemSource serves: decoded when it
// was given decoded (NewMemSource, or a Corpus claimant), else its text.
type policyEntry struct {
	source string // upper-case
	obj    object.Object
	text   string
}

// decode returns the entry's object, decoding its text on each call: a
// MemSource stays immutable and shareable, and a Cache is what remembers.
// Decode diagnostics are dropped; the loader reported them.
func (e policyEntry) decode() object.Object {
	if e.obj != nil {
		return e.obj
	}
	raw, _ := rpsl.ParseObject(e.text)
	o, _ := object.Decode(raw)
	return value(o)
}

// pick returns the entry a lookup in source selects: "" the first the default
// sources admit, a registry that registry's.
func (s *MemSource) pick(entries []policyEntry, source string) (policyEntry, error) {
	if source != "" {
		src, err := types.ParseSourceName(source)
		if err != nil {
			return policyEntry{}, err
		}
		source = src
	}
	for _, e := range entries {
		if source != "" && e.source == source || source == "" && s.admits(e.source) {
			return e, nil
		}
	}
	return policyEntry{}, ErrNotFound
}

// AutNum returns the aut-num of as, from source ("" for the precedence).
func (s *MemSource) AutNum(_ context.Context, as types.ASN, source string) (object.AutNum, error) {
	e, err := s.pick(s.autnums[as], source)
	if err != nil {
		return object.AutNum{}, fmt.Errorf("resolve: aut-num %s: %w", as, err)
	}
	an, ok := e.decode().(object.AutNum)
	if !ok || an.AS != as {
		return object.AutNum{}, fmt.Errorf("resolve: aut-num %s: %w", as, ErrNotFound)
	}
	return an, nil
}

// InetRtr returns the inet-rtr named name (compared without regard to case),
// from source ("" for the precedence).
func (s *MemSource) InetRtr(_ context.Context, name, source string) (object.InetRtr, error) {
	e, err := s.pick(s.rtrs[rtrKey(name)], source)
	if err != nil {
		return object.InetRtr{}, fmt.Errorf("resolve: inet-rtr %s: %w", name, err)
	}
	ir, ok := e.decode().(object.InetRtr)
	if !ok || rtrKey(ir.Name) != rtrKey(name) {
		return object.InetRtr{}, fmt.Errorf("resolve: inet-rtr %s: %w", name, ErrNotFound)
	}
	return ir, nil
}

// rtrKey is an inet-rtr's primary key as Corpus keys it.
func rtrKey(name string) string { return strings.ToUpper(strings.TrimSpace(name)) }

// addPolicy indexes an aut-num or inet-rtr: decoded (o set) or as text (o nil,
// class and key read from Corpus's key).
func (s *MemSource) addPolicy(class, key, source string, o object.Object, text string) {
	e := policyEntry{source: strings.ToUpper(strings.TrimSpace(source)), obj: o, text: text}
	switch class {
	case "aut-num":
		if as, err := types.ParseASN(key); err == nil {
			s.autnums[as] = append(s.autnums[as], e)
		}
	case "inet-rtr":
		s.rtrs[rtrKey(key)] = append(s.rtrs[rtrKey(key)], e)
	}
}
```

Also add `var _ PolicySource = (*MemSource)(nil)`.

`resolve/memsource.go`:
- `MemSource` gains `autnums map[types.ASN][]policyEntry`, `rtrs map[string][]policyEntry`, `rank func(source string) int`.
- `newMemSource`: initialize both maps; keep `rank` on the struct; in the loop, after `indexClaims`, add

```go
		switch t := o.(type) {
		case object.AutNum:
			s.addPolicy("aut-num", t.AS.String(), t.Source, t, "")
		case object.InetRtr:
			s.addPolicy("inet-rtr", t.Name, t.Source, t, "")
		}
```

  and replace the final sort loop with a call to `s.finish()`:

```go
// finish orders every copy of a set, aut-num and inet-rtr by precedence;
// ties keep load order, so the object loaded first wins.
func (s *MemSource) finish() {
	for _, copies := range s.sets {
		sort.SliceStable(copies, func(i, j int) bool { return s.rank(copies[i].source) < s.rank(copies[j].source) })
	}
	for _, es := range s.autnums {
		sort.SliceStable(es, func(i, j int) bool { return s.rank(es[i].source) < s.rank(es[j].source) })
	}
	for _, es := range s.rtrs {
		sort.SliceStable(es, func(i, j int) bool { return s.rank(es[i].source) < s.rank(es[j].source) })
	}
}
```

`resolve/corpus.go`:
- `Corpus` gains, first in the struct and documented:

```go
	// KeepPolicy keeps every aut-num and inet-rtr, as its text, so that a
	// MemSource built from the corpus is a PolicySource that serves them (an
	// aut-num costs 2.5 KB as text, 18 KB decoded: RIPE's 39,918 take 95 MB).
	// Set it before the first Put. Without it only those that claim membership
	// of a set are kept.
	KeepPolicy bool
```

- `held` gains `text string // an aut-num or inet-rtr kept as text (KeepPolicy); obj is nil then`.
- In `Put`, the tail after `if claims && len(memberOf) > 0 { c.putWhole(k, o); return true }` becomes:

```go
	if c.KeepPolicy && (class == "aut-num" || class == "inet-rtr") {
		if raw := o.Raw(); raw != nil {
			c.putText(k, raw.String())
		} else {
			c.putWhole(k, o) // built by hand: no text to keep
		}
		return true
	}
	delete(c.whole, k)
	…the existing route branch and return false…
```

  with

```go
// putText is putWhole for an object kept as its text.
func (c *Corpus) putText(k wholeKey, text string) {
	if h, ok := c.whole[k]; ok {
		c.whole[k] = held{text: text, key: k, seq: h.seq}
		return
	}
	c.seq++
	c.whole[k] = held{text: text, key: k, seq: c.seq}
}
```

  (`object.Object` has `Raw() *ast.Object`; it is nil for an object built by hand.)
- `build`: pass only held entries with `obj != nil` in `objs`; after `newMemSource`, add the text ones and re-finish:

```go
	for _, h := range hs {
		if h.obj == nil && h.text != "" {
			s.addPolicy(h.key.class, h.key.pk, h.key.source, nil, h.text)
		}
	}
	s.finish()
```

- `Merge` copies `held` values as they are, text included — check that it does not dereference `h.obj`.

`resolve/cache.go`: add kinds `kindAutNum`, `kindInetRtr`; `cacheEntry` gains `obj object.Object`; and

```go
// AutNum returns the aut-num of as, from the cache when it is there and fresh.
func (c *Cache) AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error) {
	ps, ok := c.Src.(PolicySource)
	if !ok {
		return object.AutNum{}, ErrNoPolicy
	}
	e, err := c.lookup(ctx, cacheKey{kind: kindAutNum, as: as, name: strings.ToUpper(source)}, func(ctx context.Context, e *cacheEntry) {
		an, err := ps.AutNum(ctx, as, source)
		e.obj, e.err = an, err
	})
	if err != nil {
		return object.AutNum{}, err
	}
	if e.err != nil {
		return object.AutNum{}, e.err
	}
	return e.obj.(object.AutNum), nil
}

// InetRtr returns the inet-rtr named name, from the cache when it is there and fresh.
func (c *Cache) InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) {
	ps, ok := c.Src.(PolicySource)
	if !ok {
		return object.InetRtr{}, ErrNoPolicy
	}
	key := cacheKey{kind: kindInetRtr, name: strings.ToUpper(source) + "::" + rtrKey(name)}
	e, err := c.lookup(ctx, key, func(ctx context.Context, e *cacheEntry) {
		ir, err := ps.InetRtr(ctx, name, source)
		e.obj, e.err = ir, err
	})
	if err != nil {
		return object.InetRtr{}, err
	}
	if e.err != nil {
		return object.InetRtr{}, e.err
	}
	return e.obj.(object.InetRtr), nil
}

var _ PolicySource = (*Cache)(nil)
```

`resolve/rpki/filter.go`:

```go
// AutNum returns Src's aut-num unchanged: RPKI suppresses route objects only.
func (f *Filter) AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error) {
	ps, ok := f.Src.(resolve.PolicySource)
	if !ok {
		return object.AutNum{}, resolve.ErrNoPolicy
	}
	return ps.AutNum(ctx, as, source)
}

// InetRtr returns Src's inet-rtr unchanged.
func (f *Filter) InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) {
	ps, ok := f.Src.(resolve.PolicySource)
	if !ok {
		return object.InetRtr{}, resolve.ErrNoPolicy
	}
	return ps.InetRtr(ctx, name, source)
}

var _ resolve.PolicySource = (*Filter)(nil)
```

- [ ] **Step 4: Run to verify pass**

Run: `cd resolve && go test ./... && go list -deps . | grep -x net`
Expected: PASS; the `grep` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add resolve/policysource.go resolve/policysource_test.go resolve/memsource.go resolve/corpus.go resolve/cache.go resolve/rpki/filter.go resolve/corpus_test.go
git commit -m "resolve: PolicySource serves aut-nums and inet-rtrs; Corpus.KeepPolicy keeps them as text"
```

---

### Task 12: `PolicySource` over IRRd and whois; `KeepPolicy` on `DumpLoader` and `nrtm4.Client`

**Files:**
- Modify: `resolve/irrd/irrd.go` (`AutNum`, `InetRtr`, `fetchObject`)
- Modify: `resolve/whois/whois.go` (`AutNum`, `InetRtr`)
- Modify: `resolve/dump.go` (`KeepPolicy`)
- Modify: `resolve/nrtm4/client.go` (`KeepPolicy`; `loadSnapshot` at ~347)
- Create: `resolve/irrd/policy_test.go`, `resolve/whois/policy_test.go`
- Modify: `resolve/nrtm4/client_test.go`, `resolve/corpus_test.go` (DumpLoader case)

**Interfaces:**
- Consumes: `resolve.PolicySource`, `Corpus.KeepPolicy` (Task 11); `irrd.Source.in` (Task 8); `whois.Source.queryObjectsIn`, `unknownSource` (Task 7).
- Produces: `*irrd.Source` and `*whois.Source` implement `resolve.PolicySource`; `DumpLoader.KeepPolicy bool`; `nrtm4.Client.KeepPolicy bool`.

- [ ] **Step 1: Write the failing tests**

`resolve/irrd/policy_test.go` and `resolve/whois/policy_test.go` share one body — write it in each package with its backend (`irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}` / `whois.Source{Addr: db.Whois(t), Sources: …}`):

```go
func TestPolicyLookups(t *testing.T) {
	db := irrtest.New(
		"aut-num: AS1\nas-name: ONE-RIPE\nimport: from AS2 accept ANY\nsource: RIPE\n",
		"aut-num: AS1\nas-name: ONE-PROXY\nsource: RADB\n",
		"inet-rtr: rtr1.example.net\nlocal-as: AS1\nifaddr: 192.0.2.1 masklen 30\nsource: RIPE\n",
	)
	src := newBackend(t, db) // the package's Source, Sources RIPE then RADB
	defer closeBackend(src)
	var _ resolve.PolicySource = src
	ctx := context.Background()
	for source, want := range map[string]string{"": "ONE-RIPE", "RADB": "ONE-PROXY"} {
		an, err := src.AutNum(ctx, 1, source)
		if err != nil || an.AsName != want || len(an.Imports) != 1 && want == "ONE-RIPE" {
			t.Errorf("AutNum(AS1, %q) = %q, %v; want %q", source, an.AsName, err, want)
		}
	}
	if _, err := src.AutNum(ctx, 9, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("missing aut-num: %v", err)
	}
	if _, err := src.AutNum(ctx, 1, "NOSUCH"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: %v", err)
	}
	if ir, err := src.InetRtr(ctx, "rtr1.example.net", ""); err != nil || ir.LocalAS != 1 {
		t.Errorf("InetRtr = %+v, %v", ir, err)
	}
	if _, err := src.InetRtr(ctx, "rtr1.example.net\n!q", ""); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a router name with a newline was not refused: %v", err)
	}
}
```

(`newBackend`/`closeBackend`: two lines each in the test file; irrd's `closeBackend` calls `Close`, whois's does nothing.)

Append to `resolve/nrtm4/client_test.go`:

```go
func TestClientKeepsPolicy(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(nrtmtest.Change{Class: "aut-num", PK: "AS1",
		Text: "aut-num: AS1\nas-name: ONE\nimport: from AS2 accept ANY\nsource: TEST\n"})
	s.Snapshot()
	c := newClient(s, "TEST")
	c.KeepPolicy = true
	mustSync(t, c)
	an, err := c.Source().AutNum(context.Background(), 1, "")
	if err != nil || an.AsName != "ONE" {
		t.Fatalf("AutNum = %q, %v", an.AsName, err)
	}
	s.Publish(nrtmtest.Change{Delete: true, Class: "aut-num", PK: "AS1"})
	mustSync(t, c)
	if _, err := c.Source().AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("after the delta's delete: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd resolve && go test -run 'TestPolicyLookups' ./irrd ./whois && go test -run TestClientKeepsPolicy ./nrtm4`
Expected: FAIL — `src.AutNum undefined`, `unknown field KeepPolicy`.

- [ ] **Step 3: Implement**

`resolve/irrd/irrd.go`:

```go
// AutNum fetches the aut-num of as ("!maut-num,AS1"), in source alone when it
// is set; a registry the server does not have is resolve.ErrNotFound.
func (s *Source) AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error) {
	o, err := s.fetchObject(ctx, "aut-num", as.String(), source)
	if err != nil {
		return object.AutNum{}, err
	}
	an, ok := o.(object.AutNum)
	if !ok || an.AS != as {
		return object.AutNum{}, fmt.Errorf("irrd: !maut-num,%s answered with another object", as)
	}
	return an, nil
}

// InetRtr fetches the inet-rtr named name ("!minet-rtr,<name>"), in source
// alone when it is set. The name must be a DNS name.
func (s *Source) InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) {
	if !dnsName(name) {
		return object.InetRtr{}, fmt.Errorf("irrd: invalid inet-rtr name %q", name)
	}
	o, err := s.fetchObject(ctx, "inet-rtr", name, source)
	if err != nil {
		return object.InetRtr{}, err
	}
	ir, ok := o.(object.InetRtr)
	if !ok || !strings.EqualFold(strings.TrimSpace(ir.Name), name) {
		return object.InetRtr{}, fmt.Errorf("irrd: !minet-rtr,%s answered with another object", name)
	}
	return ir, nil
}

// fetchObject fetches and decodes one object with "!m", through the sub-source
// of source when it is set.
func (s *Source) fetchObject(ctx context.Context, class, key, source string) (object.Object, error) {
	q := s
	if source != "" {
		reg, err := types.ParseSourceName(source)
		if err != nil {
			return nil, err
		}
		q = s.in(reg)
	}
	payload, err := q.do(ctx, "!m"+class+","+key)
	if errors.Is(err, errNotFound) || errors.Is(err, errUnknownSource) {
		return nil, resolve.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	raw, _ := rpsl.ParseObject(string(payload))
	o, _ := object.Decode(raw)
	return o, nil
}

// dnsName reports whether n is letters, digits, '-' and '.' only, so it
// cannot carry another command.
func dnsName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

var _ resolve.PolicySource = (*Source)(nil)
```

`resolve/whois/whois.go`: the same two methods over `queryObjectsIn`:

```go
// AutNum fetches the aut-num of as, from Sources' priority or, when source is
// set, from that registry alone; a registry the server does not know is
// resolve.ErrNotFound.
func (s *Source) AutNum(ctx context.Context, as types.ASN, source string) (object.AutNum, error) {
	o, err := s.fetchOne(ctx, "aut-num", as.String(), source, func(o object.Object) bool {
		an, ok := o.(object.AutNum)
		return ok && an.AS == as
	})
	if err != nil {
		return object.AutNum{}, err
	}
	return o.(object.AutNum), nil
}

// InetRtr fetches the inet-rtr named name, as AutNum does.
func (s *Source) InetRtr(ctx context.Context, name, source string) (object.InetRtr, error) {
	if !dnsName(name) {
		return object.InetRtr{}, fmt.Errorf("whois: invalid inet-rtr name %q", name)
	}
	o, err := s.fetchOne(ctx, "inet-rtr", name, source, func(o object.Object) bool {
		ir, ok := o.(object.InetRtr)
		return ok && strings.EqualFold(strings.TrimSpace(ir.Name), name)
	})
	if err != nil {
		return object.InetRtr{}, err
	}
	return o.(object.InetRtr), nil
}

// fetchOne queries "-r -T class key" and returns the object match accepts from
// the best-ranked source.
func (s *Source) fetchOne(ctx context.Context, class, key, source string, match func(object.Object) bool) (object.Object, error) {
	sources := s.Sources
	if source != "" {
		reg, err := types.ParseSourceName(source)
		if err != nil {
			return nil, err
		}
		sources = []string{reg}
	}
	objs, err := s.queryObjectsIn(ctx, sources, "-r -T "+class+" "+key)
	if err != nil {
		if source != "" && unknownSource(err) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	var best object.Object
	bestRank := len(sources) + 1
	for _, o := range objs {
		if !match(o) {
			continue
		}
		rank := slices.IndexFunc(sources, func(n string) bool { return strings.EqualFold(n, objectSource(o)) })
		if rank < 0 {
			if source != "" {
				continue
			}
			rank = len(sources)
		}
		if rank < bestRank {
			best, bestRank = o, rank
		}
	}
	if best == nil {
		return nil, resolve.ErrNotFound
	}
	return best, nil
}

// objectSource is an aut-num's or inet-rtr's source: attribute.
func objectSource(o object.Object) string {
	switch t := o.(type) {
	case object.AutNum:
		return strings.TrimSpace(t.Source)
	case object.InetRtr:
		return strings.TrimSpace(t.Source)
	}
	return ""
}
```

plus a `dnsName` identical to irrd's, and `var _ resolve.PolicySource = (*Source)(nil)`.

`resolve/dump.go`: `DumpLoader` gains

```go
	// KeepPolicy keeps every aut-num and inet-rtr (as Corpus.KeepPolicy does),
	// so that Source and SourceOf are PolicySources that serve them. Set it
	// before the first Read.
	KeepPolicy bool
```

and `Read` sets `l.corpus.KeepPolicy = l.KeepPolicy` as its first statement.

`resolve/nrtm4/client.go`: `Client` gains `KeepPolicy bool // keep aut-nums and inet-rtrs, so Source() serves them (resolve.Corpus.KeepPolicy)`; `loadSnapshot`'s `corpus := &resolve.Corpus{}` becomes `corpus := &resolve.Corpus{KeepPolicy: c.KeepPolicy}`. Nothing else changes: the client's class filter (`resolve.ExpandableClass`, `client.go` ~497) already keeps aut-num and inet-rtr, and the Corpus decides what to hold.

Append to `corpus_test.go` a `DumpLoader` case: `l := &resolve.DumpLoader{KeepPolicy: true}`, `l.Read(strings.NewReader(strings.Join(policyTexts, "\n")))`, then `checkPolicy(t, "DumpLoader", l.Source("RIPE", "RADB"))` (both helpers are in `policysource_test.go`, same package). DumpLoader's `Source` takes no arguments (it uses `l.Sources`), so set `Sources: []string{"RIPE", "RADB"}` in the literal and call `l.Source()`.

- [ ] **Step 4: Run to verify pass**

Run: `cd resolve && go test ./... -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add resolve/irrd resolve/whois resolve/dump.go resolve/nrtm4 resolve/corpus_test.go
git commit -m "resolve: PolicySource over IRRd and whois; KeepPolicy for dumps and NRTMv4 mirrors"
```

---

### Task 13: Opt-in real-data and live checks

**Files:**
- Modify: `resolve/corpus_realdata_test.go` (KeepPolicy heap bound, decode equivalence)
- Modify: `resolve/live_test.go` (scoped lookups and unknown registries over RADB and RIPE)

**Interfaces:**
- Consumes: everything above.
- Produces: tests only (run only with `RPSL_REALDATA` / `RPSL_LIVE`).

- [ ] **Step 1: Real data**

Add to `corpus_realdata_test.go` (it already imports `compress/gzip`, `os`, `path/filepath`, `rpsl`, `object`; add `runtime` and `context` if missing):

```go
// TestRealDataKeepPolicy: RIPE's dumps with KeepPolicy cost at most 150 MB
// more heap than without (95 MB of aut-num text measured, plus index), and
// every aut-num decoded on demand is the one decoded at load.
func TestRealDataKeepPolicy(t *testing.T) {
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ripe", "*.gz"))
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	load := func(keep bool) (*resolve.DumpLoader, uint64) {
		before := heap()
		l := &resolve.DumpLoader{KeepPolicy: keep, Sources: []string{"RIPE"}}
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Read(zr); err != nil {
				t.Fatal(err)
			}
			fh.Close()
		}
		return l, heap() - before
	}
	_, without := load(false)
	l, with := load(true)
	if extra := int64(with) - int64(without); extra > 150<<20 {
		t.Errorf("KeepPolicy costs %d MB, over the 150 MB bound", extra>>20)
	}
	src := l.Source()
	fh, err := os.Open(filepath.Join(dir, "ripe", "ripe.db.aut-num.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for raw := range rpsl.Parse(zr) {
		o, _ := object.Decode(raw)
		want, ok := o.(object.AutNum)
		if !ok {
			continue
		}
		got, err := src.AutNum(context.Background(), want.AS, "RIPE")
		if err != nil || got.Raw().String() != want.Raw().String() {
			t.Fatalf("%s: on-demand decode differs (%v)", want.AS, err)
		}
		n++
	}
	t.Logf("%d aut-nums, KeepPolicy +%d MB", n, (int64(with)-int64(without))>>20)
}
```


- [ ] **Step 2: Live**

Add to `live_test.go` (under its existing `RPSL_LIVE` guard):

```go
func TestLiveScoped(t *testing.T) {
	if os.Getenv("RPSL_LIVE") == "" {
		t.Skip("set RPSL_LIVE=1 to query whois.radb.net and whois.ripe.net")
	}
	ctx := context.Background()
	ir := &irrd.Source{Addr: "whois.radb.net:43", Sources: []string{"RADB"}, Timeout: 30 * time.Second}
	defer ir.Close()
	wh := &whois.Source{Addr: "whois.ripe.net:43", Timeout: 30 * time.Second}
	ref, _ := types.ParseSetRef("RIPE::AS-RIPENCC") // the stable as-set TestLiveSmoke relies on
	for name, src := range map[string]resolve.Source{"radb !sRIPE": ir, "ripe whois": wh} {
		if set, err := src.GetSet(ctx, ref); err != nil || !strings.EqualFold(set.SetSource(), "RIPE") {
			t.Errorf("%s: %s = %v, %v", name, ref, set, err)
		}
		bogus, _ := types.ParseSetRef("NOSUCHREGISTRY::AS-TEST")
		if _, err := src.GetSet(ctx, bogus); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: unknown registry: err = %v, want ErrNotFound", name, err)
		}
	}
	for name, ps := range map[string]resolve.PolicySource{"radb": ir, "ripe whois": wh} {
		if an, err := ps.AutNum(ctx, 3333, "RIPE"); err != nil || an.AS != 3333 {
			t.Errorf("%s: AS3333 from RIPE = %v, %v", name, an.AS, err)
		}
	}
}
```

- [ ] **Step 3: Run**

Run: `cd resolve && RPSL_REALDATA=$PWD/../.data go test -run TestRealDataKeepPolicy -timeout 30m . && RPSL_LIVE=1 go test -run TestLiveScoped .`
Expected: PASS; the real-data log line shows the aut-num count (≈ 39,918) and the extra heap.

- [ ] **Step 4: Commit**

```bash
git add resolve/corpus_realdata_test.go resolve/live_test.go
git commit -m "resolve: opt-in real-data and live checks for KeepPolicy and scoped lookups"
```

---

### Task 14: Documentation, invariants, and the full check

**Files:**
- Modify: `docs/rpsl-go-design.md` (§5, §6, §8.1, §8.2, §8.3, §8.9, §10, §11)
- Modify: `CLAUDE.md` (engine traps; fuzz list 33 → 35; rpslq long-option sentence)
- Modify: `README.md` (status matrix; fuzz list)
- Modify: `CHANGELOG.md` (Unreleased → v0.20.0 notes)

**Interfaces:** none.

- [ ] **Step 1: Design doc**

- §5 `types`: add `SetRef` beside `SetName` (the spec §4 block, trimmed to the type and constructors).
- §6 `object`: `SrcMembers` on `AsSet`/`RouteSet`, `SetSrcMembers`, `DirectMembers`, `WithSrcMembers`.
- §8.1: the `Source` block's `GetSet` takes `types.SetRef`; add `PolicySource` after it with two sentences from spec §8.
- §8.2: a paragraph "Registry-scoped members": the draft, §2.3's two steps, no cascade, a scoped miss never falls back, a conflict falls back to members:.
- §8.3: in "Cycle detection", say the graph key is the reference, so one name in two scopes is two nodes; in "Missing and unexpandable sets", an unknown registry is missing.
- §8.9: `KeepPolicy` and its measured cost (707 MB decoded vs 95 MB text for RIPE's aut-nums).
- §10: a bullet "Same-named sets in several registries": `src-members:` resolves them where written; bgpq4 and IRRd do not implement it (divergence pinned).
- §11 item 5: fuzz targets now include `FuzzParseSetRef` and `FuzzParseSrcMember`.

- [ ] **Step 2: CLAUDE.md**

Under "Engine correctness traps" add:

```
- **Registry-scoped members** (draft-ietf-grow-rpsl-registry-scoped-members): `object.DirectMembers`
  is the one place the draft's member selection lives; the engine keys its graph by `types.SetRef`,
  so `RIPE::AS-X` and `AS-X` are two nodes. The scope never cascades (a node's nested refs come from
  its own object) and a scoped miss never falls back to precedence. `checkSet` refuses a scoped
  answer from another registry. `Corpus.SourceOf` restricts unscoped lookups and routes only.
- **`PolicySource`**: `Corpus.KeepPolicy` holds aut-nums and inet-rtrs as text (95 MB for RIPE),
  decoded per call — never decoded in memory (707 MB).
```

In "Commands": the fuzz count becomes 35 and the list gains `FuzzParseSetRef (types)` and `FuzzParseSrcMember (object)`. Replace "rpslq-only options are `--long`" with "rpslq-only options are long options (`-P` and `-c` are rpslq's two short exceptions, kept for compatibility)" — check `docs/rpslq.md` for what `-P` and `-c` do and say it in five words each.

- [ ] **Step 3: README and CHANGELOG**

README: in the status matrix, a row for registry-scoped members and one for `PolicySource`; the fuzz list gains the two targets and `FuzzCorpusDelete` (missing today).

CHANGELOG, a new section at the top in the file's existing format:

```
## Unreleased (v0.20.0)

### Added
- `src-members:` (draft-ietf-grow-rpsl-registry-scoped-members-00): decoded on as-set and route-set,
  validated (three diagnostics per class), resolved by every backend; `types.SetRef`, `object.DirectMembers`,
  `object.WithSrcMembers`, `irrd.Source.SrcMembers`, rpslq `--src-members`.
- `resolve.PolicySource` (aut-nums and inet-rtrs) over MemSource, Corpus (`KeepPolicy`), DumpLoader,
  nrtm4.Client, irrd, whois, Cache and rpki.Filter.

### Breaking
- `Source.GetSet` takes a `types.SetRef`: implementers change the parameter and use `ref.Name()`;
  honour `ref.Source()` or return an error for a scoped ref.
- `Expander.Expand*` take a `types.SetRef`: wrap names with `types.Ref(name)`.
- `Missing()` returns `[]types.SetRef`: `String()` prints unscoped refs as before.
- `SetTooLargeError.Name` is a `types.SetRef`.
- `object.Set` gains `SetSrcMembers()`: add it (return nil) to a custom set type.
- `Corpus.SourceOf`/`DumpLoader.SourceOf`: scoped lookups and claims reach every held source.
- `ErrNotFound`'s message is "resolve: not found" (same value).
```

- [ ] **Step 4: Run the full check**

Run: `FUZZTIME=15s scripts/check.sh`
Expected: every module green under `-race`, gofmt clean, staticcheck and govulncheck clean, leaf-isolation and engine-purity invariants hold, all 35 fuzz targets run 15 s without a failure. If bgpq4 is installed, every differential test passes.

- [ ] **Step 5: Commit**

```bash
git add docs/rpsl-go-design.md CLAUDE.md README.md CHANGELOG.md
git commit -m "docs: src-members, PolicySource, and the v0.20.0 breaking changes"
```

Release is a separate step, done when the user asks: rehearse with `scripts/release-dryrun.sh`, then `scripts/release.sh v0.20.0` (it bumps the inter-module requires; `types` must be tagged first, as RELEASING.md orders).
