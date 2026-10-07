# Pre-v1 API consolidation and an API-surface guard

Status: design approved in brainstorming · 2026-10-07 · planned v0.26.0

## 1. Summary

The library stays on 0.x so its API can still break cheaply; this release
spends that window on consistency, so a later v1 freezes a surface worth
keeping. It changes no behaviour: every golden, differential and real-data
result stays as it is. It does three things:

1. Writes down five API conventions (§3) and brings the public packages in
   line with them (§4).
2. Adds a checked-in golden of the public API's signatures, plus three
   mechanical convention checks, run by `scripts/check.sh` (§5), so every
   later API change is a visible diff.
3. Records the conventions in CLAUDE.md and the design document (§7).

The inventory covered the 18 public packages (every package outside
`internal/`, `cmd/` and `examples/`) and about 450 exported top-level
symbols. A GitHub code search on 2026-10-07 found no repository importing
the module, so breaks carry no migration cost and no deprecated shims are
kept.

### Decisions taken in brainstorming

1. **Scope: the findings plus a guard.** Not the findings alone (the next
   release could drift again unseen), not a full symbol-by-symbol audit
   (two releases' worth of diff for little gain).
2. **Options: a plain function and an `XWith`.** `X(in)` takes the zero
   options; `XWith(in, Options)` takes them all. This is the shape
   `rpsl.Parse`/`rpsl.ParseWith` already has. Rejected: options always
   required (would turn `rpsl.Parse(r)` into `Parse(r, ParseOptions{})`), and
   one `ParseAttribute(name, value)` returning a sealed interface (callers
   type-assert; a misspelt attribute name fails only at run time).
3. **Object classes are pointers.** Rejected: values, documented — it keeps
   "either form works" as a caveat every new type switch must remember,
   which the compiler cannot check.
4. **Guard: a signature golden from a standard-library tool**, run by
   `check.sh`. Rejected: `go doc -all` goldens (every comment edit churns
   them; Go 1.23.0 and 1.27.1 print them identically, so version drift was
   not the problem) and `apidiff`/`gorelease` (install `golang.org/x/exp`,
   compare against a tag rather than the PR's base, do not show additions).

### Corrected after the design was approved

Section 1 of the design proposed turning `types.NewPrefixRange`'s `ok bool`
into an `error`. Writing the spec showed it is one of a family —
`PrefixRange.Intersect`, `RangeOperator.Apply` and `NewPrefixRange` — whose
`ok == false` means "the result is empty", an ordinary outcome of range
arithmetic (an AND whose sides do not overlap, `^24` applied under a /25),
not malformed input. An `error` would make callers treat an empty result as
a failure. `NewPrefixRange` therefore stays, rule 2 (§3) distinguishes the
two cases, and check C2 (§5.3) looks at `Parse*` functions only.

## 2. Architecture

Nothing moves between modules except one function, `resolve.ObjectText`,
which becomes a method in `ast` (§4.6). Import direction is unchanged:
`ast` already imports `lexer`, whose `StartsAttribute` the method uses.

The guard (§5) is a command in the root module, `internal/apisurface`. It
reads source files by path, so it reaches the nested modules without
module plumbing, and it imports only the standard library.

## 3. The conventions

These are the rules the public API follows from this release on. §7 says
where they are written down.

1. **Options.** A function with options has two forms: `X(in)` with the
   zero options, and `XWith(in, XOptions)` with all of them. `X(in)` equals
   `XWith(in, XOptions{})`.
2. **Errors, diagnostics and comma-ok.**
   - A parser of a whole attribute value recovers and reports every problem
     it finds: it returns `(T, []ast.Diagnostic)` and never an `error`.
   - A parser or constructor of one value (`types.ParseASN`,
     `object.ParseAuth`, `policy.ParseASPathRegexp`) succeeds or fails: it
     returns `(T, error)`.
   - A trailing `ok bool` is for a false case that is an expected outcome:
     a lookup miss (`GetFirst`, `Dictionary.Attr`, `ASPAs.Providers`) or an
     empty result (`Intersect`, `Apply`, `NewPrefixRange`). Malformed input
     is always an `error`, so no `Parse*` function returns a `bool`.
3. **Pointers and values.**
   - Every `object` class is a pointer: `object.Decode` returns `*object.X`,
     and every method of a class has a pointer receiver, so only `*object.X`
     implements `object.Object`.
   - Parsed values (`types.*`, `object.Auth`, `object.SetMember`, …), policy
     AST nodes and expansion results (`resolve.ASNSet`, …) are values.
   - A type holding an index, a cache or a connection is a pointer
     (`MemSource`, `Corpus`, `rpki.VRPs`, `irrd.Source`).
4. **Names.** A type is named after an RPSL class only if it is that class.
5. **Sentinel errors** are declared with `errors.New`.

## 4. The changes

### 4.1 `policy`: 13 parse entry points become 6

Before: `ParseImport`, `ParseMPImport`, `ParseImportWith(s, mp, o)`,
`ParseImportVia`, `ParseImportViaWith`, the same five for export, and three
for default (`ParseDefault`, `ParseMPDefault`, `ParseDefaultWith`).

After:

```go
type Options struct {
	MP   bool        // mp-import:/mp-export:/mp-default: syntax (RFC 4012)
	Via  bool        // import-via:/export-via: syntax; implies MP
	Dict *Dictionary // nil: actions and protocols are checked for syntax only
}

func ParseImport(s string) (Import, []ast.Diagnostic)
func ParseImportWith(s string, o Options) (Import, []ast.Diagnostic)
func ParseExport(s string) (Export, []ast.Diagnostic)
func ParseExportWith(s string, o Options) (Export, []ast.Diagnostic)
func ParseDefault(s string) (Default, []ast.Diagnostic)
func ParseDefaultWith(s string, o Options) (Default, []ast.Diagnostic)
```

- `Via` implies `MP`: the result's `MP` is true, as `ParseImportVia`'s is
  today (without an afi clause a via policy applies to every family).
- RFC 2622 has no `default-via:`. `ParseDefaultWith` with `Via` set parses
  the value as `mp-default:` and adds one Error diagnostic, rule
  `policy/no-default-via`, spanning the whole value.
- Each family has one internal parse function taking `Options`; today
  `ParseImportWith` (`policy/dict.go:168`) repeats `parseImport`'s body
  (`policy/parse.go:33`), and export and default do the same. The plain
  form calls the `With` form.
- The `aut-num` decoder (`object/classes.go:57-89`) makes one call per
  family: `policy.ParseImportWith(a.Value, policy.Options{MP: a.Name ==
  "mp-import", Via: a.Name == "import-via"})`, and likewise for export and
  default.
- `Options` keeps its name: it is the only options type in `policy`.

### 4.2 `object`: classes are pointers

All 23 types with a `Class()` method — `AsBlock`, `AsSet`, `AutNum`,
`Dictionary`, `Domain`, `FilterSet`, `Generic`, `Inet6num`, `Inetnum`,
`InetRtr`, `Irt`, `KeyCert`, `Mntner`, `Organisation`, `PeeringSet`,
`Person`, `Poem`, `PoeticForm`, `Role`, `Route`, `Route6`, `RouteSet`,
`RtrSet` — get pointer receivers on every method, and `Decode` returns a
non-nil pointer for each.

Once the receivers change, the value `object.Route` no longer implements
`object.Object`, and the compiler rejects every remaining `case
object.Route:` on an `object.Object` ("impossible type switch case"). That
makes the migration compiler-driven: about 110 case arms and 82 struct
literals across the repository, most in tests.

Value types stay values: `Auth`, `Changed`, `Timestamp`, `SetMember`,
`RtrSetMember`, `AttrSpec`, `ClassSpec`, `Profile`, `Registry`.

### 4.3 Interfaces and functions that carry objects

The pointer rule reaches every exported signature that carries a class:

| Package | Before | After |
|---|---|---|
| `resolve` | `PolicySource.AutNum(...) (object.AutNum, error)`, `InetRtr(...) (object.InetRtr, error)` | `(*object.AutNum, error)`, `(*object.InetRtr, error)` |
| `resolve` | `value()` (`resolve/claims.go:152`) turns pointers into values | deleted; `ClaimAllowed`'s doc loses "(as values or pointers)" |
| `resolve`, `resolve/irrd`, `resolve/whois`, `resolve/rpki` | the implementations: `MemSource`, `Cache`, `irrd.Source`, `whois.Source`, `rpki.Filter` (`AutNum`, `InetRtr`) | pointers |
| `auth` | `Registry.Mntner(...) (object.Mntner, error)`, `IrtRegistry.Irt(...) (object.Irt, error)`, `Database.ASBlocks(...) ([]object.AsBlock, error)`, `ReferralChain(...) ([]object.Mntner, error)`, and `MemDatabase`'s implementations | pointers |
| `auth` | `CheckMntner(ctx, m object.Mntner, …)`, `CheckIrt(ctx, irt object.Irt, …)`, `RouteRequestFor(r object.Route, …)`, `RouteRequestFor6(r object.Route6, …)` | pointer parameters |

That is every exported signature naming a class by value on 2026-10-07; no
exported struct field holds a class. The API golden of §5 (commit 1) makes
the list checkable: after commit 3, no line under `api/` names
`object.<Class>` without a `*`.

### 4.4 Renames

| Before | After | Why |
|---|---|---|
| `object.RouterSet` (interface) | `object.RouterGroup` | its siblings are `PeeringGroup` and `FilterGroup`; the class is `object.RtrSet` |
| `resolve.PeeringSet` (expansion result) | `resolve.Peerings` | it is a result, not the `peering-set` class (`object.PeeringSet`) |
| `resolve.RouterSet` (expansion result) | `resolve.Routers` | it is a result, not an `rtr-set`, and no longer clashes with `object.RouterSet` |

`ASNSet`, `PrefixSet` and `RangeSet` do not clash with a class and stay.
`Expander.ExpandPeerings` and `ExpandRouters` keep their names and return
the renamed types.

### 4.5 Sentinels

- `rdap.ErrNotFound` is declared with `errors.New` instead of `fmt.Errorf`.
- `irrd.ErrQueryRefused` is declared with `errors.New` and replaces the
  unexported `errQuery` it aliases today; `errors.Is` results are unchanged.

### 4.6 `resolve.ObjectText` becomes `(*ast.Object).Text`

`ObjectText` drops the blank, comment and malformed lines a stream attaches
before and after an object. That is about `ast`'s own trivia, so it moves
there as a method:

```go
// Text returns the object's text from its first attribute line to its
// last attribute or continuation line, without the trivia a stream
// attached before or after it.
func (o *Object) Text() string
```

Its callers (4 outside tests: three in `resolve/corpus.go`, one in
`resolve/irrdq/objects.go`) call the method. Its tests (`resolve/corpus_test.go`, `resolve/policyindex_test.go`,
`resolve/irrdq/objects_test.go`) keep their cases; the cases that test
`ObjectText` itself move to `ast`.

### 4.7 `resolve`: one fewer way to build a `MemSource`

- `LoadDumps` is deleted. `DumpLoader` is its general form, and only one
  test (`resolve/infra_test.go`) calls it.
- `LoadDump`'s doc says to use the loader "to set a source precedence",
  which `LoadDump` already takes; it is corrected.

### 4.8 Considered and kept

- `Source.GetSet`: a fetch, not a field getter, so `Get` stays.
- `ast.Object.GetAll`/`GetFirst`: named in CLAUDE.md and used throughout.
- `policy.ParseMPFilter`'s three results: the afi list is part of the value.
- `auth.CheckIrt`/`CheckMntner`'s `(ok, unsupported bool, err error)`:
  documented; reshaping it is outside this release.
- `types.NewPrefixRange`, `PrefixRange.Intersect`, `RangeOperator.Apply`:
  comma-ok for an empty result (§1, corrected).

## 5. The guard: `internal/apisurface`

### 5.1 The golden

`api/` holds one file per public package, named after the package path
below the module root with `/` as `_` (`api/rpsl.txt`, `api/policy.txt`,
`api/resolve_rpki.txt`, …; 18 files). Each lists, without comments:

- every exported const, var, func and type, with its full signature;
- every exported method of an exported type;
- every exported field of an exported struct, and every method of an
  exported interface;
- type aliases as aliases (`type Diagnostic = ast.Diagnostic`).

Entries are sorted by kind (const, var, func, type), then by name; a
type's methods follow the type, sorted by name. Declarations are printed
with `go/printer` from the parsed AST, one per line, so the text does not
depend on how a file was formatted.

A package is public when its directory is not under `internal/`, `cmd/` or
`examples/` and holds non-test `.go` files. The tool walks the repository
from its root and skips `testdata/`.

### 5.2 Running it

- `go run ./internal/apisurface -check` regenerates every file in memory,
  compares it with `api/`, and on a difference prints a unified diff and
  exits 1. A public package with no golden, and a golden with no package,
  are differences too.
- `RPSL_API_UPDATE=1 go run ./internal/apisurface -check` rewrites `api/`;
  review the diff.
- `scripts/check.sh` runs `-check` beside its other invariants, so CI runs
  it on both Go versions.

It runs as a command, not a `go test`: release.sh step 6 tests the
published root-module zip from an empty module cache, and that zip does not
hold the nested modules a test would need to read.

### 5.3 Convention checks

The same run reports, with file and line, and fails on any:

- **C1 (rule 1).** Every exported function or method `XWith` has a
  sibling `X` (same package, same receiver type) whose parameters are
  `XWith`'s without the last one, and whose results are the same.
- **C2 (rule 2).** No exported function or method whose name starts with
  `Parse` returns `bool` as its last result.
- **C3 (rule 5).** Every exported package-level var whose name starts with
  `Err` is initialised with a call to `errors.New`.

Rule 3 needs no check: once the receivers are pointers, the compiler
refuses a value class wherever an `object.Object` is expected, and a test
in `object` (§6) checks `Decode`. Rule 4 is left to review.

## 6. Tests

**Behaviour is unchanged.** Existing tests change mechanically — new
names, `&` on class literals, `With` forms — never in what they assert. No
file under any `testdata/` changes: the round-trip corpus, the bgpq4
snapshots, the rtconfig, rpslcheck and IRRd goldens all stay. Check:
`git diff --stat main -- '*testdata*'` lists only
`internal/apisurface/testdata/`. A golden that moves is a bug to
root-cause, never a re-recording.

New tests:

- `policy`:
  - a table over `Options`: `MP`; `Via` gives `MP == true` with or without
    `MP` set; `ParseDefaultWith` with `Via` gives one Error,
    `policy/no-default-via`, and the same AST as `MP`;
  - `X(s)` equals `XWith(s, Options{})` (AST and diagnostics) for every
    input of the policy package's import, export and default table tests
    and `FuzzParseImport`'s seeds (the root `testdata/` holds only 8 policy
    lines, too few to stand alone).
- `object`: for every class of every profile (`RIPE`, `IRRd`, `ARIN`,
  `RFCStrict`), decoding a minimal object returns a non-nil pointer of
  that class's type.
- `ast`: `Text` with `ObjectText`'s test cases, including a leading comment
  quoting the first attribute line and ARIN's trailing `EOF`.
- `internal/apisurface`: the generator over fixture packages in
  `internal/apisurface/testdata` (consts, vars, funcs, generic types,
  aliases, embedded fields, unexported members hidden), and C1–C3 each
  with one passing and one failing fixture.
- Fuzz: the target count stays 45. `FuzzParseImport` drives
  `ParseImportWith` with fuzzed `MP` and `Via` and each of the three
  families; its seeds are unchanged.

## 7. Docs and invariants

- CLAUDE.md, "Go conventions": the five rules of §3, compressed, and the
  `apisurface` command under "Commands".
- `docs/rpsl-go-design.md` §2: the conventions in full.
- CHANGELOG `## [0.26.0]`, `### Breaking`: one line per change in §4.
- `docs/rpslq.md`, `rpslconf.md`, `rpslcheck.md`, `rpsld.md` and the
  READMEs: any example naming a changed function is updated (the plan
  lists them by grep).

## 8. Order of work

Each commit compiles and passes `scripts/check.sh` on its own:

1. `internal/apisurface` and `api/` generated from the current API, so each
   later commit shows its own API change under `api/`.
2. `policy` options (§4.1).
3. `object` pointers through every module (§4.2, §4.3).
4. Renames (§4.4).
5. Sentinels, `ast.Object.Text`, `LoadDumps` (§4.5–§4.7).
6. Docs (§7).

## 9. Verification before merge

- `FUZZTIME=15s GOMAXPROCS=4 scripts/check.sh` under the memory guard.
- Real data, one registry per process: `TestRealData` for RIPE and for
  APNIC, and `TestRealDataPeval`. Their summary counts must equal a run at
  v0.25.0; one count checked by hand against its dump. Peak RSS recorded
  beside v0.25.0's (RIPE 1,096 MB).
- `scripts/bench.sh v0.25.0`. A regression over 10% is explained before
  merge.
- An independent reviewer on the full diff; its Critical and Important
  findings fixed.

Released as v0.26.0 from branch `api-v0.26` by `scripts/release.sh`. Every
module is tagged; `ast` (`Text`) and `types` (unchanged API, rebuilt
requires) move with the rest.

## 10. Out of scope

- Making `filtergen` public (the next release; it follows these
  conventions from the start).
- A full audit of every exported symbol against the conventions.
- Renaming `Source.GetSet`, reshaping `CheckIrt`/`CheckMntner`.

## 11. Risks

- **Nil pointers.** A lookup that returned a zero value on error now
  returns nil. Every new pointer result is nil exactly when its error is
  non-nil; the reviewer checks call sites that ignore the error.
- **Hidden copies.** Code that relied on a value copy (decode, then mutate a
  field of the copy) would now mutate the shared object. Search for writes
  to fields of decoded objects in non-test code before commit 3 lands.
- **Golden churn.** The golden changes with every API change by design; a
  reviewer reads `api/` diffs as the API change list.
