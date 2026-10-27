# One test for "this name is AS-ANY": `types.SetName.IsAny` — design

Approved by the user 2026-10-27.

## Why

Seven places in non-test code decide by name whether a set is AS-ANY or one of its kin, and
they spell the test three ways:

| Site | Test | Names it accepts |
|---|---|---|
| `resolve/expander.go:650` `isAnySet` | `switch n.String()` | AS-ANY, RS-ANY, RTRS-ANY, PRNG-ANY, FLTR-ANY |
| `resolve/consist/lint.go:829` `anySets` (read at :931) | map lookup on `n.String()` | the same five |
| `resolve/consist/pathall.go:90` `onesAll` | `strings.EqualFold(…, "AS-ANY")` | AS-ANY |
| `resolve/rtconfig/regex.go:61` `members` | `strings.EqualFold(…, "AS-ANY")` | AS-ANY |
| `resolve/peval/match.go:163` `inASSet` | `strings.EqualFold(…, "AS-ANY")` | AS-ANY |
| `policy/flatten.go:324` `isAnyPeering` | `strings.EqualFold(…, "AS-ANY")` | AS-ANY |
| `resolve/internal/routemodel/routemodel.go:209` `single` (test-only oracle) | `strings.EqualFold(…, "AS-ANY")` | AS-ANY |

`isAnySet` is called at 8 more places in `resolve` (normalize.go:320 and :528, expander.go:345
and :385, expand_more.go:390, :429, :486 and :634). The list was taken with
`git ls-files '*.go' | grep -v '_test.go$' | xargs grep -n -i -E '"(AS|RS|RTRS|PRNG|FLTR)-ANY"'`
on 2026-10-27 (main at 0c00b6e). The only other match, `resolve/internal/irrdoracle/cases.go:42`,
is a list of names to query IRRd with, not a test.

The second review of PR #38 (2026-10-22) counted four of these copies and suggested one
`SetName.IsAny()` in `types`. It was left for a separate change because it adds to a leaf
module's API. Nothing is wrong today: every copy gives the right answer. The risk is the next
copy. A new site would choose between two lists of names and two ways of comparing, and the
`EqualFold` copies suggest a `SetName`'s text might be in mixed case, which it never is
(`types/setname.go:45-47`, held by `TestParseSetName`'s `"as-foo"` → `"AS-FOO"` case and
`TestSetNameIsCanonical`).

## Goals

1. One exported predicate, `func (n SetName) IsAny() bool` in `types`, true for exactly the five
   names `isAnySet` accepts today.
2. All seven sites use it. `isAnySet` and `anySets` are deleted.
3. No answer changes anywhere: every existing test passes unchanged.
4. A check stops an eighth copy from being written.

## Non-goals

- What a set reaching AS-ANY means is unchanged: D19 and D20, `CauseAnySet`, `lint/any-set`,
  the ASPA rules, `AnySetError` and `ASNSet.Any()` stay as they are.
- `SetRef` gets no `IsAny`. The callers that hold a `SetRef` already read `ref.Name()`, and a
  registry scope is ignored, as `isAnySet`'s comment says today (`RIPE::AS-ANY` is AS-ANY).
- `isAnyPeering` keeps its router checks (`Router`, `AtRouter`). Only its name comparison
  changes.
- No other cleanup in the touched files.

## Anti-goals

- A predicate that accepts more or fewer names than today, such as RS-ANY only in filter
  position or a hierarchical `AS1:AS-ANY`. Either would change answers. A change in meaning is
  its own design.
- Two predicates, for example `IsAny` plus an `IsASAny` for the AS-ANY-only sites. Why one is
  enough is shown below.
- A guard that flags comments or prose that mention AS-ANY. Docs name it all the time.

## The change

### Why one predicate is enough

The five AS-ANY-only sites all get their name from a `policy.ASPathSet` (`onesAll`, `members`,
`single`) or a `policy.ASSetRef` (`isAnyPeering`; `inASSet` through `peval/match.go:135` and
:137). The parser builds both only for an as-set name: `policy/regexp.go:554` and :560 for
`ASPathSet`, `policy/parse.go:733` and :739 for `ASSetRef`. The two other builders keep the
class too. `regexp_ops.go:152` and `expand_more.go:690` instantiate an as-set template, and a
template always holds a `PeerAS` component, so it can never instantiate to a bare `AS-ANY`. Of
the five names, only `AS-ANY` is an as-set name, so `IsAny()` on these names is the same test as
`== "AS-ANY"`.

The `EqualFold` becomes an exact comparison in effect. That is safe because a `SetName`'s text
is always canonical, which the two tests named under **Why** pin.

### `types.SetName.IsAny`

In `types/setname.go`, next to `IsZero`:

```go
// IsAny reports whether n is one of the names that denote the whole IRR rather
// than a set: AS-ANY and RS-ANY, which RFC 2622 §5.3 reserves, and RTRS-ANY,
// PRNG-ANY and FLTR-ANY, which have no basis in the RFC and are treated alike.
// No registry holds a set by these names. A hierarchical name with an AS-ANY
// component (AS208301:AS-ANY) is an ordinary set, and the zero SetName is not
// any.
func (n SetName) IsAny() bool
```

The body is a `switch n.canon` over the five canonical names. The method takes a value
receiver, like `IsZero`, so the API conventions hold: C2's `ok bool` rule does not apply to a
predicate, and the name is no RPSL class (C3). `api/types.txt` gains one line,
`func (SetName) IsAny() bool`, written by `RPSL_API_UPDATE=1 go run ./internal/apisurface -check`.
The diff must show only that line.

The text "refused alike" in `isAnySet`'s comment describes the engine, not the name, so it
moves to `AnySetError`'s doc (see Docs). The `types` comment says only what the names are.

### The seven sites

| Site | Becomes |
|---|---|
| `isAnySet(x)`, 8 calls in `resolve` | `x.IsAny()`; the function is deleted |
| `anySets[n.String()]` at lint.go:931 | `n.IsAny()`; the map and its comment are deleted |
| pathall.go:90, regex.go:61, match.go:163, flatten.go:324, routemodel.go:209 | `x.Name.IsAny()` (or `n.IsAny()`, `ref.Name.IsAny()`) |

A file whose only use of `strings` was the `EqualFold` loses the import. `routemodel` switches
too, so the guard has no exception for it. A name predicate does not weaken it as an oracle: it
still matches paths by brute force, with its own code. What it shares with the engine is the
fact that AS-ANY is a reserved name, which comes from the RFC, not from engine logic.

### Module boundaries

`types` is a leaf with no rpsl dependencies, and it stays one. `policy` (root module) and
`resolve` already import `types`. Their `go.mod` files require types v0.30.2, which has no
`IsAny`, so they build against it only through `go.work` until the next release.
`release.sh` already handles this: it tags `types` first and then bumps the requires
("rpsl: require the leaves at …"). CI builds with `go.work`.

### The guard

A new step in `scripts/check.sh`, beside the leaf-isolation and engine-purity steps:

```
step "any names: only types spells AS-ANY and its kin"
```

- It lists files with the existing `gofiles` helper and drops `_test.go`.
- It greps case-insensitively for the quoted literal `"(AS|RS|RTRS|PRNG|FLTR)-ANY"`.
- The only allowed matches are `types/setname.go` and `resolve/internal/irrdoracle/cases.go`.
- Any other match fails with its file and line.

Like the gofmt step, it records the listing's status separately, so a failed `git ls-files`
cannot pass the step by listing nothing. It matches only double-quoted literals, so comments
that mention `AS-ANY` in backticks or prose do not trip it. Test files are out of scope because
they use the names as data all the time.

### Docs

- `resolve/source.go:70`, `AnySetError`: "a reference to a set whose name denotes the whole IRR
  (`types.SetName.IsAny`: AS-ANY and RS-ANY, RFC 2622 §5.3, and RTRS-ANY, PRNG-ANY and FLTR-ANY,
  which are refused alike) …". The rest is unchanged.
- `docs/rpsl-go-design.md:594`: "`AS-ANY`/`RS-ANY` denote the whole IRR" gains
  "(`types.SetName.IsAny`, which also names RTRS-ANY, PRNG-ANY and FLTR-ANY)".
- CLAUDE.md, the any-set bullet: one clause, "the name test is `types.SetName.IsAny`, and
  check.sh refuses another copy".
- CHANGELOG `[Unreleased]`:
  - `### Added`: "`types`: `SetName.IsAny` reports whether a name is AS-ANY, RS-ANY, RTRS-ANY,
    PRNG-ANY or FLTR-ANY, the names that denote the whole IRR."
  - `### Changed`: "`policy` and `resolve` test for those names through it. No answer changes."

## Tests

Test-first, in `types` (`types/types_test.go`, beside `TestParseSetName`):

`TestSetNameIsAny`, a table of `ParseSetName` input → `IsAny()`:

| Input | Want | Why |
|---|---|---|
| `AS-ANY`, `RS-ANY`, `RTRS-ANY`, `PRNG-ANY`, `FLTR-ANY` | true | the five |
| `as-any`, `Rs-Any` | true | any spelling of one name is that name |
| `AS-ANYTHING`, `AS-AN`, `FLTR-ANY1` | false | not the name |
| `AS1:AS-ANY`, `AS-ANY:AS1`, `RS-ANY:RS-X` | false | hierarchical names are ordinary sets |

A further case checks that `SetName{}.IsAny()` is false.

Everything else is existing behaviour, and the existing suites are the test. They must pass
unchanged, with no test file edited outside `types`.

**Each site is covered.** The verification below proves it by mutation. With `IsAny` changed to
return false, each of the seven former sites must have at least one existing test that fails.
These are the tests expected to fail:

| Site | Test |
|---|---|
| `isAnySet` | the `AnySetError` tests in resolve, `TestAnySetLimits` |
| `anySets` | consist's missing-set lint tests with AS-ANY |
| `onesAll` | `TestASPAAnySetPath` (`NOT <AS-ANY>`) |
| `members` | rtconfig's `[AS-ANY AS1-AS5000]` class tests |
| `inASSet` | peval's AS-ANY peering tests |
| `isAnyPeering` | policy's Flatten tests with an AS-ANY peering |
| `single` | the filter and policy models through routemodel |

The verification records which test fails for which site. A site where nothing fails gets a
test in the same change: a table case in that package's existing test for AS-ANY.

## Verification before done

1. `TestSetNameIsAny` fails before the method exists (it does not compile), then passes.
2. The API golden diff is the one added line.
3. The mutation run: `IsAny` returns false, then `go test` on `./policy`, `./resolve`,
   `./resolve/peval`, `./resolve/rtconfig`, `./resolve/consist` and `./resolve/internal/...` (no
   `-race`, under memguard). Record which tests fail for each site, then revert the mutation.
4. The guard: add a temporary `"AS-ANY"` literal in a resolve file and see check.sh's new step
   fail on it, then remove it. On the clean tree, the step passes.
5. `scripts/check.sh` under memguard (`GOMAXPROCS=4`, `GOMEMLIMIT`, 8 GB cap): `check: ok`.
6. Real data: the change is meant to change no answer, and the mutation run plus the unchanged
   suites are the evidence for that. The real-data rule asks for the test covering the changed
   code. `TestRealDataConsist` on the seeded 2,000-aut-num sample, main against the branch, one
   run at a time under memguard, with identical count lines, as was done for each-cancel.

## Left to the builder

- The exact table cases beyond those listed, and where in `types_test.go` the test sits.
- The form of the guard's grep and its error text, within the rules above.
- Which existing test the mutation run names for each site, as found.

## Release

This is an API addition, so it ships in a minor release (v0.31.0), not a patch. Whether it
ships alone or waits for follow-up 3 (one-sided anchors in the ASPA full-table rule) is the
user's call.
