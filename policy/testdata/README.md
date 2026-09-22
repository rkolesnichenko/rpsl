# policy testdata

This directory holds inputs for the `policy` package's tests.

## `rfc-examples.txt`

Every routing-policy example in RFC 2622, RFC 2650 and RFC 4012, one per line
with its RFC and line number. `TestRFCExamples` parses each and expects no
diagnostic, or exactly the rules after `## expect:`.

## `fuzz/FuzzParseImport/`

Seed corpus for `FuzzParseImport` in `policy/fuzz_test.go`. Each file is a
single byte sequence the fuzzer mutates and feeds into `policy.ParseImport`.

The seeds split into two groups:

- **Named seeds** (`seed_*`) — hand-curated inputs that exercise a specific
  RFC 2622 / 4012 feature: `seed_rpslng_afi` for `afi`-scoped factors,
  `seed_rpslng_except` for the `except`/`refine` block structure, etc. Add
  more here when adding test coverage for a new policy shape.
- **Hex-named seeds** (e.g. `27276039ba332be5`) — inputs preserved from
  past fuzz runs, typically because they triggered a panic or a parse
  asymmetry before the fix landed. Removing these is fine *only* once the
  property they once falsified has its own named seed.

The contract `FuzzParseImport` enforces is the resilience invariant
(§1.2 of the design doc): the parser must never panic on any input. Every
seed in here has already been processed without a panic; the fuzzer is the
guard against future regressions.

## Adding seeds

```sh
mkdir -p policy/testdata/fuzz/FuzzParseImport
printf 'from AS65001 accept ANY' > policy/testdata/fuzz/FuzzParseImport/seed_my_case
go test -run FuzzParseImport ./policy   # confirms the seed parses cleanly
```

For directed fuzzing of a hypothesis, prefer running with a small
`-fuzztime` and a focused seed set rather than mutating a giant corpus.
