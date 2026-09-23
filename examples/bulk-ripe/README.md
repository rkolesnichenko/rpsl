# bulk-ripe

`bulk-ripe` is the integration-test harness for the `rpsl` library at GB scale.
It streams an RPSL bulk dump (e.g. one of RIPE's split files) through
`rpsl.Parse` / `ParseWith`, validates each decoded object against a chosen
profile, and prints a throughput + diagnostic-histogram report. With `--expand`
it also smoke-tests the `resolve.Expander` against a sample of the retained
sets. The test fixture under `bulk/testdata/` exercises the same code path on
a tiny synthetic dump so the harness can't rot silently.

It is not a piece of library API — it is a CLI you run against a real dump to
sanity-check the parser, the typed-decode path, and the resolver under load.

## Build & run

```sh
go run ./examples/bulk-ripe <file|->
```

The file may be plain text or gzipped — both are auto-detected. Use `-` to read
from stdin (useful for `zcat … | bulk-ripe -`).

### Canonical invocations

```sh
# Plaintext summary against a route file:
go run ./examples/bulk-ripe ripe.db.route.gz

# JSON report + resolve smoke test against an aut-num dump:
go run ./examples/bulk-ripe --json --expand ripe.db.aut-num.gz

# Stream a gzipped as-set dump from stdin:
zcat ripe.db.as-set.gz | go run ./examples/bulk-ripe -
```

## Flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--validate` | `ripe` | Validation profile: `ripe` (lenient), `rfc-strict`, or `off`. |
| `--json` | `false` | Emit the report as JSON instead of plaintext. |
| `--expand` | `false` | After streaming, smoke-test `resolve.Expander` against retained sets. |
| `--expand-set` | — | Explicit set name to expand (repeatable; overrides sampling). |
| `--expand-sample` | `10` | Number of largest-by-membership sets per class to sample when `--expand-set` isn't given. |
| `--expand-timeout` | `30s` | Per-set expansion timeout. |
| `--max-retain-aut-nums` | `200000` | Cap on `aut-num` objects retained for the resolve pass. |
| `--max-retain-as-sets` | `50000` | Cap on `as-set` objects retained. |
| `--max-retain-route-sets` | `50000` | Cap on `route-set` objects retained. |
| `--max-retain-routes` | `500000` | Cap on `route` + `route6` objects retained (combined). |

Retention caps only matter when `--expand` is on; otherwise the harness
streams without holding objects.

## Where to get a real dump

RIPE publishes split daily dumps at
`https://ftp.ripe.net/ripe/dbase/split/`, and APNIC at
`https://ftp.apnic.net/apnic/whois/`; ARIN, AFRINIC, LACNIC and RADB publish one
file each, and RADB also serves the ten IRRs it mirrors (NTTCOM, ALTDB, JPIRR,
TC, …). `scripts/fetch-irr-dumps.sh [registry ...]` (from the repository root)
downloads all of them into `.data/<registry>/`. RADB's dump
(`ftp://ftp.radb.net/radb/dbase/`) is the other common target — its 1.4 million
objects are a useful regression test for memory behavior.

## What good output looks like

A run over RIPE's `ripe.db.aut-num.gz` split dump (September 2026):

```
objects:      39899
bytes:        8893983 on disk, 81545181 parsed
elapsed:      1.950049334s
throughput:   39.9 MB/s parsed (4.3 MB/s on disk), 20461 obj/s

by class:
  aut-num        39899

diagnostics: 23 total
  error    23
top rules:
        10  error    policy/filter                            L498748:C37
        10  error    policy/trailing                          L498748:C41
         3  error    policy/expect-filter                     L1235144:C27
```

The 23 errors are genuinely malformed `import:`/`export:` values in the
registry — about 3 per 100,000 policy values.

A non-empty `lexer/malformed-line` entry on a canonical RIPE feed is a
**streaming/boundary regression** — the parser should not be producing those
on well-formed input. The plaintext output surfaces a hint to that effect; the
JSON output exposes the first-span via `--json | jq '.by_rule[] | select(.rule=="lexer/malformed-line")'`
so you can land directly on the offending byte range.

## Exit codes

- `0` — clean run.
- `1` — usage error or fatal input error before any report could be built.
- `2` — partial report (e.g. read error mid-stream). The harness prints what it
  has and warns on stderr.
- `130` — interrupted by SIGINT/SIGTERM; partial report follows.

## Real-data regression

`bulk/realdata_test.go` turns the harness into an opt-in regression test over
the same dumps:

```sh
scripts/fetch-irr-dumps.sh
RPSL_REALDATA=$PWD/.data go test -run TestRealData -v ./examples/bulk-ripe/bulk
```

The path must be absolute (`go test` runs in the package directory). For
every dump it requires:

- a lossless stream (SHA-256 of input = SHA-256 of the re-serialized objects)
  and no stream-level diagnostics;
- a valid prefix on every route and route6 (one that fails to decode is
  silently missing from every expansion);
- Errors of any one family (`object/`, `policy/`, `dict/`, …) on at most 0.1 %
  of the objects, and at least 3 tolerated for small dumps.

Only RIPE's dumps are validated against the RIPE profile, which describes
RIPE's templates rather than the other registries'. A registry's dump artefacts
(RIPE removes some `auth:` lines; ARIN's file ends with a line reading `EOF`)
are listed in the test with their reasons, as is a problem in a registry's own
data too frequent for the error limit (person names where a NIC handle belongs,
in RADB and its mirrors): its diagnostics are counted and logged rather than
failing the test. A registry whose data misuses RPSL more often than the limit
allows raises that one family's limit, with its reason (TC's policies).

For RIPE and APNIC, whose dumps come one class per file, it also expands the 20
largest as-sets and route-sets twice, in opposite input orders, and requires
identical results. The filter-set and peering-set dumps exercise the policy
parser's filter and peering grammar.
