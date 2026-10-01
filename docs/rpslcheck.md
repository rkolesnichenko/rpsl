# rpslcheck: policy consistency and lint

`rpslcheck` is a neighbour check: it compares what one network's `export:`
toward a neighbour permits announcing with what the neighbour's `import:`
from it accepts — both directions, one address family at a time — on the
rpsl engine's `resolve/consist`. It also lints one network's own import,
export and default policies for what is dead or wrong in them, whether or
not anyone peers with it yet.

The comparison is exact or undecided. Prefix parts are decided exactly,
through `types.PrefixSpace`; AS-path and community tests are compared by
identity only, so a finding over one is stated conditionally (`given: ...`)
rather than guessed, and whatever is neither decided nor conditional is
`Undecided`. An AS-path regexp is never evaluated against a route: matching
one against live BGP paths is a separate consumer's job, not a registry
tool's (the library's long-standing scope guardrail — see CLAUDE.md).

## Install

With a Go toolchain:

```sh
go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslcheck@latest
```

Static release binaries, as `rpslq` and `rpslconf` have, ship alongside
theirs: each [release](https://github.com/rkolesnichenko/rpsl/releases/latest)
carries `rpslcheck` for Linux and macOS (amd64, arm64) and Windows (amd64),
with `SHA256SUMS`. `rpslcheck -v` prints the binary's version.

## Usage

`rpslcheck` has three modes.

**One AS**, against a live server: lint it, then check it against every peer
its own policies name (Forward) and, over a dump, every aut-num naming it
back (Reverse), in both families.

```sh
rpslcheck -h whois.radb.net AS65001
```

**A pair**: lint both, then check that one pair, in both families.

```sh
rpslcheck AS65001 AS65002
```

**A sweep**, over one or more dumps: lint and check every aut-num the dumps
hold, and print totals.

```sh
rpslcheck -dump ripe.db.aut-num.gz -dump ripe.db.route.gz -sweep
```

### Flags

Generated from `rpslcheck -help`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-h` | `whois.radb.net` | IRR server host, or `host:port` |
| `-p` | `43` | IRR server port, when `-h` names none |
| `-s` | (the server's) | registries to query, comma-separated, in precedence order |
| `-whois` | off | query with the whois protocol instead of IRRd's |
| `-dump` | — | read objects from a dump file instead of a server (repeatable; gzip is read too) |
| `-af` | `both` | address families to check: `ipv4`, `ipv6` or `both` |
| `-json` | off | write one JSON object per line |
| `-sweep` | off | audit every aut-num in the dumps (needs `-dump`) |
| `-sample` | `0` | sweep: a random sample of `N` aut-nums instead of all |
| `-seed` | `1` | sweep: the sample's random seed |
| `-c` | `GOMAXPROCS` | `N` checks at once; the output is the same for any `N` |
| `-timeout` | `10m0s` | give up on the whole run after this long (0: never); a `-sweep` has no deadline unless this is given |
| `-check-timeout` | `1m0s` | sweep: give each aut-num's lint and each pair's check this long, counting the ones that run out (0: no limit) |
| `-v` | — | print rpslcheck's version and exit |

## Reading the output

### Findings

A pair's check produces one `Direction` each way, each a list of `Finding`s
(no findings: the two agree). Each kind:

| Kind | Severity | Means | What to do |
| --- | --- | --- | --- |
| `not-imported` | Warning | The exporter's policy permits announcing routes the importer's policy refuses. | The export is broader than the neighbour accepts — usually the exporter leaking more than it means to (`announce ANY` toward a provider), occasionally the importer's accept list falling behind. |
| `not-exported` | Info | The importer's policy accepts routes the exporter's policy does not permit announcing. | Usually harmless — the importer accepts more than this neighbour will ever send — but worth a look if the importer meant to be strict. |
| `no-import` | Warning | The exporter has policy toward the neighbour; the neighbour has no decided import term covering it. | The session is one-sided in the registry: add the missing `import:`, or confirm the export is stale. |
| `no-export` | Info | The importer has policy from the neighbour; the neighbour has no decided export term covering it. | As `no-import`, the other way round; lower severity because an importer's `accept` with nothing arriving is the common, harmless case. |
| `no-aut-num` | Warning | One side's aut-num is not in the source. | The registry is missing an object `Finding.AS` names; nothing else about the pair was compared. |
| `undecided` | Info | Part of the comparison could not be decided. | See below. |

"Announces" always means "permits announcing" — the comparison is of policy
text, not of a RIB. A customer's `export: to AS2 announce ANY` toward a
provider whose `import: from AS1 accept AS-CUST` is a `not-imported`
Warning: the text claims a leak the provider's policy would in fact refuse,
whatever routes the customer happens to be sending today.

`given:` appears under a finding when it is conditional: the listed AS-path
and community tests are ones only one side's policy carries, so the finding
holds only for a route that also passes them. It never claims that such a
route exists — regexps are never evaluated — only that if one does, with a
prefix in the finding's ranges, it is refused (or accepted, for
`not-exported`).

### Undecided

An `Undecided` finding's `Of` says what it may be (`NotImported`,
`NotExported`, `NoImport` or `NoExport`), and `Why` is one of three reasons
(`consist.Whys()`, verbatim):

- `symbolic test on one side only` — an AS-path or community test the other
  side does not hold.
- `importer has undecided terms` — the importing side's policy has a term
  `peval` cannot decide for this session (a router the pair does not give, a
  peering regexp, another protocol).
- `exporter has undecided terms` — the same, on the exporting side.

A side with any undecided term demotes every `not-imported`/`not-exported`
finding that side would otherwise produce to `Undecided`, rather than
reporting a comparison that an undecided term could still overturn.

### Lint

`rpslcheck AS65001` (and the pair and sweep modes) also print `AS65001`'s
lint: what is wrong or dead in its own import, export and default policies,
evaluated toward every peer it names and, over a dump, every aut-num naming
it back. Same severities as [`docs/diagnostics.md`](diagnostics.md):

| Rule | Severity | Fires when |
| --- | --- | --- |
| `lint/shadowed` | Warning | Every route a term accepts is accepted by an earlier decided term (same AS-path/community signature), so the later term's actions never apply. Partial shadowing is not reported. |
| `lint/empty` | Info | A term's filter, or a `default:`'s `networks` filter, accepts no route. |
| `lint/missing-set` | Warning | A filter, a peering or a router expression names a set the source does not have. |
| `lint/missing-router` | Warning | A peering names an inet-rtr the source does not have. |
| `lint/no-aut-num` | Warning | A peering names an AS whose aut-num the source does not have. |
| `lint/undecided` | Info | A term `peval` cannot decide for a session, or a session whose filter cannot be evaluated at all (it names a set reaching `AS-ANY`, or has no normal form); the other sessions are still linted. |
| `lint/limit` | Warning | A session's evaluation hit a limit; the other sessions are still linted. |

### A real example

Running the test fixture `resolve/testdata/rpslcheck/objects.rpsl` (four
small aut-nums with a shadowed import term, a one-sided export, and a peer
whose aut-num is missing):

```sh
$ rpslcheck -dump resolve/testdata/rpslcheck/objects.rpsl AS65001
AS65001 lint
  warning lint/shadowed import (line 5): import term AS65002 | AS65002 never decides: earlier terms accept every route it accepts [AS65002; ipv4.unicast]
AS65001 -> AS65002 ipv4.unicast
  warning not-imported: AS65001's export (line 3) permits announcing routes AS65002's import refuses: 0.0.0.0/0^0-15, 0.0.0.0/0^17-32, 0.0.0.0/5^16, … (18 ranges; e.g. 0.0.0.0/0)
AS65002 -> AS65001 ipv4.unicast: consistent
AS65001 -> AS65002 ipv6.unicast: consistent
AS65002 -> AS65001 ipv6.unicast
  info no-export: AS65001 imports from AS65002, and AS65002's export has nothing toward AS65001
AS65001 -> AS65003 ipv4.unicast: consistent
AS65003 -> AS65001 ipv4.unicast: consistent
AS65001 -> AS65003 ipv6.unicast: consistent
AS65003 -> AS65001 ipv6.unicast: consistent
AS65001 -> AS65005 ipv4.unicast: consistent
AS65005 -> AS65001 ipv4.unicast
  warning no-import: AS65005 exports to AS65001, and AS65001's import has nothing from AS65005
AS65001 -> AS65005 ipv6.unicast: consistent
AS65005 -> AS65001 ipv6.unicast: consistent
$ echo $?
1
```

(AS65001's `import: from AS65002 accept AS65002` is shadowed by the earlier
`import: from AS65002 accept ANY` — hence the lint warning — and its
`export: to AS65002 announce ANY` is what the `not-imported` finding is
about, since AS65002 only imports `AS-CUST1` from it.)

## The reverse index

Over `-dump`, `rpslcheck` builds `resolve.Corpus.IndexPeers`, which answers
"who names me" for any AS without scanning every aut-num. One AS's own mode
uses it for the Reverse half of its peer list: aut-nums that peer toward
AS65001 without AS65001 peering back are still checked.

A live server offers no such query, so against `-h`/`-whois` `rpslcheck`
reports only the Forward half (the peers the named AS's own policy names)
and says so on stderr:

```
rpslcheck: note: the source keeps no reverse index (only -dump does), so networks that name AS65001 without being named back are not checked
```

## Sweeps

`-sweep` only runs over `-dump`: walking a whole registry over a live server
would be hundreds of thousands of queries against someone else's service,
and no registry offers that as a query in the first place. It lints every
aut-num the dumps hold, checks every unordered pair an aut-num's forward
peerings reach (each pair once, whichever side names it first), in each
family `-af` asks for, and prints totals. Output is deterministic: the same
for `-c 1` and `-c 8`.

**Text output** writes one self-contained line per Warning — a lint issue or
a finding at Warning severity — then the totals; with a full registry this
is the only readable form. Info-severity findings (`not-exported`,
`no-export`, `lint/empty`, `lint/undecided`) are not printed as lines, but
are still counted in the totals. `-json` writes everything: every issue,
every direction (including consistent ones, as a record with `findings: 0`),
every finding, every pair that timed out or hit a limit, and the totals,
one JSON object per line.

### Totals

The text totals block (see the real sweep example in the next section) and
the JSON `totals` record both carry:

- `aut-nums` swept;
- `pairs checked (per family)` and `directions` (two per pair);
- `directions consistent`;
- one row per finding kind seen in at least one direction (`not-imported`,
  `not-exported`, `no-import`, `no-export`, `no-aut-num`, and `undecided`
  broken out by `Why`);
- one row per lint rule;
- `pairs over a limit or not decidable` — a pair whose check hit an
  `Expander` limit, or whose filter could not be evaluated for the session
  at all (`*resolve.AnySetError`, `*resolve.NotEnumerableError`);
- `checks over their time budget` — a lint or a check that ran past
  `-check-timeout` (never guessed at, never counted as consistent: see
  "On real data" below);
- the ten aut-nums with the most Warnings.

### JSON record types

Each line's `type` field picks its shape (fields from
`resolve/internal/rpslcheck/output.go` and `sweep.go`):

| Type | Fields |
| --- | --- |
| `issue` | `as`, `rule`, `severity`, `message`, `attr`, `index`, `line`, `peers`, `afs` |
| `direction` | `from`, `to`, `af`, `findings` (count) |
| `finding` | `from`, `to`, `af`, `kind`, `of`, `severity`, `as`, `example`, `ranges`, `truncated`, `given`, `export_lines`, `import_lines`, `why` |
| `limit` | `a`, `b`, `af`, `error` — a sweep pair over a limit or not decidable |
| `timeout` | a lint: `as`, `error`; a check: `a`, `b`, `af`, `error` — over `-check-timeout` |
| `totals` | `autnums`, `pairs`, `directions`, `consistent`, `kinds`, `rules`, `limits`, `timeouts`, `top` (`[{as, warnings}]`) |

A field omitted from a record (Go's `omitempty`) does not apply to that
finding or issue — a `no-aut-num` finding has no `ranges`, a consistent
`direction` has `findings: 0` and nothing else.

## Exit status

- **0** — no Warning.
- **1** — at least one Warning (a finding or a lint issue).
- **2** — a command line `rpslcheck` cannot use.
- **3** — the check could not complete: an unreachable server, the named
  AS's aut-num not found, or, outside a sweep, an `Expander` limit or a
  filter that cannot be evaluated for the session. An explicit `-timeout`
  that the whole run exceeds also exits 3. Inside a sweep, a pair hitting a
  limit or a per-call `-check-timeout` is counted (see "Sweeps" above), not
  fatal; the sweep still exits 1 if anything it did complete found a
  Warning.

## On real data

`resolve/consist`'s own real-data test, `TestRealDataConsist`
(`resolve/consist/consist_realdata_test.go`), swept RIPE's split dumps
(fetched 2026-09-27) whole, run on 2026-10-01, each aut-num's Lint/Peers and
each pair's Check under its own 60-second budget. One measured run, verbatim
(the totals depend on that budget and on the machine, so treat them as one
run's, not a guarantee):

| Measure | Value |
| --- | --- |
| Load, `KeepPolicy` | 7s, 545 MB |
| Load, with `IndexPeers` | 7s, 549 MB |
| Aut-nums swept | 39918 |
| Wall time | 1h1m29s |
| pairs | 561916 |
| directions | 1123832 |
| directions consistent | 452723 |
| directions with no-aut-num | 209044 |
| directions with no-export | 188811 |
| directions with no-import | 196512 |
| directions with not-exported | 30156 |
| directions with not-exported (given) | 813 |
| directions with not-imported | 9125 |
| directions with not-imported (given) | 60 |
| directions with undecided: exporter has undecided terms | 18911 |
| directions with undecided: exporter has undecided terms (given) | 3 |
| directions with undecided: importer has undecided terms | 19612 |
| directions with undecided: symbolic test on one side only | 964 |
| directions with undecided: symbolic test on one side only (given) | 16 |
| lint: lint/empty | 51255 |
| lint: lint/missing-router | 2526 |
| lint: lint/missing-set | 7827325 |
| lint: lint/no-aut-num | 52261 |
| lint: lint/shadowed | 23710 |
| lint: lint/undecided | 93356 |
| not decidable | 2 |
| timeout | 227 |

No `verify timeout` was counted, and all 9125 unconditional `not-imported`
directions were independently re-checked against the two sides' clause
spaces with no contradiction (the test's own soundness check on this run).
`lint/missing-set` in particular moves noticeably between runs — a lint that
times out reports nothing for that aut-num — so read any one count as that
run's, not as a fixed property of the data.

This test is opt-in and not part of `scripts/check.sh`:

```sh
RPSL_REALDATA=$PWD/.data go test -run TestRealDataConsist ./resolve/consist
RPSL_CONSIST_SAMPLE=5000 RPSL_REALDATA=$PWD/.data go test -run TestRealDataConsist ./resolve/consist  # a sample
```

## What it does not do

- **Actions.** `rpslcheck` compares which routes pass, not what is done to
  them: a community one side sets and the other expects, or a preference, is
  not checked.
- **Route servers.** `import-via:`/`export-via:` make consistency a
  three-party question (the route server's policy too); `rpslcheck` lints
  their sets and routers but does not check them against a peer.
- **`default:` consistency.** Lint covers a `default:`'s sets, routers and
  empty filters; it is not compared between neighbours.
- **Multicast.** `consist.Pair.AF` must be `ipv4.unicast` or
  `ipv6.unicast`.
- **Business relationships and over-broad exports.** RPSL states no
  customer/peer/provider relationship, so `rpslcheck` cannot flag an export
  that is wider than a business relationship would allow — only wider than
  the neighbour's own stated import.
- **Reverse-indexing as-set peerings.** The peer index used for a dump's
  Reverse list and for a sweep's pairs only indexes a peering written as a
  bare AS number; a peering written only as an as-set is found via Forward
  expansion from the other side, not via the index.
- **Evaluating regexps or community tests.** Both are compared by identity
  only (`given:`), never matched against a route — the library never
  evaluates an AS-path regexp or a community test against live data.
