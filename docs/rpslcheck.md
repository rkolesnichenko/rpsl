# rpslcheck: policy consistency and lint

`rpslcheck` is a neighbour check: it compares what one network's `export:`
toward a neighbour permits announcing with what the neighbour's `import:`
from it accepts — both directions, one address family at a time — on the
rpsl engine's `resolve/consist`. It also lints one network's own import,
export and default policies for what is dead or wrong in them, whether or
not anyone peers with it yet.

The comparison is exact or undecided. Prefix parts are decided exactly,
through `types.PrefixSpace`; AS-path and community tests are compared by
identity only, and never across the session (the importer reads a route
after the exporter prepends its AS and applies its export actions), so a
finding over one is stated conditionally (`given: ...`) rather than
guessed, and whatever is neither decided nor conditional is `Undecided`. An AS-path regexp is never evaluated against a route: matching
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
its own policies name directly (Forward) and, over a dump, every aut-num
naming it back (Reverse), in both families — and, with `-set-peers`, every
peer its policies name only through an as-set or a peering-set (see "Peers
through sets" below).

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
| `-c` | `GOMAXPROCS` | `N` checks at once; the output is the same for any `N` while no call runs past `-check-timeout` |
| `-timeout` | `10m0s` | give up on the whole run after this long (0: never); a `-sweep` has no deadline unless this is given |
| `-check-timeout` | `1m0s` | sweep: give each aut-num's peer list, its lint, and each pair's check this long, each its own budget, counting the ones that run out (0: no limit) |
| `-set-peers` | off | also check (and lint toward) the peers named only through as-sets and peering-sets; there can be tens of thousands |
| `-rpki` | — | a validator's JSON export (rpki-client `-j`, Routinator `json`): lint each aut-num against its ASPAs too (the `lint/aspa-*` rules); an export without ASPAs is an error |
| `-v` | — | print rpslcheck's version and exit |

## Reading the output

### Findings

A pair's check produces one `Direction` each way, each a list of `Finding`s.
No findings: the two agree (`consistent`) — or neither side has any term,
decided or undecided, toward the other in that family, which is printed
`no policy either way` (`Direction.NoPolicy`, JSON `"no_policy": true`),
since two networks the registry does not show peering have nothing to agree
on. Each kind:

| Kind | Severity | Means | What to do |
| --- | --- | --- | --- |
| `not-imported` | Warning | The exporter's policy permits announcing routes the importer's policy refuses. | The export is broader than the neighbour accepts — usually the exporter leaking more than it means to (`announce ANY` toward a provider), occasionally the importer's accept list falling behind. |
| `not-exported` | Info | The importer's policy accepts routes the exporter's policy does not permit announcing. | Usually harmless — the importer accepts more than this neighbour will ever send — but worth a look if the importer meant to be strict. |
| `no-import` | Warning | The exporter has policy toward the neighbour, permitting some route of the family; the neighbour has no decided import term covering it. (An export that permits nothing in the family makes no finding.) | The session is one-sided in the registry: add the missing `import:`, or confirm the export is stale. |
| `no-export` | Info | The importer has policy from the neighbour; the neighbour has no decided export term covering it. | As `no-import`, the other way round; lower severity because an importer's `accept` with nothing arriving is the common, harmless case. |
| `no-aut-num` | Warning | One side's aut-num is not in the source. | The registry is missing an object `Finding.AS` names; nothing else about the pair was compared. |
| `undecided` | Info | Part of the comparison could not be decided. | See below. |

"Announces" always means "permits announcing" — the comparison is of policy
text, not of a RIB. A customer's `export: to AS2 announce ANY` toward a
provider whose `import: from AS1 accept AS-CUST` is a `not-imported`
Warning: the text claims a leak the provider's policy would in fact refuse,
whatever routes the customer happens to be sending today.

`given:` appears under a finding when it is conditional: the listed AS-path
and community tests are ones the side the finding is about carries and the
other side's policy does not settle, so the finding holds only for a route
that also passes them. It never claims that such a route exists — regexps
are never evaluated — only that if one does, with a prefix in the finding's
ranges, it is refused (or accepted, for `not-exported`). The tests are read
where that side reads the route: for `not-imported`, the exporter's tests
on the route before its prepend and actions; for `not-exported`, the
importer's tests on the route as it receives it.

The same test on both sides is not the same test. The importer sees the
path with the exporter's AS prepended, and the communities after the
exporter's actions — `export: to AS2 announce <^AS3>` against `import: from
AS1 accept <^AS3>` can never agree, since AS2 receives every such path
starting with AS1. So an import test on the AS path never settles what the
exporter permits, and an import community test settles it only when the
exporter's clause changes no community; anything else is `Undecided`.

### Undecided

An `Undecided` finding's `Of` says what it may be (`NotImported`,
`NotExported`, `NoImport` or `NoExport`), and `Why` is one of three reasons
(`consist.Whys()`, verbatim):

- `symbolic test on one side only` — an AS-path or community test the other
  side does not hold — or holds too, but cannot be compared across the
  session boundary: the same AS-path regexp on both sides never settles it
  (the importer reads the path after the exporter's prepend), and the same
  community test settles it only when the exporter's clause changes no
  community.
- `importer has undecided terms` — the importing side's policy has a term
  `peval` cannot decide for this session (a router the pair does not give, a
  peering regexp, another protocol).
- `exporter has undecided terms` — the same, on the exporting side.

A side with any undecided term demotes every `not-imported`/`not-exported`
finding that side would otherwise produce to `Undecided`, rather than
reporting a comparison that an undecided term could still overturn. The
converse holds too: when both sides have decided terms, an exporter's
undecided term may announce any route of the family, so the direction gets
`undecided` (may be `not-imported`, `exporter has undecided terms`) over
every prefix the importer does not accept unconditionally — every prefix
outside its terms with no AS-path or community test — with the undecided
terms' lines; and an importer's undecided term, the mirror (may be
`not-exported`, `importer has undecided terms`). A direction with an
undecided term is `consistent` only when the other side's test-free terms
already accept (or announce) everything the undecided term could.

### Lint

`rpslcheck AS65001` (and the pair and sweep modes) also print `AS65001`'s
lint: what is wrong or dead in its own import, export and default policies,
evaluated toward every peer it names directly and, over a dump, every
aut-num naming it back (and with `-set-peers`, every peer it names through a
set; without it, each peering through a set that reaches none of those peers
is linted toward one of its members, the lowest AS it names). Same
severities as [`docs/diagnostics.md`](diagnostics.md):

| Rule | Severity | Fires when |
| --- | --- | --- |
| `lint/shadowed` | Warning | Every route a term accepts is accepted by an earlier decided term (same AS-path/community signature), so the later term's actions never apply. Partial shadowing is not reported. |
| `lint/empty` | Info | A term's filter, or a `default:`'s `networks` filter, accepts no route. |
| `lint/missing-set` | Warning | A filter, a peering or a router expression names a set the source does not have. |
| `lint/missing-router` | Warning | A peering names an inet-rtr the source does not have. |
| `lint/no-aut-num` | Warning | A peering names an AS whose aut-num the source does not have (an AS named only through a set: with `-set-peers`, or as its peering's representative). |
| `lint/undecided` | Info | A term `peval` cannot decide for a session, or a session whose filter cannot be evaluated at all (it names a set reaching `AS-ANY`, or has no normal form); the other sessions are still linted. |
| `lint/limit` | Warning | A session's evaluation hit a limit; the other sessions are still linted. |
| `lint/aspa-missing-provider` | Warning | With `-rpki`: the aut-num takes a full table from a peer, and its ASPA does not list that peer, or is AS0. A full table is a conjunct accepting the family's whole space less negated prefixes, with no positive AS-path or community test, that accepts at least one prefix; the clause counts only if its own peering names the peer, and a peering reaching `AS-ANY` on its positive side (`OR`, `AND`, left of `EXCEPT`) — written, through an as-set, or in a peering-set — names no peer; a set template names the peer only if its instantiation for that peer lists it. |
| `lint/aspa-stale-provider` | Info | With `-rpki`: the aut-num's ASPA lists a provider none of its peerings names (silent when a peering could name any AS, or reaches a set the source does not have). |
| `lint/aspa-customer-set` | Warning | With `-rpki`: the aut-num announces an as-set whose direct member AS has an ASPA not naming it, or an AS0 one. |

`Lint` always evaluates both families; `-af` chooses which issues are
written (and count toward the exit status and a sweep's totals): those of a
chosen family, and those of none — the static ones, such as a missing set
the policy names. A policy toward `AS-ANY` is linted through a session
toward the reserved AS4294967295; a term there that depends on the peer —
`PeerAS` or a set template in its filter, directly, in a regexp, or inside a
filter-set at any depth, or a normal form that changes when the session is
evaluated again toward AS65535 — is left out of that session's
`lint/empty` and `lint/shadowed`. Line numbers count from the aut-num's own
first line, whatever the source: a dump's `member-of:` claimant aut-num
too.

**Known limit.** `Lint` evaluates each attribute once per session, so its
time grows with the aut-num's size times its number of peers: measured, an
aut-num with N peers, one import and one export each, took 29 ms at
N=250, 108 ms at N=500 and 396 ms at N=1000. A sweep's `-check-timeout`
bounds it; memoizing per-attribute evaluation within one lint is a
follow-up.

### A real example

Running the test fixture `resolve/testdata/rpslcheck/objects.rpsl` (four
small aut-nums with a shadowed import term, a one-sided import, an export
of an AS with no routes, and a peer whose aut-num is missing):

```sh
$ rpslcheck -dump resolve/testdata/rpslcheck/objects.rpsl AS65001
AS65001 lint
  warning lint/shadowed import (line 5): import term AS65002 | AS65002 never decides: earlier terms accept every route it accepts [AS65002; ipv4.unicast]
AS65001 -> AS65002 ipv4.unicast
  warning not-imported: AS65001's export (line 3) permits announcing routes AS65002's import refuses: 0.0.0.0/0^0-15, 0.0.0.0/0^17-32, 0.0.0.0/5^16, … (18 ranges; e.g. 0.0.0.0/0)
AS65002 -> AS65001 ipv4.unicast: consistent
AS65001 -> AS65002 ipv6.unicast: no policy either way
AS65002 -> AS65001 ipv6.unicast
  info no-export: AS65001 imports from AS65002, and AS65002's export has nothing toward AS65001
AS65001 -> AS65003 ipv4.unicast: consistent
AS65003 -> AS65001 ipv4.unicast: no policy either way
AS65001 -> AS65003 ipv6.unicast: no policy either way
AS65003 -> AS65001 ipv6.unicast: no policy either way
AS65001 -> AS65005 ipv4.unicast: no policy either way
AS65005 -> AS65001 ipv4.unicast: consistent
AS65001 -> AS65005 ipv6.unicast: no policy either way
AS65005 -> AS65001 ipv6.unicast: no policy either way
$ echo $?
1
```

(AS65001's `import: from AS65002 accept AS65002` is shadowed by the earlier
`import: from AS65002 accept ANY` — hence the lint warning — and its
`export: to AS65002 announce ANY` is what the `not-imported` finding is
about, since AS65002 only imports `AS-CUST1` from it. AS65005's `export: to
AS65001 announce AS65005` names an AS with no routes, so it permits nothing
and makes no `no-import` finding; the directions where neither side has a
term read `no policy either way`.)

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

## Peers through sets

A peering can name its peers through an as-set or a peering-set:
`import: from AS-DECIX accept ANY` names every member of the exchange's set.
Such sets are large — on RIPE's data, 160 aut-nums name more than 5,000
peers each this way, the largest about 59,000, and checking every one would
make a registry sweep 7.3 million pairs, days of work. So `rpslcheck` checks
by default only the peers a policy names directly, as an AS number, and the
aut-nums naming it back; the peers named only through sets
(`consist.PeerList.ViaSets`) are checked with `-set-peers`. Without it, one
AS's mode says on stderr how many it left out:

```
rpslcheck: note: 2 peers named through sets are not checked; -set-peers checks them
```

and a sweep counts them in its totals. Its lint still covers a peering
through a set: each one that reaches none of the peers already linted is
evaluated toward its lowest AS, so a term such a peering makes dead is still
reported (with that AS as its peer).

## ASPA (-rpki)

`-rpki FILE` reads a relying party's JSON export and lints each aut-num
against the ASPAs (RPKI Autonomous System Provider Authorization objects) in
it. rpki-client writes ASPAs to its JSON unless run with `-A`; Routinator
only with `enable-aspa`. An export with no `aspas` member is an error (exit
3), not a run with no ASPA findings.

The three `lint/aspa-*` rules compare registry data (an aut-num's
import/export policy and as-sets) with the ASPAs. They never look at AS
paths. A finding is a snapshot of one export: a later export, or a changed
registry, can give another.

Measured: `RPSL_CONSIST_ASPA=1` (`TestRealDataConsist`, `resolve/consist`) lints with
NTT's export (`metadata.buildtime` 2026-09-27T15:06:50Z, 3,269 customers with an
ASPA, the export's own `uniquevaps`) against the RIPE dumps downloaded on
2026-09-27, run on 2026-10-06. A sweep of all 39,918 aut-nums (6,469 s, peak RSS
4,372 MB) reports:

| Rule | Issues |
| --- | ---: |
| `lint/aspa-customer-set` | 95,353 |
| `lint/aspa-missing-provider` | 4,036 |
| `lint/aspa-stale-provider` | 1,834 |

A seeded sample of 2,000 aut-nums (RPSL_CONSIST_SAMPLE=2000, 379 s, peak RSS
2,673 MB) gave 2,049, 138 and 60. These are issues, not aut-nums. For
`lint/aspa-customer-set` an issue is one export attribute, one announced as-set
and one member, merged across families: an aut-num that announces one as-set to
many peers on separate `export:` lines repeats each member once per line, so
95,353 is not 95,353 ASes. For `lint/aspa-missing-provider` it is one import
attribute and one peer, and for `lint/aspa-stale-provider` one provider. One
aut-num can have many: AS1764 announces AS-NEXTLAYER, whose members AS208089 and
AS58299 have ASPAs that do not list it. Five examples of each rule were checked by hand against the dump
and the export (the aut-num's `import:`/`export:` lines, its as-set, the ASPA's
providers) and all agreed.

## Sweeps

`-sweep` only runs over `-dump`: walking a whole registry over a live server
would be hundreds of thousands of queries against someone else's service,
and no registry offers that as a query in the first place. It lints every
aut-num the dumps hold, checks every unordered pair an aut-num's peerings
name directly — and, with `-set-peers`, those they reach through sets — (each
pair once, whichever side names it first), in each
family `-af` asks for, and prints totals. Each aut-num's peer list, then its
lint, and each pair's check runs under its own `-check-timeout` budget; the
peer list comes first, so a lint that runs out never drops a pair. Output
is deterministic — the same for `-c 1` and `-c 8` — as long as no call runs
past `-check-timeout`; one that does is counted, and whether a call near
the budget finishes in time depends on the machine and its load.

Every pair the sweep forms comes from some aut-num's own Forward peer list —
the AS numbers its policy names directly as a bare ASN — never from
`Reverse` (that index exists for one AS's own mode; a sweep walks every
aut-num in the dump, so a pair either side's Forward names is formed once
regardless of which side is walked first). A pair where neither side names
the other directly, only through a set, is never checked — it falls under
"peers through sets, not checked" below. `-sample` draws *aut-nums*, not
pairs: it picks `N` of them at random and then pairs each one with its own
Forward peers, so a pair is in the swept sample only when one of its two
aut-nums was drawn.

**Text output** writes one self-contained line per Warning — a lint issue or
a finding at Warning severity — then the totals; with a full registry this
is the only readable form. Info-severity findings (`not-exported`,
`no-export`, `lint/empty`, `lint/undecided`) are not printed as lines, but
are still counted in the totals. `-json` writes everything: every issue,
every direction (including consistent ones, as a record with `findings: 0`,
and those with no policy either way, with `"no_policy": true` too),
every finding, every pair that timed out or hit a limit, and the totals,
one JSON object per line.

### Totals

The text totals block (see the real sweep example in the next section) and
the JSON `totals` record both carry:

- `aut-nums` swept;
- `pairs checked (per family)` and `directions` (two per pair);
- `peers through sets, not checked` — an aut-num's peers named only through
  an as-set or a peering-set whose pair no aut-num's direct peers bring into
  the sweep, one per aut-num and peer (0 with `-set-peers`);
- `directions consistent`;
- `directions with no policy either way` — neither side has a term toward
  the other in that family; counted here, never as consistent;
- one row per finding kind seen in at least one direction (`not-imported`,
  `not-exported`, `no-import`, `no-export`, `no-aut-num`, and `undecided`
  broken out by `Why`);
- one row per lint rule;
- `pairs over a limit or not decidable` — a pair whose check hit an
  `Expander` limit, or whose filter could not be evaluated for the session
  at all (`*resolve.AnySetError`, `*resolve.NotEnumerableError`);
- `checks over their time budget` — a peer list, a lint or a check that ran past
  `-check-timeout` (never guessed at, never counted as consistent: see
  "On real data" below);
- the ten aut-nums with the most Warnings.

### JSON record types

Each line's `type` field picks its shape (fields from
`resolve/internal/rpslcheck/output.go` and `sweep.go`):

| Type | Fields |
| --- | --- |
| `issue` | `as`, `rule`, `severity`, `message`, `attr`, `index`, `line`, `peers`, `afs` |
| `direction` | `from`, `to`, `af`, `findings` (count), `no_policy` (true when neither side has a term) |
| `finding` | `from`, `to`, `af`, `kind`, `of`, `severity`, `as`, `example`, `ranges`, `truncated`, `given`, `export_lines`, `import_lines`, `why` |
| `limit` | `a`, `b`, `af`, `error` — a sweep pair over a limit or not decidable |
| `timeout` | a peer list or a lint: `as`, `error` (beginning `peers: ` or `lint: `); a check: `a`, `b`, `af`, `error` — over `-check-timeout` |
| `totals` | `autnums`, `pairs`, `via_sets_skipped`, `directions`, `consistent`, `no_policy`, `kinds`, `rules`, `limits`, `timeouts`, `top` (`[{as, warnings}]`) |

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
whole, each aut-num's Lint/Peers and each pair's Check under its own
60-second budget. The dumps were fetched 2026-09-27 (`ls -l .data` shows
`ripe/` — and `rpki/`, fetched alongside it — dated 2026-09-27; every other
registry's directory is dated 2026-09-23, from an earlier fetch); the run
below is from 2026-10-02, at commit `05b018e`. One measured run, verbatim
(the totals depend on that budget and on the machine, so treat them as one
run's, not a guarantee):

```
load: KeepPolicy 7s, 545 MB; with IndexPeers 7s, 549 MB
39918 aut-nums swept in 1h5m52s:
      directions                                                   954052
      directions consistent                                        101063
      directions with no policy either way                         304690
      directions with no-aut-num                                   188584
      directions with no-export                                    145108
      directions with no-import                                    140524
      directions with not-exported                                 27690
      directions with not-exported (given)                         766
      directions with not-imported                                 8875
      directions with not-imported (given)                         58
      directions with undecided: exporter has undecided terms      19254
      directions with undecided: exporter has undecided terms (given) 3
      directions with undecided: importer has undecided terms      19263
      directions with undecided: symbolic test on one side only    911
      directions with undecided: symbolic test on one side only (given) 16
      lint: lint/empty                                             50710
      lint: lint/missing-router                                    2526
      lint: lint/missing-set                                       8011748
      lint: lint/no-aut-num                                        40708
      lint: lint/shadowed                                          25515
      lint: lint/undecided                                         93447
      not decidable                                                2
      pairs                                                        477026
      timeout                                                      91
      via sets, not checked                                        7104372
```

Two rows are new since the pairing rule changed to direct peers only
(Ruling R20). "directions with no policy either way" counts a direction
where neither side has any term toward the other, decided or undecided, in
that family (`Direction.NoPolicy`; see "Findings" above) — counted apart
from `consistent`, never as one. "via sets, not checked" is each aut-num's
`PeerList.ViaSets` that no pair checked already covers: peers reached only
through an as-set or a peering-set (see "Peers through sets" above) —
7,104,372 of them here, against 477,026 pairs the sweep actually checked.
The sweep pairs only an aut-num's *direct* peers, Forward and Reverse, named
as a bare AS number; a peer named only through a set is never drawn into a
pair by this test, on either side.

No `verify timeout` was counted, and all 8875 unconditional `not-imported`
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
  not checked. An export action that changes communities only makes the
  comparison of a community test the importer shares undecided.
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
  Reverse list only indexes a peering written as a bare AS number; a
  peering written only as an as-set is found by expanding it from the
  other side (`ViaSets`, checked with `-set-peers`), not via the index.
- **Evaluating regexps or community tests.** Both are compared by identity
  only (`given:`), never matched against a route — the library never
  evaluates an AS-path regexp or a community test against live data.
