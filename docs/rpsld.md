# rpsld: an IRRd-compatible mirror

`rpsld` keeps a set of IRR registries in memory — from dump files, NRTMv4
mirrors and RPKI VRPs — keeps them current, and answers IRRd's query
protocol and RIPE-style whois queries on them, on one port, as IRRd 4.5.3
answers. bgpq4, IRRToolSet's `peval` and `rtconfig`, `rpslq`, and this
library's own `irrd.Source` and `whois.Source` run against it unchanged.

It is for one network's own tooling: a mirror on localhost or an internal
network, so that filter generation and policy checks query current data
without RADB's or RIPE's rate limits (RADB answers about 1,200 queries a
second to one client) and without crossing the internet. It has limits and
never answers with a cut-short reply, but it is not a public service: it has
no per-client rate limits or abuse handling.

It serves the routing classes only — as-set, route-set, rtr-set,
filter-set, peering-set, aut-num, inet-rtr, route and route6. A query for
anything else is refused, never answered "not found" (see "What it keeps").

The semantics live in `resolve/irrdq` (pure: no sockets, no goroutines), the
sockets in `resolve/irrdserver`; `rpsld` (`resolve/cmd/rpsld`, logic in
`resolve/internal/rpsld`) loads the inputs and keeps them current. The
design is in `docs/rpsl-go-design.md` §8.13.

## Install

With a Go toolchain:

```sh
go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpsld@latest
```

Static release binaries ship beside `rpslq`'s, `rpslconf`'s and
`rpslcheck`'s: each [release](https://github.com/rkolesnichenko/rpsl/releases/latest)
carries `rpsld` for Linux and macOS (amd64, arm64) and Windows (amd64), with
`SHA256SUMS`. `rpsld -v` prints the binary's version.

## Running it

Each `-source NAME=SPEC` is one registry; the flags' order is the
registries' precedence, as `rpslq -S` gives it. `SPEC` is one of:

- `dump:FILE[,FILE…]` — dump files, gzip or plain, read in order. The
  registry holds only the objects whose `source:` is `NAME` (case
  ignored); any other object in the files is left out and counted in the
  `loaded` log line (`other_sources`). The files are re-read when any of
  their modification times changes (looked at every `-check-dumps`) and on
  SIGHUP.
- `nrtm4:URL,key=PEMFILE` — an NRTMv4 mirror (draft-ietf-grow-nrtm-v4) of
  the database `NAME`, from its Update Notification File (`https://`, or
  `file://`), whose signature is checked with the public key in `PEMFILE`.

A file name or URL may not hold a comma. `RPKI` is no `-source`: it is the
registry `-rpki` makes.

The RIPE Database over NRTMv4, with the key RIPE publishes (a copy is in
the repository, `resolve/nrtm4/testdata/ripe-public-key.pem`), and RADB from
its dump:

```sh
rpsld -source RIPE=nrtm4:https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose,key=/etc/rpsld/ripe.pem \
      -source RADB=dump:/var/lib/irr/radb/radb.db.gz \
      -rpki https://rpki.gin.ntt.net/api/export.json \
      -state-dir /var/lib/rpsld -listen 127.0.0.1:43
```

`rpsld` does not fetch dumps. `scripts/fetch-irr-dumps.sh` does, from cron:
it writes each file under a temporary name and renames it into place, and
downloads only a copy newer than the one it has, so `rpsld` sees one whole
new file and re-reads it at its next check.

```sh
# crontab: RADB's dump, every six hours, into /var/lib/irr/radb/radb.db.gz
0 */6 * * *  cd /opt/rpsl && DIR=/var/lib/irr scripts/fetch-irr-dumps.sh radb
```

RIPE's split dumps work as one registry too, listing the routing classes'
files (`RIPE=dump:ripe.db.as-set.gz,ripe.db.route-set.gz,ripe.db.aut-num.gz,…`).

`-rpki` takes the VRPs a relying-party validator exports
(rpki-client's or Routinator's JSON, the form IRRd's `rpki.roa_source`
reads) from a file or an `https://` URL; `-slurm` applies an RFC 8416 file
to them. The example above uses NTT's export, IRRd's default `roa_source`.

Once every input has loaded, `rpsld` listens; until then it answers
nothing. It logs (`log/slog` text, to stderr) one line per load, sync,
swap, reload and failure, with the registry, its serial and the time taken;
a query that failed for a reason of the server's own (the client gets only
IRRd's "An internal error occurred") with its cause and the command's name;
each command only with `-log-queries`.

### A systemd unit

```ini
[Unit]
Description=rpsld, an IRRd-compatible mirror
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=3600
StartLimitBurst=3

[Service]
User=rpsld
ExecStart=/usr/local/bin/rpsld \
    -source RIPE=nrtm4:https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose,key=/etc/rpsld/ripe.pem \
    -source RADB=dump:/var/lib/irr/radb/radb.db.gz \
    -rpki https://rpki.gin.ntt.net/api/export.json \
    -state-dir ${STATE_DIRECTORY} -listen 127.0.0.1:43
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=300
StateDirectory=rpsld
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`AmbientCapabilities` lets an unprivileged user bind port 43; with
`-listen` on a port above 1023 it is not needed. `systemctl reload rpsld`
re-reads every dump registry. SIGTERM (`systemctl stop`) stops it: the
listener closes, open connections get `-grace` to finish, and it exits 0.
`Restart=on-failure` starts it again after exit status 3, such as a mirror
whose first snapshot download failed: five minutes later, and at most three
times an hour (`StartLimitIntervalSec`, `StartLimitBurst`), since each
start of a mirror downloads its whole snapshot (RIPE's is about 400 MB). A
second SIGTERM or SIGINT during `-grace` ends `rpsld` at once.

### Flags

From `rpsld -help` (the notes in brackets are not in the help text):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-source` | — | a registry: `NAME=dump:FILE[,FILE…]` or `NAME=nrtm4:URL,key=PEMFILE` (repeatable; the order is precedence) |
| `-rpki` | — | VRPs (rpki-client/Routinator JSON): a file or an https:// URL; serves the registry RPKI and hides RPKI-invalid routes |
| `-rpki-refresh` | `1h0m0s` | how often `-rpki` is re-read (IRRd's roa_import_timer default; a download over 512 MB is refused) |
| `-slurm` | — | an RFC 8416 SLURM file applied to `-rpki` |
| `-rpki-default` | `true` | select the RPKI registry by default, last, as RADB does |
| `-listen` | `:43` | the address of the IRRd and whois query port |
| `-rfc` | off | RFC 2622 answers for `!i…,1` and `!a` (`resolve.Expander`), not IRRd's |
| `-keep-route-text` | off | keep every route's text, for `!m route`, `!r` and `-i origin` |
| `-state-dir` | — | a directory for each NRTMv4 mirror's current signing key |
| `-check-dumps` | `1m0s` | how often dump files' modification times are checked |
| `-nrtm-interval` | `1m0s` | how often each NRTMv4 mirror polls [at least a minute: less exits 2] |
| `-max-conns` | `256` | connections served at once |
| `-idle-timeout` | `30s` | how long a connection may wait between commands (IRRd's default; `!t` overrides it) |
| `-max-line` | `1048576` | bytes in one command line |
| `-max-reply` | `268435456` | bytes in one answer |
| `-query-time` | `1m0s` | how long one command may evaluate |
| `-grace` | `10s` | how long open connections get to finish at shutdown |
| `-log-queries` | off | log every command |
| `-v` | — | print rpsld's version and exit |

## Freshness

`!j` reports each registry's serial, in IRRd's form, `NAME:N:0-<serial>`
(`!j-*` every registry, in precedence order; `!jRIPE,RADB` the ones named;
a name no registry has is `NAME:X:Database unknown`). The serial is:

- for an NRTMv4 mirror, the NRTMv4 version it holds (`RIPE:N:0-897793`);
- for a dump registry, its load count: 1 when `rpsld` starts, one more
  after each reload. It starts again at 1 when `rpsld` restarts, and it is
  not the registry's own serial (a `CURRENTSERIAL` file is not read);
- for `RPKI`, the same kind of count over the VRPs' loads. It moves on
  every refresh, whether or not the VRPs changed.

Each change is built beside the snapshot being served and published with
one atomic store; a command reads the snapshot once, so one answer comes
from one snapshot, never a mixture, and answers in progress finish on the
one they read.

When a reload, a sync or a VRP refresh fails after startup, the registry
keeps its previous data and its serial: the failure is logged, and a client
sees the mirror fall behind in `!j`, never half-updated data. A dump file
whose modification time cannot be read is logged once, not at every check,
and a changed dump that cannot be read is tried again at its next change
or SIGHUP, not at every check.

Replace a dump atomically: write the new file elsewhere on the same file
system, then rename it over the old one, as `scripts/fetch-irr-dumps.sh`
does (it downloads to `FILE.part` and renames that). A plain dump read while it is still being
written reads without error, as a shorter dump, and would be served so; a
gzip file cut short fails its read, and the previous data stays.

Each NRTMv4 mirror polls every `-nrtm-interval`, never more often than once
a minute (NRTMv4 §5.2; a smaller value exits 2). After a failed sync it
waits twice `-nrtm-interval`, doubling the wait with each further failure
in a row, up to an hour (never less than `-nrtm-interval`), and starts
again from `-nrtm-interval` after a success. `nrtm4.Client` loads the whole
snapshot again after three failed deltas in a row, so without the hour's
backoff a delta the mirror keeps refusing would download RIPE's snapshot
every few minutes. Every
file is verified before it is used (design §8.8): a signature (ES256, ES384, ES512, Ed25519, RS256 or PS256, each bound to its key type), a
SHA-256 hash per file, the delta chain contiguous; a refused delta applies
nothing, and nothing after it does. A notification file older than 24 hours
is refused, as IRRd refuses one, so a restart cannot be fed a replayed old
file.

With `-state-dir`, each mirror's current signing key is written to
`<dir>/<NAME>.pem` whenever it changes (to a temporary file, synced, then
renamed into place), and read at the next start in place of `key=`, so a key
rotated while `rpsld` was down still verifies. A key file there that cannot
be read stops the start (exit 3) rather than being passed over.

## Queries

IRRd commands begin with `!`; any other line is a RIPE-style query, on the
same port, as IRRd 4 serves both. Without `!!` a connection closes after
one answer; commands may be pipelined, and are answered in order. Every
answer is byte for byte what IRRd 4.5.3 answers on the same data — its
ordering, spacing, `D`/`F` choice and error text — except where
`resolve/testdata/rpsld/divergences.md` says otherwise.

| Command | Answer |
| --- | --- |
| `!!` | persistent mode |
| `!q` | close (`q` alone is a RIPE-style query, as in IRRd) |
| `!v` | `IRRd -- version 4.5.3 (rpsld <version>)` |
| `!n<name>` | accepted |
| `!t<seconds>` | the connection's idle timeout, 1-1000 s |
| `!s<list>`, `!s-lc`, `!s-*` | select registries (comma-separated, in that order), list the selection, change nothing; an unknown registry is refused and the selection stays |
| `!j-*`, `!j<list>` | serials (see "Freshness") |
| `!i<set>` | the set's direct members, normalized (an AS number asplain, a prefix canonical, a bare address with its host length, an operator kept), plus the mbrs-by-ref claimants from the set's own registry; the set's own name, as sent, left out |
| `!i<set>,1` | IRRd's recursive resolution (below) |
| `!a<as-set>`, `!a4…`, `!a6…` | the prefixes the as-set's ASes originate, by family, sorted |
| `!g<AS>`, `!6<AS>` | the prefixes an AS originates, sorted |
| `!r<prefix>[,o\|l\|L\|M]` | route objects for the exact prefix, or with `l` the most specific less specific one, `L` every less specific one and the exact one, `M` every more specific one; with `o` the exact prefix's origins instead, one per object |
| `!m<class>,<key>` | the object, from the first selected registry holding it, matched by its canonical primary key only (`!maut-num,AS065001` finds nothing); IRRToolSet's legacy `an`, `ir`, `rt` accepted |
| `-V <agent> !<command>` | the IRRd command, the user agent dropped |

IRRd answers `!g`, `!6` and `!a` in hash order and multi-object answers in
database order; `rpsld` sorts them (IPv4 first, by address, then length),
so its answers are deterministic.

`!i<set>,1` is IRRd's recursion, not RFC 2622's. From an as-set it follows
as-sets only; from a route-set it follows route-sets and as-sets, an AS
member giving its routes' prefixes and a prefix member kept with its range
operator as written — and so a route-set listed in an as-set is followed
when the expansion began at a route-set. A member with a range operator on
a set or an AS number (`RS-INNER^25`, `AS65002^24`) is looked up as a set
name, found nowhere and dropped; so are a missing set, a set of another
class, and `AS-ANY`/`RS-ANY`, which IRRd has no set for. The differences
from the engine are listed in `resolve/testdata/bgpq4/divergences.md`.

RIPE-style queries read the line as IRRd 4.5.3's `handle_ripe_command`
does: split at spaces, read left to right, the last search answering.
Flags are whole words: `-rK` is no flag.

| Flag | Meaning |
| --- | --- |
| `-s <list>` | select registries, for the rest of the connection |
| `-T <classes>` | restrict the next search to these classes |
| `-i <attr> <value>` | inverse search on `origin`, `member-of`, `mbrs-by-ref`, `members` or `mp-members`; as in IRRd, the value is upper-cased and matched as given against each member as stored, so a route-set member spelled in lower case, or an IPv6 prefix with a letter in it, is not found, and an rtr-set's address is found as written, not as a host prefix |
| `-x`, `-l`, `-L`, `-M <prefix>` | route search: exact, one level less specific, all less specific, more specific |
| `-K` | primary keys and members only |
| `-k` | keep the connection open |
| `-r`, `-F`, `-V <agent>` | accepted, change nothing |
| a key, with `-T` naming kept classes only | the objects of those classes it names: an aut-num, the routes of a prefix and every less specific one, a set, a route by `<prefix><origin>`, an inet-rtr |

A plain lookup — a key without `-T`, or with a `-T` that names a class the
mirror does not keep — is refused (see "What it keeps"); `whois.Source`
always sends `-T`, so it is not affected.

**Not served**, though IRRd answers them: `!e` (set exclusion), `!J`
(database status as JSON), `!o<mntner>` (refused as `-i mnt-by` is),
`!fno-rpki-filter`, `!fno-scope-filter`, `!fno-route-preference-filter`,
and the RIPE-style `-a`, `-t`, `-q` and `-g`. Each gets a refusal naming
it, not "unrecognised". Any other flag, `-B` and `-G` among them, is IRRd's
`Unrecognised flag/search`, as IRRd 4.5.3 answers them.

### RPKI-aware mode

With `-rpki`, `rpsld` answers as IRRd 4's RPKI-aware mode (design §8.7):

- a route or route6 that RFC 6811 finds invalid against the VRPs is hidden
  from every answer — `!g`, `!6`, `!a`, `!i` claimants, `!r`, `!m`,
  RIPE-style searches. A route-set's listed prefixes are not routes and
  stay;
- a served route's text ends with IRRd's `rpki-ov-state:` line (`valid`,
  or `not_found # No ROAs found, or RPKI validation not enabled for
  source`); a pseudo route of the registry `RPKI` carries none;
- the registry `RPKI` holds IRRd's pseudo route object for each VRP, as
  `rpki.WriteRPSL` renders it. They are never hidden (an AS0 VRP's pseudo
  route included, as in IRRd), and `!m route,<prefix><origin>` does not
  find them, since IRRd keys them with their maximum length too.

`RPKI` comes last in precedence. With `-rpki-default` (the default) it is
also in the default selection, last, as RADB lists its pseudo source;
`-rpki-default=false` leaves it out, as IRRd's own `sources_default` does,
and a client selects it with `!s` or `-s`.

### RFC mode

With `-rfc`, `!i<set>,1` and `!a` answer with the engine's RFC 2622
expansion (`resolve.Expander` over the selected registries, in precedence
order) instead of IRRd's; every other command is unchanged. The answers
differ from IRRd mode exactly where the engine differs from IRRd
(`resolve/testdata/bgpq4/divergences.md`):

- range operators on members are applied, and ranges written in RPSL
  notation (`192.0.2.0/24^25`);
- a route-set listed in an as-set is not followed (RFC 2622 §5.1);
- `src-members:` is honoured, a scoped reference looked up in its registry
  whether selected or not;
- an expansion that reaches `AS-ANY` or `RS-ANY` is refused
  (`F AS-ANY denotes the whole registry: not expanded in RFC mode`);
- an expansion over a limit is refused with the engine's error (with a
  MaxDepth of 1, `F resolve: expansion of AS-L1 exceeds MaxDepth (1):
  reached 2`), never answered in part. `rpsld` uses the engine's default limits (MaxDepth 32,
  MaxVisited 1<<17, MaxPrefixes 1<<20).

In RPKI-aware mode the expansion leaves out what IRRd mode hides, with the
same rule. `resolve/testdata/rpsld/divergences.md` lists the recorded IRRd
exchanges RFC mode answers otherwise.

## What it keeps

A registry holds the routing classes: as-set, route-set, rtr-set,
filter-set, peering-set, aut-num and inet-rtr whole (aut-nums and inet-rtrs
as text, decoded per query), and route and route6 as prefix, origin and
source — whole when they claim membership of a set (`member-of:`), and as
text too with `-keep-route-text`.

Anything else is refused, never answered as missing. A mirror that holds
part of a registry must not pass the rest off as absent: a "not found" for
a maintainer or a person it never loaded would be false.

| Query | Answer |
| --- | --- |
| `!m` of a class RIPE's or IRRd's tables list but the mirror does not keep | `F Class mntner is not kept by this mirror` |
| `-T` naming such a class | `%% ERROR: Class mntner is not kept by this mirror` |
| `-i mnt-by`, `admin-c`, `tech-c`, `zone-c`, `person`, `role`; `!o` | `Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only` |
| a plain lookup without `-T` | `%% ERROR: This mirror keeps only the routing classes, so it cannot answer a lookup of <key> whole; ask with -T and any of as-set, route-set, rtr-set, filter-set, peering-set, aut-num, inet-rtr, route, route6` |
| route text without `-keep-route-text` | `F Route text is not kept by this mirror (rpsld -keep-route-text)` (RIPE-style: `%% ERROR: …`) |

A plain lookup is refused because IRRd's text search answers it with
classes the mirror lacks: an AS number with the as-blocks covering it, a
prefix with inetnums and inet6nums, any other key with persons and roles
whose name holds it. With `-T` naming only kept classes the answer is whole,
and is given. A class name neither table lists stays IRRd's answer (`D`;
`-T foo` gives "No entries").

Route text is what `!m route`/`!m route6`, `!r` without `o`, `-i origin`,
`-x`/`-l`/`-L`/`-M` and a lookup of a prefix need; `!g`, `!6`, `!a`,
`!r…,o`, `-K` and every set query do not. `irrd.Source`, bgpq4 and
IRRToolSet need no route text; `whois.Source` asks `-i origin` for an AS's
routes, so it needs `-keep-route-text`. The `RPKI` registry always keeps
its pseudo routes' text.

Object text is served as the registry published it: the attribute lines as
loaded, without the blank and comment lines a dump puts around an object.
IRRd re-renders it (names lower-cased, values padded to column 16, lists
rejoined with commas); `rpsld` does not.

A set whose `members:` holds an item the library cannot read is served with
its valid items and that item as written, upper-cased; IRRd's import refuses
the whole object (and a route-set whose `members:` holds an IPv6 prefix), so
an IRRd mirror would not have the set at all.

## Limits

Every limit is a flag. Over the line, answer or query-time limit, a client
gets an `F` line naming it, as IRRd answers an error, never a cut-short
answer; past `-max-conns` or the idle timeout the connection is closed.

| Limit | Default | Over it |
| --- | --- | --- |
| `-max-conns` | 256 | a further connection is closed as soon as it is accepted, unanswered |
| `-idle-timeout` | 30 s | the connection is closed; `!t` sets it per connection, 1-1000 s |
| `-max-line` | 1 MiB | `F Line too long: over 1048576 bytes`, and the connection is closed, as soon as more than that many bytes of one line have arrived, newline or not |
| `-max-reply` | 256 MiB | `F Answer larger than 268435456 bytes` in place of the answer; the connection stays |
| `-query-time` | 1 min | `F Query took longer than 1m0s` in place of the answer; the connection stays |

The idle timeout is IRRd's (`SOCKET_DEFAULT_TIMEOUT`, 30 s, measured at
30.03 s); the other four are `rpsld`'s own. IRRd 4.5.3 behaves otherwise in
two ways: past its `max_connections` (10) it queues a connection until one
ends, where `rpsld` closes it at once, so the client can retry or go
elsewhere; and it has no line limit (a 1 MB line was answered).

An answer is never sent in part: `-max-reply` is decided before anything of
it is written. Nor is one far over the limit built only to be refused: the
text of an answer that grows with the data — route objects (`!r`, `-M`,
`-L`), a list of origins (`!r…,o`), of prefixes or members (`!g`, `!6`,
`!a`, `!i`), RIPE-style objects and their `-K` forms — stops being built as
soon as it passes `-max-reply`, so `!r0.0.0.0/0,M` over a whole registry
costs a connection a small multiple of `-max-reply` in memory, not the
answer's size. A route's text is held by reference while an answer is built
and copied once, into the answer sent. Only the text is under the limit, not
what some answers are made from: the members or prefixes of `!i`, `!i…,1`
and `!a` (the whole expansion), the prefixes of `!g` and `!6`, and the
objects an `-i` search finds (with a copy of the text of each route that
names the set in `member-of:`) are gathered whole first, so they cost memory
in proportion to what the registry holds for them, whatever `-max-reply` is.

The idle timeout also bounds how long the client takes to read each 64 KiB
of an answer, not the whole answer. A client that reads just fast enough
can hold a connection for one idle timeout per 64 KiB (a 256 MiB answer is
4,096 pieces); only `-max-conns` bounds how many such clients there are.

At shutdown (SIGTERM, SIGINT) `rpsld` stops accepting, lets each connection
finish the command it is answering, writes out every answer completed so
far, whole, and closes. A command still running at the end of `-grace` is
abandoned unanswered, and an answer still being written then may be cut
short; the connection is closed either way. A second SIGTERM or SIGINT
during `-grace` ends `rpsld` at once.

## How it is tested

Two oracles:

- **IRRd itself.** `resolve/testdata/irrd` holds a fixed fixture (two
  registries, RIPE and RADB, with a set for each of IRRd's corner cases, and
  ROAs) and IRRd 4.5.3's recorded answers to 274 exchanges on it, in plain
  and RPKI-aware mode (`golden/plain.txt`, `golden/rpki.txt`). They were
  recorded from IRRd in Docker, and are re-recorded with
  `RPSL_IRRD_DOCKER=1 go test -run TestRecord ./internal/irrdoracle` (from
  `resolve/`; Docker and Compose only, nothing installed on the host). A
  golden is never edited by hand. `irrdq`'s `TestGoldens` replays every
  exchange; each answer must match byte for byte, or as a multiset where
  IRRd's order is a hash's, or (object text) after IRRd's re-rendering is
  applied to both sides. Each deliberate difference is pinned with
  `rpsld`'s own answer and listed in `resolve/testdata/rpsld/divergences.md`.
- **`irrtest`**, the library's in-process IRRd, written independently of
  `irrdq`, corrected against the same recordings (`TestMatchesIRRd`), so the
  two cannot share a bug the recordings would show. `TestIRRdqMatchesIrrtest`
  holds `irrdq` to it on random IRRs, for every command family: `!i`,
  `!i…,1`, `!a`, `!g` and `!6`; `!m`; RIPE-style `-T` lookups, `-i origin`
  and `-i member-of` and their `-K` forms; and the lists and `!m` again in
  RPKI-aware mode with random ROAs.

Then the clients:

- the expansion, RPKI, policy and consistency models
  (`TestModelBackends`, `TestModelRPKIBackends`, `TestModelPolicyBackends`,
  `TestModelConsistBackends`) run `irrd.Source` and `whois.Source` against
  `rpsld` as against `irrtest`, held to the same brute-force oracles;
- bgpq4 (`TestBgpq4Differential`, `TestRpslqServerSideMatchesBgpq4`),
  `rpslq` (the latter, with and without `--server-expand`) and IRRToolSet's
  `peval` and `rtconfig` (`TestPevalMatchesIRRToolSet`,
  `TestRtconfigMatches`) give the same output against `rpsld` as against
  `irrtest`, when the binaries are installed;
- `internal/rpsld`'s tests run the command against `nrtmtest` (random
  histories of deltas, snapshots and new sessions; a refused delta leaves
  the answers and the `!j` serial as they were) and against dump files
  changed, removed and reloaded;
- `irrdserver`'s tests hold each limit at exactly its value, check that
  answers read while registries swap come from one snapshot (under
  `-race`), and count goroutines after shutdown;
- `FuzzSession` (any command lines, in any order) and `FuzzSourceSpec`
  (`-source` values) never panic, and every frame's length is its payload's.

## On real data

Measured 2026-10-04 on the branch that became v0.24.0, on RIPE's split dumps
of 2026-09-27 (the nine routing classes, 654,490 objects) and RADB's dump of
2026-09-23 (1,380,857 objects), each registry loaded alone in its own test
process (`TestRealDataServe`, under `GOMEMLIMIT=6GiB`). A load is one
registry read from its dumps; a reload builds a second registry beside the
first while the first is served, as a dump change does.

| Registry | `-keep-route-text` | Load | Heap after load | Reload | Heap, both registries alive | Highest heap sampled during the reload (garbage included) | Peak RSS of the process |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RIPE | off | 35 s | 622 MB | 37 s | 1245 MB | 2243 MB | 2682 MB |
| RIPE | on | 34 s | 981 MB | 36 s | 1962 MB | 3764 MB | 4134 MB |
| RADB | off | 46 s | 698 MB | 49 s | 1396 MB | 2255 MB | 2671 MB |
| RADB | on | 47 s | 1079 MB | 55 s | 2158 MB | 3921 MB | 4796 MB |

Some answers, from the same runs (without route text; with it, the same
sizes):

| Query | Bytes | Time |
| --- | --- | --- |
| `!iAS-DECIX` (RIPE) | 26 | 0 s |
| `!aAS-DECIX` (RIPE) | 8,306,859 | 1.283 s |
| `!maut-num,AS3333` (RIPE) | 137,624 | 14 ms |
| `!iAS-HURRICANE` (RADB) | 210,085 | 19 ms |
| `!aAS-HURRICANE` (RADB) | 8,415,676 | 880 ms |
| `!gAS6939` (RADB) | 4,698 | 0 s |

RIPE and RADB loaded together in one process, and a reload of one beside
the other, were not measured: projected from the runs above, the peak would
pass the 6 GB the measuring machine could spare. Add the per-registry
figures for an estimate.

bgpq4 against `rpsld` was held to `rpslq --dump` over the same RIPE dumps
(`TestRpsldMatchesRpslqRealData`; the as-set, route-set, aut-num, route and
route6 files, 653,853 objects): for as-sets and for route-sets, the 10
largest by direct members and a seeded sample of 150, deduplicated; an
as-set's `-t` list and both classes' `-4` and `-6` lists, byte for byte.

```
rpslq --dump vs bgpq4 against rpsld: 315 sets picked; 309 the same; 1 differ and 0 are refused by rpslq where a known divergence explains it (sets by divergence in the closure: single-length-range 1); 4 over a prefix limit, not compared; 0 with a range operator on a set or AS member in the closure, not compared; 1 past rpslq's 5m0s deadline, not compared; 10m45s in all, heap 1493 MB
```

The one difference is bgpq4's `^n` bug (`AS12491:RS-IPPLANET-GERMANY`
lists `169.239.72.0/22^24`); the four over a prefix limit are bogon and
martian route-sets (`AS20483:RS-MARTIANS-OUT`, `AS12695:RS-BOGUS`,
`RS-DISREGARD`, `AS210578:RS-BOGONS-V4`), which `rpslq` refuses at 2^23
prefixes; and the one past the deadline is `RS-MOUATS-V6-ROUTES`
(`2607:f150:ffff::/48^48-128`), whose `-6` list `rpslq` was still building
after five minutes (the run was at background priority, under a memory
watchdog). bgpq4 is not run on either kind: it would enumerate them without
end. Peak RSS of the test process and its bgpq4 children: 1851 MB.

The RIPE Database mirrored live over NRTMv4 (`TestLiveMirror`, 2026-10-04):
the snapshot and deltas loaded in 44 s, 654,678 objects at version 897793,
728 MB of heap with the mirror held, 1433 MB peak RSS. The direct members of
the 20 largest RIPE as-sets, asked of `rpsld` and of whois.ripe.net:

```
live: 20 sets, 0 differ (at 2026-10-04T10:38:41Z)
```

These tests are opt-in and not part of `scripts/check.sh`. Each loads a
whole registry, so on a workstation run them one at a time, with a memory
cap:

```sh
cd resolve
RPSL_REALDATA=$PWD/../.data go test -run TestRealDataServe ./internal/rpsld   # RPSL_REALDATA_REGISTRY=RIPE|RADB, RPSL_REALDATA_KEEPTEXT=0|1
RPSL_REALDATA=$PWD/../.data go test -timeout 30m -run TestRpsldMatchesRpslqRealData .   # bgpq4 installed; RPSL_REALDATA_LARGEST, RPSL_REALDATA_SAMPLE
RPSL_LIVE_NRTM=1 RPSL_REALDATA=$PWD/../.data go test -run TestLiveMirror ./internal/rpsld   # about 400 MB from RIPE
```

## Exit status

- **0** — stopped as asked (SIGTERM or SIGINT), or `-v`.
- **2** — a command line `rpsld` cannot use: no `-source`, a malformed or
  repeated one, an argument that is no flag, a limit or interval that is
  not positive, a negative `-grace` (0 is accepted), `-nrtm-interval` under
  a minute, `-slurm` without `-rpki`; `-help` too.
- **3** — could not complete: an input failed to load at startup (a dump
  that cannot be read, a mirror whose snapshot, signature or a delta is
  refused or whose notification file is over 24 hours old, a key file in
  `-state-dir` that cannot be read, VRPs that cannot be read), the port
  could not be opened, or serving failed. A stop asked for during startup
  exits 0.

## What it does not do

- **Serve mirrors downstream.** No NRTMv3 or NRTMv4 is served.
- **Accept updates.** No submission, no authentication.
- **Public-internet hardening.** No per-client rate limits or abuse
  handling; `-max-conns` is the only bound on clients.
- **Classes holding personal data**, and every other class outside the
  routing classes (refused, above), and `!o`.
- **IRRd 4's HTTP and GraphQL API.**
- **Fetch dumps.** cron and `scripts/fetch-irr-dumps.sh` do.
- **Multicast.**
- **The IRRd commands and flags listed under "Not served"**: `!e`, `!J`,
  `!fno-rpki-filter` and the other `!f` switches, `-a`, `-t`, `-q`, `-g`.
- **IRRd's import validation.** An object the library parses is served
  (above), and nothing in a dump is refused as IRRd's loader would.
