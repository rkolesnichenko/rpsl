# An IRRd-compatible mirror server (`rpsld`)

Status: designed · 2026-10-02

## 1. Summary

The library reads every IRR the way its servers do — dumps, NRTMv4 mirrors,
RPKI-aware filtering, IRRd's and whois's query protocols as a client — but
nothing in it answers a query. An operator who wants bgpq4, IRRToolSet or
`rpslq` to run against current data still queries RADB or RIPE across the
internet, under their rate limits (RADB answers about 1,200 queries a second
to one client, design §8.5) and their source selection.

This milestone adds a server: `rpsld` keeps a set of registries in memory —
from dumps, NRTMv4 mirrors and RPKI VRPs — and answers the IRRd query protocol
and RIPE-style whois queries on them, the way IRRd 4 answers, so any IRRd
client works against it unchanged.

It adds a pure package that holds IRRd's query semantics (`resolve/irrdq`), a
socket package that serves them (`resolve/irrdserver`), an opt-in route-text
mode on `resolve.Corpus`, and the command `rpsld`.

### Decisions taken in brainstorming

1. **Direction:** an IRRd-compatible server, ahead of a second round of
   consistency checks, more router vendors and a set-hygiene audit.
2. **Semantics: IRRd's by default.** On the same data a client gets what IRRd
   4 would answer, including where IRRd and the engine differ
   (`resolve/testdata/bgpq4/divergences.md`): a member with a range operator
   stays an unresolved leaf, an as-set follows a route-set listed in it,
   `AS-ANY` is a missing set, `src-members:` is not read. `-rfc` switches
   `!i…,1` and `!a` to the engine's RFC 2622 answers.
3. **Deployment: an operator's own mirror.** Run by a network for its own
   tooling, on localhost or an internal network. It serves the routing
   classes; it has limits and never panics on hostile input, but it is not a
   public service.
4. **Data: dumps, NRTMv4 and RPKI.** Any mix per registry, NRTMv4 kept current
   every minute, dumps re-read when they change, VRPs refreshed; each change
   publishes a new immutable snapshot.
5. **Approach A: per-registry snapshots and a pure semantics layer.** Not an
   IRRd mode inside `resolve.Expander` (the engine stays RFC 2622's), and not a
   caching proxy (no fresher than its upstream).

## 2. Architecture

```
resolve.Corpus.KeepRouteText   route/route6 text kept, opt-in (new field)
resolve/irrdq                  IRRd's query semantics over a Snapshot (new, pure)
resolve/irrdserver             listeners, framing on the wire, limits (new, sockets)
resolve/internal/rpsld         inputs, refresh, snapshot publishing (new)
resolve/cmd/rpsld              the command (new shim)
resolve/internal/irrtest       unchanged in role: the independent oracle
```

Imports run `internal/rpsld → irrdserver → irrdq → resolve`, with
`internal/rpsld` also using `nrtm4` and `rpki`. `resolve/irrdq` is pure: no
`net`, no goroutines of its own, context-cancellable. The purity check becomes
`cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq | grep -x net`
(must print nothing). Sockets live only in `irrdserver` and the existing
client backends.

`resolve/internal/irrtest` stays independent: `irrdq` never imports it and it
never imports `irrdq`. It is one of the two oracles (§7); where it disagrees
with a real IRRd, IRRd decides and `irrtest` is corrected.

## 3. The snapshot (`resolve/irrdq`)

```go
// A Registry is one source's data, immutable once built.
type Registry struct {
    Name   string             // canonical source name (types.ParseSourceName)
    Serial uint64             // NRTMv4 version, or a load count for dumps
    Src    *resolve.MemSource // built from this registry's Corpus alone
    // unexported: the prefix index for !r, route text when kept
}

// NewRegistry builds a Registry from one source's Corpus.
func NewRegistry(name string, serial uint64, c *resolve.Corpus) (*Registry, error)

// A Snapshot is the server's whole state for one answer: registries in
// precedence order, and the VRPs when RPKI-aware.
type Snapshot struct { /* unexported */ }

func NewSnapshot(regs []*Registry, opts SnapshotOptions) (*Snapshot, error)
func (s *Snapshot) With(r *Registry) *Snapshot // replaces one registry by name

type SnapshotOptions struct {
    VRPs *rpki.VRPs // RPKI-aware mode: suppress invalid routes, serve source RPKI
    RFC  bool       // !i…,1 and !a answered by resolve.Expander
    Expander resolve.Expander // limits for RFC mode (Src is set per query)
}
```

- **One registry, one index.** IRRd's rules are per source: `!s` selects
  sources, `!j` reports each one's serial, a `mbrs-by-ref` claim must come
  from the set's own source (design §8.2). A registry therefore keeps its own
  `MemSource`, built from a `Corpus` that holds that source alone, and a
  change to one input rebuilds only its registry.
- **Precedence** is the registry order, as `rpslq -S` gives it: a lookup by
  primary key answers from the first selected registry that holds the key.
- **RPKI.** With `VRPs`, the snapshot answers as IRRd 4's RPKI-aware mode
  (design §8.7): routes invalid under RFC 6811 vanish from every answer
  (`!g`, `!6`, `!a`, `!i` claimants, `!r`, `!m`, whois), a visible route's
  text gains IRRd's `rpki-ov-state:` line, and the registry `RPKI` holds the
  pseudo route objects `rpki.AddTo` makes. New VRPs make a new snapshot.
- **Route text (`Corpus.KeepRouteText`).** A `Corpus` keeps a route that
  claims nothing as its (prefix, origin, source) tuple only (design §8.9), so
  its text is not there to answer `!m route`, `!r …,o` or whois `-i origin`.
  `KeepRouteText`, set before the first `Put`, keeps each route and route6 as
  text as well (source interned, as `KeepPolicy` keeps aut-nums), under the
  same identity `Delete` and NRTM replacement use. Without it those queries
  are refused (§4), never answered as "not found". Its cost on RIPE is
  measured (§7) and published.

## 4. Queries (`resolve/irrdq`)

```go
// A Session is one client connection's state.
type Session struct { /* selected sources, persistent mode, closed */ }

func NewSession(snapshot func() *Snapshot) *Session

// Do answers one command line. The snapshot is read once per call, so one
// answer comes from one snapshot.
func (s *Session) Do(ctx context.Context, line string) (Reply, error)

// A Reply is what the server writes: an IRRd frame (A<len>…C, C, D, E,
// F <message>) or whois text, and whether the connection closes after it.
type Reply struct { /* … */ }
func (r Reply) WriteTo(w io.Writer) (int64, error)
func (r Reply) Close() bool
```

Every command answers byte for byte as the pinned IRRd 4 release does on the
same data (§7): its ordering, spacing, `D`/`F` choice and error text.

| Command | Answer |
| --- | --- |
| `!!` | persistent mode; without it a connection closes after one answer |
| `!q`, `q` | close (IRRd's way and IRRToolSet's) |
| `!v` | a version string containing "version" (IRRToolSet needs it) |
| `!n<name>`, `!t<seconds>` | accepted; `!t` capped by the server's limit |
| `!s<list>`, `!s-*`, `!s-lc` | select, reset, list; an unknown source is refused as IRRd refuses it and the selection stays |
| `!j-*`, `!j<names>` | `NAME:Y|N:first-last` per registry; the serial is §3's |
| `!i<set>` | direct members as written (a bare address gets its host length), plus mbrs-by-ref claims from the set's own source |
| `!i<set>,1` | IRRd's recursion: as-sets in as-sets; route-sets and as-sets in route-sets, an AS member expanding to its routes; an as-set following a route-set listed in it; a member with a range operator kept as an unresolved leaf; `AS-ANY` a missing set |
| `!a`, `!a4`, `!a6` | an as-set's routes' prefixes, by family, sorted and distinct |
| `!g<AS>`, `!6<AS>` | the prefixes an AS originates |
| `!r<prefix>[,o\|l\|L\|M]` | exact, one level less specific, all less specific, more specific; keys by default, text with `o` |
| `!m<class>,<key>` | the object, for the classes kept (below); IRRToolSet's legacy `an`, `ir`, `rt` accepted |
| RIPE-style (no `!`) | `-s`, `-T`, `-i origin\|member-of\|mbrs-by-ref`, `-K`, a primary key; `-r`, `-B`, `-G` accepted and ignored; IRRd's whois output and its "no entries" and error lines |

- **Classes kept.** as-set, route-set, rtr-set, filter-set, peering-set,
  aut-num, inet-rtr (the loaders set `KeepPolicy`), and route/route6 (whole
  when they claim membership; as text with `KeepRouteText`). Any other class
  — mntner, person, role, inetnum, … — and route text without
  `KeepRouteText` is refused with `F` naming what this mirror does not keep:
  a mirror that holds part of a registry must not pass the rest off as
  missing (the rule `ErrNoPolicy` follows, design §8.1). `whois.Source`
  asks `-i origin` for an AS's routes, so it needs a server run with
  `-keep-route-text`; `irrd.Source` asks `!g`/`!6` and needs no text.
- **RFC mode.** With `SnapshotOptions.RFC`, `!i…,1` and `!a` answer through
  `resolve.Expander` over the selected registries in precedence order:
  operators applied and written in RPSL notation (`192.0.2.0/24^25`),
  `AS-ANY` refused with `F`, a route-set in an as-set not followed,
  `src-members:` honoured, `SetTooLargeError` an `F` naming the limit. Every
  other command is unchanged. Each difference from IRRd mode is pinned
  (§7).
- **Errors are answers.** A malformed command, an unknown class, a bad prefix
  or AS number is IRRd's `F` with its text; `Do` returns a Go error only when
  the context ends.

## 5. Serving (`resolve/irrdserver`)

```go
type Server struct {
    Snapshot func() *irrdq.Snapshot // read once per command
    Limits   Limits
    Log      *slog.Logger // nil: no logging
}

type Limits struct {
    MaxConns    int           // concurrent connections, both ports
    IdleTimeout time.Duration // between commands
    MaxLine     int           // bytes in one command line
    MaxReply    int64         // bytes in one answer
    QueryTime   time.Duration // one command's evaluation
}

func (s *Server) ServeIRRd(ln net.Listener) error // persistent, pipelined
func (s *Server) ServeWhois(ln net.Listener) error // one query per connection
func (s *Server) Shutdown(ctx context.Context) error
```

- **Pipelining.** Commands are answered in the order they arrive, one at a
  time per connection, as IRRd does; a client may send many before reading
  (bgpq4 and `irrd.Source.Pipeline` do).
- **Limits.** Each is a flag of `rpsld` with a default: the idle timeout is
  IRRd's own default, read from IRRd's configuration documentation in the
  plan; the others are chosen in the plan and stated in `docs/rpsld.md`. A
  line over `MaxLine` is answered `F` and the connection closed; an answer
  over `MaxReply` or past `QueryTime` is `F` naming the limit, never a
  truncated answer; over `MaxConns` a new connection is closed at once.
- **Never panics.** A panic in a command is a bug; the server does not recover
  from it silently — the fuzzing (§7) is what keeps it from happening.
- **Shutdown** stops accepting and lets open connections finish their current
  command within the context's deadline.

## 6. The command (`rpsld`)

```
rpsld -source NAME=SPEC [-source NAME=SPEC …] [flags]

SPEC  dump:PATH[,PATH…]          dump files, re-read when they change
      nrtm4:URL,key=PEMFILE      an NRTMv4 mirror

-rpki FILE|https://URL   VRPs (rpki-client/Routinator JSON); -rpki-refresh (10m), -slurm FILE
-listen ADDR             IRRd protocol (default :43)
-whois-listen ADDR       one-query whois (default off)
-rfc                     RFC 2622 answers for !i…,1 and !a
-keep-route-text         Corpus.KeepRouteText
-state-dir DIR           each NRTMv4 mirror's current signing key
-max-conns, -idle-timeout, -max-line, -max-reply, -query-time, -grace (10s)
-log-queries             one log line per command
-v                       version
```

- **Order is precedence.** The `-source` flags' order is the registries'
  order (§3). The registry `RPKI`, with `-rpki`, comes last, as RADB lists it.
- **Startup.** Every input loads before the first `listen`; an input that
  fails exits with status 3, as rpslq, rpslconf and rpslcheck do. Each NRTMv4
  client starts from the key in `-state-dir` when one is saved there (so a
  rotation while the server was down still verifies) and writes
  `Status.CurrentKey` back after each sync. `Client.MaxAge` is 24 hours, as
  IRRd's limit, so a restart cannot be fed a replayed old notification file.
- **Running.** Each NRTMv4 client syncs every minute (`Client.Run`); after a
  sync that moved its version, the registry is rebuilt from the client's
  version (`CopyTo` into a fresh `Corpus`) and swapped in. A dump registry is
  re-read when any of its files' modification times change (checked every
  minute) or on SIGHUP. VRPs are re-read on `-rpki-refresh`. Each rebuild
  happens beside the live snapshot; one atomic store publishes the next
  snapshot, and answers already in progress finish on the one they read.
- **Failures after startup** keep the registry's previous data: the failure
  is logged, the registry's `!j` serial stays where it was (a client sees the
  mirror fall behind), and an NRTMv4 `Stale` notification file is logged.
  Nothing is served half-updated.
- **Logging** (`log/slog`, text, stderr): one line per load, sync, swap,
  refusal and failure, with the registry, serial and duration; queries only
  with `-log-queries`.
- **Exit status.** 0 after a clean shutdown (SIGTERM or SIGINT), 2 for a bad
  command line, 3 when an input fails at startup.

## 7. Tests

- **`irrdq` table tests** per command and flag, with every refusal and `F`
  text, in IRRd mode and RFC mode.
- **The oracles.** Random IRRs from the existing generators (as-sets and
  route-sets in two sources, mbrs-by-ref honoured and refused, range
  operators on every kind of member, cycles, `AS-ANY`, routes in both
  families, ROAs) are loaded into a `Snapshot` and into an oracle, and every
  command family is asked of both:
  - `irrtest`, in every CI run;
  - a real IRRd 4 in Docker (PostgreSQL and Redis, objects loaded with
    `irrd_load_database`), the arbiter of exact text, opt-in with
    `RPSL_IRRD_DOCKER=1` unless the plan finds a compose stack fits a CI job.
    The IRRd release is pinned by tag and named in the test.
  Answers must match byte for byte. Deliberate differences — the `F` for a
  class not kept, RFC mode's answers — are pinned in
  `resolve/testdata/rpsld/divergences.md`, each with a test, as bgpq4's and
  IRRToolSet's are.
- **Tools against the server.** bgpq4 (`-j`, `-A`, `-l`, `-S`, `-6`,
  recursing itself and letting the server expand) and `rpslq` against
  `rpsld`, against `irrtest` and over the same dump must agree; IRRToolSet's
  `peval` and `rtconfig` against `rpsld` and against `irrtest` must agree.
- **Our clients.** The expansion, filter, policy and consistency models,
  which already run over `irrd.Source` and `whois.Source` against `irrtest`,
  run against `irrdserver` too, held to the same oracles.
- **Mirroring end to end.** `nrtmtest` feeds `internal/rpsld` random
  histories (deltas, snapshots, new sessions, expiring deltas). After each
  sync the server's answers equal `irrtest`'s over the NRTMv4 server's
  database; a refused delta leaves the answers and the `!j` serial unchanged.
- **Snapshot consistency** (`-race`): clients query while registries and VRPs
  are swapped; every answer equals the old snapshot's or the new one's, never
  a mixture.
- **Hostile clients.** A line over `MaxLine`, a client idle past the timeout,
  `MaxConns` plus one, half-closed sockets, a client that pipelines without
  reading: each limit holds at exactly its value; no goroutine leaks
  (counted after shutdown).
- **Fuzzing** (43 targets): `FuzzSession` (any command lines, any order: no
  panic, every frame's length equals its payload, a reply over a limit is
  `F`) and `FuzzSourceSpec` (`-source` values: what is accepted round-trips).
- **Real data** (`RPSL_REALDATA`): RIPE's and RADB's dumps loaded as two
  registries, with and without `KeepRouteText`: load time, heap, one
  registry's rebuild time and the peak heap during a swap, measured and
  published in `docs/rpsld.md`; bgpq4 against `rpsld` equals `rpslq --dump`
  over the same dumps for the largest and a seeded sample of real sets.
- **Live** (`RPSL_LIVE`): `rpsld` mirroring RIPE over NRTMv4, compared with
  whois.ripe.net on a sample of sets; the differences are measured and
  reported as freshness, not assumed.

## 8. Docs and invariants

- `docs/rpsld.md`: running it, the `-source` forms, a systemd unit, the
  limits and their defaults, `!j` and freshness, RPKI-aware mode, RFC mode
  and its divergences, what the mirror keeps, the measured real-data costs.
- Design doc: a §8.13 for `irrdq` and `irrdserver`; §2's layout; §11's
  testing items; §12's status.
- `CLAUDE.md`: the layout lines; an engine-trap bullet (IRRd's semantics live
  in `irrdq`, never in the engine; `irrtest` stays an independent oracle; a
  class not kept is refused, never "not found"); the purity line with
  `./irrdq`; the fuzz count; an `rpsld` entry under Commands.
- README and `resolve/README.md`; CHANGELOG.
- `scripts/check.sh`: the purity step adds `./irrdq`; the new fuzz targets.
  `scripts/release.sh` builds `rpsld` as a fourth tool (20 archives).

## 9. Review Focus

1. One answer, one snapshot: no reply mixes two snapshots' data.
2. A class or route text the mirror does not keep is refused, never "not
   found".
3. IRRd mode never leaks the engine's semantics (operators, AS-ANY, route-set
   in as-set, src-members), and RFC mode changes only `!i…,1` and `!a`.
4. A failed sync or reload leaves the previous registry and its serial in
   place.
5. Every limit refuses with `F`; nothing is truncated; nothing panics.

## 10. Out of scope

- Serving NRTMv3 or NRTMv4 to downstream mirrors.
- Accepting updates (submission, authentication).
- Public-internet hardening: per-client rate limits, abuse handling.
- Classes holding personal data, and `!o` (objects by maintainer).
- IRRd 4's HTTP and GraphQL API.
- Fetching dumps (cron and `scripts/fetch-irr-dumps.sh` do).
- Multicast.

## 11. Risks

- **IRRd's exact text.** Only a real IRRd settles ordering, spacing and error
  text, and IRRd versions differ; the pinned release is the contract, and
  moving to a new one is a deliberate change with a test.
- **The Docker oracle's cost.** If it cannot run in CI, `irrtest` carries CI,
  so `irrtest` must be corrected wherever the Docker oracle finds it wrong.
- **Memory.** Every registry resident, a rebuild beside the live snapshot,
  and route text when kept. Measured on real data and published; if the peak
  during a swap is out of line, rebuilding shares unchanged parts instead.
- **NRTMv4 beyond RIPE.** RIPE is the one publisher tested live; another
  IRRd's feed is covered by `nrtmtest` alone.
