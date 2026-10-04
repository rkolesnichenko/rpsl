# An IRRd-compatible mirror server (`rpsld`)

Status: implemented in v0.24.0 · 2026-10-04

This is the design as built. The plan
(`docs/superpowers/plans/2026-10-02-rpsld-v0.24.md`) refined it in fourteen
places, and implementation changed it in more; both are folded into the
sections below, and §12 lists them, numbered as the plan, `docs/rpsld.md`
and `resolve/testdata/rpsld/divergences.md` cite them.

## 1. Summary

The library reads every IRR the way its servers do — dumps, NRTMv4 mirrors,
RPKI-aware filtering, IRRd's and whois's query protocols as a client — but
nothing in it answered a query. An operator who wants bgpq4, IRRToolSet or
`rpslq` to run against current data still queries RADB or RIPE across the
internet, under their rate limits (RADB answers about 1,200 queries a second
to one client, design §8.5) and their source selection.

This milestone adds a server: `rpsld` keeps a set of registries in memory —
from dumps, NRTMv4 mirrors and RPKI VRPs — and answers the IRRd query protocol
and RIPE-style whois queries on them, on one port, the way IRRd 4.5.3
answers, so any IRRd client works against it unchanged.

It adds a pure package that holds IRRd's query semantics (`resolve/irrdq`), a
socket package that serves them (`resolve/irrdserver`), an opt-in route-text
mode on `resolve.Corpus`, and the command `rpsld`.

### Decisions taken in brainstorming

1. **Direction:** an IRRd-compatible server, ahead of a second round of
   consistency checks, more router vendors and a set-hygiene audit.
2. **Semantics: IRRd's by default.** On the same data a client gets what IRRd
   4.5.3 answers, including where IRRd and the engine differ
   (`resolve/testdata/bgpq4/divergences.md`): a member with a range operator
   on a set or an AS number is dropped from a recursive expansion, an as-set
   follows a route-set listed in it when the expansion began at a route-set,
   `AS-ANY` is a missing set, `src-members:` is not read. `-rfc` switches
   `!i…,1` and `!a` to the engine's RFC 2622 answers.
3. **Deployment: an operator's own mirror.** Run by a network for its own
   tooling, on localhost or an internal network. It serves the routing
   classes; it has limits and never panics on hostile input, but it is not a
   public service.
4. **Data: dumps, NRTMv4 and RPKI.** Any mix of registries, NRTMv4 kept
   current every minute, dumps re-read when they change, VRPs refreshed;
   each change publishes a new immutable snapshot.
5. **Approach A: per-registry snapshots and a pure semantics layer.** Not an
   IRRd mode inside `resolve.Expander` (the engine stays RFC 2622's), and not a
   caching proxy (no fresher than its upstream).

## 2. Architecture

```
resolve.Corpus.KeepRouteText   route/route6 text kept, opt-in (new field)
resolve.ObjectText             an object's text as its registry published it (newly exported)
resolve/irrdq                  IRRd's query semantics over a Snapshot (new, pure)
resolve/irrdserver             one listener, framing on the wire, limits (new, sockets)
resolve/internal/rpsld         inputs, refresh, snapshot publishing (new)
resolve/cmd/rpsld              the command (new shim)
resolve/internal/irrdoracle    IRRd 4.5.3's recorded answers and how to compare (new, test-only)
resolve/internal/rpsldtest     a snapshot from RPSL texts, served (new, test-only)
resolve/internal/irrtest       unchanged in role: the independent oracle, corrected against IRRd
```

Imports run `internal/rpsld → irrdserver → irrdq → resolve`, with
`internal/rpsld` also using `nrtm4` and `rpki`. `resolve/irrdq` is pure: no
`net`, no goroutines of its own, context-cancellable. The purity check is
`cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq | grep -x net`
(must print nothing). Sockets live only in `irrdserver` and the existing
client backends.

`resolve/internal/irrtest` stays independent: `irrdq` never imports it and it
never imports `irrdq`, and `irrdoracle` imports neither, so it can judge both.
`irrtest` is one of the two oracles (§7); where it disagreed with a real
IRRd, IRRd decided and `irrtest` was corrected.

## 3. The snapshot (`resolve/irrdq`)

```go
// A Registry is one source's data, immutable once built.
type Registry struct { /* unexported */ }

// NewRegistry builds a Registry from a Corpus holding that one source; the
// Corpus must keep policy (KeepPolicy or IndexPeers).
func NewRegistry(name string, serial uint64, c *resolve.Corpus) (*Registry, error)
func (r *Registry) Name() string           // canonical source name
func (r *Registry) Serial() uint64         // NRTMv4 version, or a load count; 0: none
func (r *Registry) KeepsRouteText() bool
func (r *Registry) WithSerial(serial uint64) *Registry

// A Snapshot is the server's whole state for one answer: registries in
// precedence order, and the options.
type Snapshot struct { /* unexported */ }

func NewSnapshot(regs []*Registry, opts SnapshotOptions) (*Snapshot, error)
func (s *Snapshot) With(r *Registry) (*Snapshot, error) // replaces one registry by name
func (s *Snapshot) Registries() []*Registry

type SnapshotOptions struct {
    Default  []string         // the default selection (IRRd's sources_default); nil: every registry
    VRPs     *rpki.VRPs       // RPKI-aware mode: hide invalid routes
    RFC      bool             // !i…,1 and !a answered by resolve.Expander
    Expander resolve.Expander // limits and Exclude for RFC mode
    Version  string           // after "rpsld" in the !v answer
}
```

- **One registry, one index.** IRRd's rules are per source: `!s` selects
  sources, `!j` reports each one's serial, a `mbrs-by-ref` claim must come
  from the set's own source (design §8.2). A registry therefore keeps its own
  `MemSource`, its routes sorted with an exact-prefix index for `!r`, and the
  inverse indexes RIPE-style `-i` reads, built from a `Corpus` that holds that
  source alone; a change to one input rebuilds only its registry. Splitting
  input by source is the loader's job: `rpsld`'s dump loader keeps only the
  objects whose `source:` is the registry's, and an NRTMv4 client keeps only
  its database's.
- **Precedence** is the registry order, as `rpslq -S` gives it: a lookup by
  primary key answers from the first selected registry that holds the key.
- **RPKI.** With `VRPs`, the snapshot answers as IRRd 4's RPKI-aware mode
  (design §8.7): routes invalid under RFC 6811 vanish from every answer
  (`!g`, `!6`, `!a`, `!i` claimants, `!r`, `!m`, whois), a visible route's
  text gains IRRd's `rpki-ov-state:` line (a pseudo route's does not), and the registry `RPKI` holds the
  pseudo route objects. `rpsld` builds that registry from the text
  `rpki.WriteRPSL` writes, loaded by a `DumpLoader` that keeps route text, so
  the pseudo objects are served exactly as IRRd renders them. The pseudo
  registry's routes are never hidden — an AS0 VRP's included, as IRRd
  serves it. New VRPs make a new snapshot.
- **Route text (`Corpus.KeepRouteText`).** A `Corpus` keeps a route that
  claims nothing as its (prefix, origin, source) tuple only (design §8.9), so
  its text is not there to answer `!m route`, `!r` objects or whois
  `-i origin`. `KeepRouteText`, set before the first `Put`, keeps each route
  and route6 as text as well (source interned, as `KeepPolicy` keeps
  aut-nums), under the same identity `Delete` and NRTM replacement use;
  `Corpus.Routes` yields every route with its text, and `Corpus.Whole` the
  objects kept whole. Without it those queries are refused (§4), never
  answered as "not found". Its cost is measured (§7) and published.
- **Object text** is served as the registry published it (`resolve.ObjectText`:
  from the first attribute line to the last, without the blank, comment and
  malformed lines a dump stream attaches around the object), not
  re-rendered as IRRd renders it (names lower-cased, values padded to
  column 16, lists rejoined with commas, bare addresses given their length).

## 4. Queries (`resolve/irrdq`)

```go
// A Session is one client connection's state.
type Session struct { /* selected sources, persistent mode, timeout */ }

func NewSession(snapshot func() *Snapshot) *Session

// Do answers one command line. The snapshot is read once per call, so one
// answer comes from one snapshot.
func (s *Session) Do(ctx context.Context, line string) (Reply, error)
func (s *Session) Timeout() time.Duration // what !t set, or 0

// A Reply is what the server writes: an IRRd frame (A<len>…C, C, D, E,
// F <message>) or whois text, and whether the connection closes after it.
type Reply struct { /* … */ }
func (r Reply) WriteTo(w io.Writer) (int64, error)
func (r Reply) Close() bool
func (r Reply) Len() int
func (r Reply) Refused(msg string) Reply // F msg in r's place, keeping r's close
func Fail(msg string) Reply
```

Every command answers byte for byte as IRRd 4.5.3 does on the same data
(§7): its `D`/`F` choice, error text and spacing. Where IRRd answers in hash
order (`!g`, `!6`, `!a`) or database order (multi-object answers), `rpsld`
sorts — prefixes IPv4 first, by address, then length — so its answers are
deterministic. A line starting with `!` is an IRRd command; any other is a
RIPE-style query, on the same port, as IRRd 4 serves both.

| Command | Answer |
| --- | --- |
| `!!` | persistent mode; without it a connection closes after one answer |
| `!q` | close; `q` alone is a RIPE-style query, as in IRRd 4.5.3 |
| `!v` | `IRRd -- version 4.5.3 (rpsld <version>)`: clients detect IRRd 4 by the prefix (bgpq4 decides on `!a` by it), IRRToolSet needs the word "version", and the parenthesis says what answers |
| `!n<name>`, `!t<seconds>` | accepted; `!t` sets the connection's idle timeout, 1-1000 s, as IRRd's |
| `!s<list>`, `!s-lc`, `!s-*` | select (split at commas only), list; `!s-*` answers `C` and changes nothing, as IRRd 4.5.3; an unknown source is refused as IRRd refuses it and the selection stays |
| `!j-*`, `!j<names>` | `NAME:N:0-<serial>` per registry (`NAME:N:-` for serial 0), then `NAME:X:Database unknown` per unknown name |
| `!i<set>` | direct members, normalized as IRRd stores them (an AS number asplain, a prefix canonical, a bare address with its host length, an operator kept as written), plus mbrs-by-ref claims from the set's own source; the parameter itself, as sent (case-sensitive), removed |
| `!i<set>,1` | IRRd's `_recursive_set_resolve`: from an as-set, as-sets only; from a route-set, route-sets and as-sets, an AS member expanding to its routes, a prefix member kept with its operator — so an as-set follows a route-set listed in it only under a route-set root; a member with an operator on a set or AS number looked up as a set name, found nowhere and dropped; a missing set, a set of another class and `AS-ANY` dropped |
| `!a`, `!a4`, `!a6` | an as-set's routes' prefixes, by family, sorted and distinct |
| `!g<AS>`, `!6<AS>` | the prefixes an AS originates, sorted |
| `!r<prefix>[,o\|l\|L\|M]` | route *objects* by default; origins with `o` (one per object); `l` the most specific route strictly less specific (sized across every selected registry), `L` every less specific and the exact one, `M` every more specific |
| `!m<class>,<key>` | the object, for the classes kept (below), matched by its canonical primary key only; IRRToolSet's legacy `an`, `ir`, `rt` accepted, which IRRd 4.5.3 answers `D` |
| `-V <agent> !<command>` | the IRRd command, the user agent dropped (IRRd's handle_query) |
| RIPE-style (no `!`) | the line split at spaces and read left to right, flags whole words (`-rK` is no flag): `-s` (selecting for the rest of the connection, as IRRd's does), `-T` (for the next search only), `-i origin\|member-of\|mbrs-by-ref\|members\|mp-members`, `-x`, `-l`, `-L`, `-M`, `-K`, `-k`; `-r`, `-F`, `-V <agent>` accepted and ignored; a key; IRRd's whois output and its "no entries" and error lines. `-B`, `-G` and any unknown flag are IRRd's `Unrecognised flag/search`, as IRRd 4.5.3 answers them |

- **Classes kept.** as-set, route-set, rtr-set, filter-set, peering-set,
  aut-num, inet-rtr (the loaders set `KeepPolicy`), and route/route6 (whole
  when they claim membership; as text with `KeepRouteText`). What the mirror
  does not keep is refused, never answered "not found" — a mirror that holds
  part of a registry must not pass the rest off as missing (the rule
  `ErrNoPolicy` follows, design §8.1):
  - `!m` of a class `object.RIPE` or `object.IRRd` lists but the mirror does
    not keep: `F Class <c> is not kept by this mirror`; `-T` naming one:
    `%% ERROR: Class <c> is not kept by this mirror`. A class neither lists
    stays IRRd's answer (`D`; `-T foo` gives "No entries").
  - `-i` on `mnt-by`, `admin-c`, `tech-c`, `zone-c`, `person` or `role`, and
    `!o<mntner>` (IRRd's twin of `-i mnt-by`): `Inverse search on <attr> is
    not served by this mirror: it keeps the routing classes only`.
  - A plain lookup — a key with no `-T`, or a `-T` naming a class not kept —
    is refused: `%% ERROR: This mirror keeps only the routing classes, so it
    cannot answer a lookup of <key> whole; ask with -T and any of <the kept
    classes>`. IRRd's `text_search` answers an AS number with the as-blocks
    covering it too, a prefix with inetnums and inet6nums, and any other key
    with persons and roles whose name holds it; any mirror answer would be
    partial and a "No entries" possibly false. With a `-T` naming only kept
    classes it is answered whole, from every selected registry: an aut-num,
    the routes of a prefix and every less specific one, a set, a route by
    `<prefix><origin>`, an inet-rtr. `whois.Source` always sends `-T`.
  - Route text without `KeepRouteText` — `!r` without `o`, `!m route`,
    `-i origin`, route searches and prefix lookups:
    `F Route text is not kept by this mirror (rpsld -keep-route-text)`
    (RIPE-style: `%% ERROR: …`). `whois.Source` asks `-i origin` for an
    AS's routes, so it needs a server run with `-keep-route-text`;
    `irrd.Source` asks `!g`/`!6` and needs no text.
- **Not served**, though IRRd answers them: `!e`, `!J`, `!fno-rpki-filter`,
  `!fno-scope-filter`, `!fno-route-preference-filter` (`F Command !<c> is not
  served by this mirror`), and RIPE-style `-a`, `-t`, `-q`, `-g`
  (`%% ERROR: Flag -<f> is not served by this mirror`).
- **Invalid members.** IRRd's import refuses a whole set when one
  `members:`/`mp-members:` item fails to parse (or a route-set's `members:`
  holds IPv6). `rpsld` does not emulate IRRd's import validation: it serves
  every object the library parses, its valid items normalized and an item it
  cannot read as written, upper-cased.
- **RFC mode.** With `SnapshotOptions.RFC`, `!i…,1` and `!a` answer through
  `resolve.Expander` over the selected registries in precedence order (a
  scoped reference looked up in its registry whether selected or not):
  operators applied and written in RPSL notation (`192.0.2.0/24^25`),
  `AS-ANY`/`RS-ANY` refused with `F`, a route-set in an as-set not followed,
  `src-members:` honoured, `SetTooLargeError` an `F` naming the limit. The
  registries are filtered with the same visibility rule as IRRd mode, not
  wrapped in `rpki.Filter` (which would hide the AS0 pseudo route IRRd
  serves), and the Expander runs with `Concurrency` 0: the registries are in
  memory, and an answer starts no goroutines. Every other command is
  unchanged. Each difference from IRRd mode is pinned (§7).
- **Errors are answers.** A malformed command, an unknown class, a bad prefix
  or AS number is IRRd's `F` with its text, and a Source's error is IRRd's
  `F An internal error occurred while processing this query.`; `Do` returns
  a Go error only when the context ends.

## 5. Serving (`resolve/irrdserver`)

```go
type Server struct {
    Snapshot   func() *irrdq.Snapshot // read once per command
    Limits     Limits
    Log        *slog.Logger // nil: no logging
    LogQueries bool         // one log line per command
}

type Limits struct {
    MaxConns    int           // concurrent connections; default 256
    IdleTimeout time.Duration // between commands, and per 64 KiB written; default 30s
    MaxLine     int           // bytes in one command line; default 1 MiB
    MaxReply    int64         // bytes in one answer; default 256 MiB
    QueryTime   time.Duration // one command's evaluation; default 60s
}

func (s *Server) Serve(ln net.Listener) error // IRRd and RIPE-style, one port
func (s *Server) Shutdown(ctx context.Context) error
var ErrServerClosed error
```

- **One listener.** IRRd 4 has no separate whois port: a line starting with
  `!` is an IRRd command, any other a RIPE-style query. There is no
  `ServeWhois` and no `-whois-listen`.
- **Pipelining.** Commands are answered in the order they arrive, one at a
  time per connection, as IRRd does; a client may send many before reading
  (bgpq4 and `irrd.Source.Pipeline` do). Answers are flushed when no further
  command is already buffered.
- **Limits.** Each is a flag of `rpsld`. The idle timeout is IRRd's
  (`SOCKET_DEFAULT_TIMEOUT`, 30 s, measured at 30.03 s), and `!t` overrides it
  per connection; the other four are `rpsld`'s own. A line over `MaxLine` is
  answered `F Line too long: over <MaxLine> bytes` and the connection closed,
  as soon as more than that many bytes have arrived; an answer over `MaxReply` is
  `F Answer larger than <MaxReply> bytes` and a command past `QueryTime`
  `F Query took longer than <QueryTime>`, both keeping the connection, never
  a truncated answer; over `MaxConns` a new connection is closed at once,
  unanswered. IRRd 4.5.3 queues a connection past its `max_connections` (10)
  and has no line limit (a 1 MB line was answered). The server hands
  `MaxReply` to each session (`irrdq.Session.SetMaxReply`), and the text of
  an answer that grows with the data — route objects, lists of origins,
  prefixes or members, RIPE-style objects and `-K` blocks — stops being
  built as soon as it passes it, so a far larger answer's text costs a
  connection a small multiple of `MaxReply`, not its own size; a route's
  text is held by reference and copied once, into the reply. The list some
  answers are made from — a set's members or expansion (`!i`, `!i…,1`,
  `!a`), an AS's prefixes (`!g`, `!6`), an inverse search's objects — is
  gathered whole first, bounded by the registry rather than by `MaxReply`.
- **Writing.** An answer is written in 64 KiB pieces, each with its own write
  deadline of one idle timeout, so the timeout bounds how long the client
  takes to read a piece, not the whole answer. A client that reads just fast
  enough can therefore hold a connection one idle timeout per piece (a
  256 MiB answer is 4,096 pieces); only `MaxConns` bounds how many do.
- **Never panics.** A panic in a command is a bug: the connection's goroutine
  logs it with its stack and closes that connection, and the fuzzing (§7) is
  what keeps it from happening.
- **Shutdown** stops accepting, lets each connection finish the command it
  is answering, writes out every answer completed so far, whole, and closes
  the connections gently (it closes its write side and drains what the
  client still sends, up to a second, so unread input does not reset the
  connection and lose the answers). At the context's end it gives up: a
  command still running is abandoned unanswered (not refused), and an answer
  being written then may be cut short.

## 6. The command (`rpsld`)

```
rpsld -source NAME=SPEC [-source NAME=SPEC …] [flags]

SPEC  dump:FILE[,FILE…]          dump files (gzip or plain), re-read when they change or on SIGHUP
      nrtm4:URL,key=PEMFILE      an NRTMv4 mirror (https:// or file://)

-rpki FILE|https://URL   VRPs (rpki-client/Routinator JSON); -rpki-refresh (1h), -slurm FILE
-rpki-default            the RPKI registry in the default selection, last (default true)
-listen ADDR             IRRd and RIPE-style queries (default :43)
-rfc                     RFC 2622 answers for !i…,1 and !a
-keep-route-text         Corpus.KeepRouteText
-state-dir DIR           each NRTMv4 mirror's current signing key
-check-dumps (1m)        how often dump files' modification times are checked
-nrtm-interval (1m)      how often each NRTMv4 mirror polls; at least a minute
-max-conns, -idle-timeout, -max-line, -max-reply, -query-time, -grace (10s)
-log-queries             one log line per command
-v                       version
```

- **Order is precedence.** The `-source` flags' order is the registries'
  order (§3). The registry `RPKI`, with `-rpki`, comes last, as RADB lists it;
  `-rpki-default=false` leaves it out of the default selection, as IRRd's
  own `sources_default` (and the goldens' IRRd) does. A file name or URL in
  a `-source` may not hold a comma, and `RPKI` is no `-source` name.
- **Startup.** Every input loads before the first `listen`; an input that
  fails exits with status 3, as rpslq, rpslconf and rpslcheck do — a refused
  delta in the startup sync included. Each NRTMv4 client starts from the key
  in `-state-dir` when one is saved there (so a rotation while the server was
  down still verifies; a saved key that cannot be read stops the start), and
  the key is written back, through a synced temporary file and a rename,
  whenever it changes (a save that fails is tried again after the next
  sync). `Client.MaxAge` is 24 hours, as IRRd's limit, so a
  restart cannot be fed a replayed old notification file. A dump registry
  keeps only the objects of its own source, counting the others in its log
  line.
- **Running.** Each NRTMv4 mirror has `rpsld`'s own sync loop, not
  `Client.Run`: it calls `Client.Sync` every `-nrtm-interval` (never under a
  minute, NRTMv4 §5.2: a smaller value exits 2), and after failed syncs in a
  row backs off: twice the interval after the first, doubling with each
  further one, up to a fixed ceiling of an hour (never below the interval),
  starting again from the interval after a success. `Client.Sync` loads the
  whole snapshot again after three failed deltas, so a ceiling at the
  interval would fetch RIPE's 400 MB every few minutes for as long as a
  delta is refused. Whenever the client holds another (session,
  version) than the one last published — also after a rebuild that failed,
  which the next sync retries — the registry is rebuilt from the client's
  version (`CopyTo` into a fresh `Corpus`) and swapped in. A dump registry is
  re-read when any of its files' modification times change (checked every
  `-check-dumps`) or on SIGHUP, which reaches every dump registry; a read
  that fails is tried again at the next change or SIGHUP, not at every
  check. A dump is replaced atomically (written elsewhere, then renamed into
  place): a plain file half written reads without error. VRPs are re-read
  every `-rpki-refresh` (an hour, IRRd's `roa_import_timer` default; a
  download over 512 MB is refused). Each rebuild happens beside the live
  snapshot; one atomic store publishes the next snapshot, and answers
  already in progress finish on the one they read.
- **Serials.** An NRTMv4 registry's serial is its version; a dump
  registry's is its load count (1, then one more per reload); `RPKI`'s
  likewise counts its loads.
- **Failures after startup** keep the registry's previous data: the failure
  is logged, the registry's `!j` serial stays where it was (a client sees the
  mirror fall behind), and an NRTMv4 `Stale` notification file is logged.
  Nothing is served half-updated.
- **Logging** (`log/slog`, text, stderr): one line per load, sync, swap,
  reload, refusal and failure, with the registry, serial and duration;
  queries only with `-log-queries`.
- **Exit status.** 0 after a clean shutdown (SIGTERM or SIGINT, or one asked
  for during startup; a second signal during `-grace` ends the process at
  once, by Go's default handling) and for `-v`; 2 for a bad command line (and `-help`);
  3 when an input fails at startup, the port cannot be opened, or serving
  fails (`Serve` returning an error cancels the refreshers and exits 3,
  rather than hanging or exiting 0).

## 7. Tests

- **`irrdq` table tests** per command and flag, with every refusal and `F`
  text, in IRRd mode and RFC mode.
- **The recorded oracle.** IRRd's loader rejects a whole file on one object
  it refuses, and the random generators write RPSL only this library
  accepts, so the Docker oracle checks a fixed fixture
  (`resolve/testdata/irrd`: RIPE and RADB, a set for each corner case, ROAs),
  recorded once: IRRd 4.5.3 in Docker (PostgreSQL and Redis, objects loaded
  with `irrd_load_database`), pinned by version in the Dockerfile and named
  in the test, answers 247 exchanges in plain and RPKI-aware mode, checked
  in as `golden/plain.txt` and `golden/rpki.txt`. `RPSL_IRRD_DOCKER=1 go test
  -run TestRecord ./internal/irrdoracle` re-records them (a case is asked
  until two answers agree, since IRRd now and then answers a fresh
  connection empty); every other run, CI's included, replays them without
  Docker. Answers compare byte for byte (`Exact`), as multisets where IRRd's
  order is a hash's or the database's (`Words`, `Objects`), and object text
  after `irrdoracle.Normalize` applies IRRd's re-rendering to both sides; the
  reply's envelope (status line, frame length, terminator) always byte for
  byte.
- **`irrtest`**, corrected against those recordings (`TestMatchesIRRd`), is
  the oracle for random IRRs (as-sets and route-sets in two sources,
  mbrs-by-ref honoured and refused, range operators on every kind of member,
  cycles, `AS-ANY`, routes in both families, ROAs): `TestIRRdqMatchesIrrtest`
  asks both every command family. Deliberate differences — the `F` for what
  is not kept, `!v`, the legacy classes, RFC mode's answers, the server's
  limits — are pinned in `irrdq`'s `diverges` and `irrdserver`'s tests and
  listed in `resolve/testdata/rpsld/divergences.md`, each with a test
  (`TestDivergencesDocumented` checks both directions).
- **Tools against the server.** bgpq4 (recursing itself and letting the
  server expand) and `rpslq` (with and without `--server-expand`) against
  `rpsld` and against `irrtest` must agree; IRRToolSet's `peval` and
  `rtconfig` against `rpsld` and against `irrtest` must agree.
- **Our clients.** The expansion, RPKI, policy and consistency models, which
  already ran over `irrd.Source` and `whois.Source` against `irrtest`, run
  against `irrdserver` too, held to the same oracles.
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
- **Real data** (`RPSL_REALDATA`), one registry per process
  (`TestRealDataServe`): RIPE's and RADB's dumps each loaded and reloaded,
  with and without `KeepRouteText` — load time, heap, the rebuild's time and
  the highest heap during it — published in `docs/rpsld.md`. Loading both
  registries in one process was not measured: projected from the
  per-registry runs, it would pass the memory the measuring machine could
  spare. bgpq4 against `rpsld` equals `rpslq --dump` over the same RIPE dumps
  for the largest and a seeded sample of real sets
  (`TestRpsldMatchesRpslqRealData`); bgpq4 against `irrtest` is not run on
  real data (holding RIPE as text in `irrtest` doubles the memory, and the
  random tests cover `rpsld` against `irrtest`).
- **Live** (`RPSL_LIVE_NRTM=1`, with `RPSL_REALDATA` for the set list):
  `rpsld` mirroring RIPE over NRTMv4, compared with whois.ripe.net on the 20
  largest RIPE as-sets' direct members (`TestLiveMirror`); a difference is
  freshness and is logged, a set one side lacks fails.

## 8. Docs and invariants

- `docs/rpsld.md`: running it, the `-source` forms, a systemd unit, the
  limits and their defaults, `!j` and freshness, RPKI-aware mode, RFC mode
  and its divergences, what the mirror keeps and refuses, the measured
  real-data costs, exit statuses.
- Design doc: §8.13 for `irrdq`, `irrdserver` and `rpsld`; §2's layout;
  §11's testing items; §12's status.
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
5. The line, answer and query-time limits refuse with `F`; past `MaxConns`
   or the idle timeout the connection is closed; nothing is truncated;
   nothing panics.

## 10. Out of scope

- Serving NRTMv3 or NRTMv4 to downstream mirrors.
- Accepting updates (submission, authentication).
- Public-internet hardening: per-client rate limits, abuse handling.
- Classes holding personal data, and `!o` (objects by maintainer).
- IRRd 4's HTTP and GraphQL API.
- Fetching dumps (cron and `scripts/fetch-irr-dumps.sh` do).
- Multicast.
- IRRd's import validation (§4, invalid members), and the commands listed
  as not served in §4.

## 11. Risks

- **IRRd's exact text.** Only a real IRRd settles ordering, spacing and error
  text, and IRRd versions differ; the pinned release (4.5.3) is the
  contract, and moving to a new one is a deliberate change with a test.
- **The Docker oracle's cost.** It does not run in CI, so `irrtest` carries
  CI, and `irrtest` is corrected wherever the recordings find it wrong.
- **Memory.** Every registry resident, a rebuild beside the live snapshot,
  and route text when kept. Measured per registry on real data and
  published (`docs/rpsld.md`); the highest heap during a rebuild, garbage
  included, was 3.2 to 3.8 times one registry's heap after load. An NRTMv4
  mirror holds its version more than once (the client's `Corpus`, its
  published `MemSource`, the registry built from `CopyTo`); how much of the
  live mirror's heap is that duplication was not measured.
- **NRTMv4 beyond RIPE.** RIPE is the one publisher tested live; another
  IRRd's feed is covered by `nrtmtest` alone.

## 12. Refinements

Each is folded into the section named; the numbers are the plan's, and
`docs/rpsld.md` and `resolve/testdata/rpsld/divergences.md` cite them.

1. The Docker oracle records a fixed fixture once; random IRRs are held to
   `irrtest`, corrected against the recordings (§7).
2. IRRd's unordered answers are compared as multisets; `rpsld` sorts them
   (§4, §7).
3. Object text is served as loaded, not re-rendered as IRRd renders it — the
   user's decision of 2026-10-02 (§3, §7).
4. One listener for IRRd and RIPE-style queries, as IRRd 4 has; no
   `ServeWhois`, no `-whois-listen` (§5).
5. `!v` answers `IRRd -- version 4.5.3 (rpsld <version>)` (§4).
6. `!j` answers `NAME:N:0-<serial>`, `NAME:N:-` for serial 0 (§4).
7. `!s-*` changes nothing and `q` is a query, as in IRRd 4.5.3 (§4).
8. `!g`, `!6`, `!a` sorted IPv4 first, by address, then length (§4).
9. `!r` answers objects by default and origins with `o`; objects need route
   text (§4).
10. The RIPE-style flags served, and the IRRd commands and flags not served
    (§4). As built, `!o` is refused with the `-i mnt-by` answer (11), and
    the `!f` switches and `-g` are among those not served.
11. What the mirror does not keep is refused, with the exact texts (§4). As
    built, the plain-lookup rule is the one ruled in Task 6's review: a key
    without `-T`, or with a `-T` naming a class not kept, is refused
    whatever the key, not only a key the mirror holds no object for.
12. `!m` accepts IRRToolSet's legacy class names (§4).
13. The limits' defaults; IRRd queues past its connection limit and has no
    line limit (§5).
14. `-rpki-default`, `-check-dumps`, `-nrtm-interval` (§6).
15. **What implementation changed without a plan refinement**, each folded
    where named:
    - `!i…,1` as IRRd 4.5.3 actually does it, from the recordings: a member
      with a range operator on a set or an AS number is dropped, not kept as
      an unresolved leaf; a route-set listed in an as-set is followed only
      under a route-set root; a missing set, a set of another class and
      `AS-ANY` are dropped (§1, §4). `!i` removes the set's own name as sent
      (§4).
    - Invalid members are served as written, where IRRd's import refuses the
      whole object — a divergence (§4).
    - `-V <agent> !<command>` runs the IRRd command (§4).
    - `Registry` is read through accessors (`Name`, `Serial`,
      `KeepsRouteText`), `WithSerial` re-serials one, `Snapshot.With` returns
      an error, and `SnapshotOptions` gains `Default` and `Version` (§3).
    - The `RPKI` registry is built from `rpki.WriteRPSL`'s text through a
      `DumpLoader`, not from `rpki.AddTo` (§3).
    - RFC mode filters with `irrdq`'s own visibility rule, not `rpki.Filter`,
      and runs the Expander with `Concurrency` 0 (§4).
    - `rpsld` runs its own NRTMv4 sync loop, not `Client.Run`, with a
      one-minute floor on `-nrtm-interval` (exit 2 below it) and
      `Client.Run`'s backoff; a delta refused during the startup sync exits
      3; serving that fails exits 3; SIGHUP reloads every dump registry; a
      dump registry keeps only its own source's objects (§6).
    - `irrdserver`'s `Shutdown` writes out every completed answer whole and
      abandons, rather than refuses, a command still running at its
      deadline; a slow reader can hold a connection one idle timeout per
      64 KiB, bounded only by `MaxConns`; a panic is logged and closes its
      connection (§5).
    - `!t` is not capped by the server's idle timeout: it sets the
      connection's timeout, 1-1000 s, as IRRd's does (§4, §5).
    - `resolve.ObjectText` is exported (it drops trailing trivia too, and
      reads continuation lines as the lexer does) (§3). `irrd.Source`
      restores a scoped set's reference to its own name, which IRRd's `!i`
      drops, from the object (`!m`); `irrd.Source.ASSetPrefixes` asks `!m`
      on a `D` answer to tell a missing as-set from one whose members
      originate nothing. `rpslq.RunWith` (internal, dumps only) runs rpslq
      over a backend its caller opened once, for the real-data comparison.
    - `irrtest` was corrected against IRRd 4.5.3: rtconfig's D2 is re-pinned
      as the loss of the operator member (IRRd drops it, so IRRToolSet's
      `0.0.0.0/0` came from the old `irrtest`), and bgpq4's `source-cycle`
      is re-pinned to what bgpq4 does against a faithful IRRd.
    - Real data is measured one registry per process; the combined
      RIPE-and-RADB process, and bgpq4 against `irrtest` on real data, were
      not run, for memory (§7).
