# rpsl/resolve

`import "github.com/rkolesnichenko/rpsl/resolve"`

The set-expansion engine: it expands set references into concrete
ASNs and prefixes by traversing a graph of objects it must *fetch*. This is the
feature nobody else ships in Go.

The engine is **pure** — no global state, no implicit network, context-cancellable,
all limits explicit. Every I/O boundary goes through the injected `Source`, so the
same engine runs against an in-memory corpus in tests and a live IRR/RDAP backend
in production. (Core `resolve` imports only `net/netip`, never `net`;
`go list -deps .` excludes `net`. Sockets live exclusively in the sub-packages.)

## The `Source` interface

```go
type Source interface {
	GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error)
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)
	MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error)
}
```

`GetSet` takes a `types.SetRef`: unscoped (`types.Ref(name)`) is resolved by the
`Source`'s precedence, scoped (`RIPE::AS-FOO`, draft-ietf-grow-rpsl-registry-scoped-members)
only in that registry, and a registry the `Source` does not know is `ErrNotFound`.
It returns `ErrNotFound` for a missing set: a missing *nested* set expands to
nothing and is listed by the result's `Missing()` (`[]types.SetRef`), while a missing
top-level set is an error. `MembersByRef` backs the indirect `mbrs-by-ref` membership
mechanism; implementations should filter with `resolve.ClaimAllowed(obj, set)`, and the
engine re-checks every returned claim anyway. `NewMemSource(objs, "RIPE", "RADB")` takes
an optional source precedence for set names defined in several IRRs.

`PolicySource` is a sibling interface — `Source` plus `AutNum(ctx, as, source)` and
`InetRtr(ctx, name, source)` — for the objects routing policy names outside sets, with
the same registry scoping as `GetSet`. `MemSource`, `irrd.Source`, `whois.Source`,
`Cache` and `rpki.Filter` implement it; `Corpus.KeepPolicy` (and `DumpLoader`'s and
`nrtm4.Client`'s) feeds a `MemSource` built from a `Corpus`, and one built without it
returns `ErrNoPolicy` rather than the few aut-nums and inet-rtrs it keeps as claimants.
A wrapper (`Cache`, `rpki.Filter`) over a `Source` that is not a `PolicySource` returns
`ErrNoPolicy` too.

## The `Expander`

```go
type Expander struct {
	Src         Source
	MaxDepth    int       // cap on shortest nesting distance from the top (default 32)
	MaxPrefixes int       // cap on output prefixes, or ranges (default 1<<20)
	MaxVisited  int       // cap on distinct sets fetched (default 1<<17)
	AFI         types.AFI // address-family constraint; Unspecified/Any = both
}

func (e *Expander) ExpandAS(ctx context.Context, ref types.SetRef) (ASNSet, error)
func (e *Expander) ExpandPrefixes(ctx context.Context, ref types.SetRef) (PrefixSet, error)
func (e *Expander) ExpandPrefixRanges(ctx context.Context, ref types.SetRef) (RangeSet, error)
func (e *Expander) ExpandRouters(ctx context.Context, ref types.SetRef) (RouterSet, error)
func (e *Expander) ExpandPeerings(ctx context.Context, ref types.SetRef) (PeeringSet, error)
func (e *Expander) ExpandFilterSet(ctx context.Context, ref types.SetRef) (RangeSet, error)
func (e *Expander) EvalFilter(ctx context.Context, f policy.Filter) (RangeSet, error)
```

Every `Expand*` call takes a `types.SetRef`; an unscoped caller writes
`types.Ref(name)`. A scoped top ref is bgpq4's `SOURCE::SET`: it looks the set
up in that one registry, and the scope does not cascade to what it nests.
`EvalFilter` is unchanged — a set reference inside a filter has no registry
syntax, so it is always unscoped.

`ASNSet`/`PrefixSet`/`RangeSet` are deduplicated sets with `Has`, `Len`, a sorted
`List`, and `Missing` (nested sets that were referenced but not found).
`ExpandPrefixRanges` returns ranges before materialization — bgpq4's `le`/`ge`
form — which is the only usable form for sets containing ranges like `/8^+`.

### Engine semantics

- **Two phases** — discovery walks the set graph breadth-first, fetching each set
  once, so a set's depth is its shortest nesting distance and the result never
  depends on member order; evaluation then builds the result without further I/O.
  Each AS's routes are fetched once per call.
- **Cycle detection** — a revisit is *skipped, not an error* (matches `bgpq4`).
  Evaluation walks each (set, operator stack) pair once, with stacks compared by
  what they do (`^+^+` is `^+`), so a cycle through range operators (`RS-A`
  lists `RS-B^+`, `RS-B` lists `RS-A`) resolves to the RFC's fixpoint.
- **Range operators on members** — `RS-FOO^+` and `AS1^24` apply to every range of
  the set or route of the AS, composing along the path (RFC 2622 §5.2).
- **Dual membership** — direct `members:`/`mp-members:` unioned with indirect
  `member-of:` claims, the latter honored only via `mbrs-by-ref:` + the mntner
  check, and only from the set's own `source:` (maintainer names are unique per
  registry, and IRRd applies the same rule). Skipping either check is a silent,
  hijack-relevant bug, so the engine re-applies `ClaimAllowed` to every claim.
- **Class rules** — an as-set is followed only into as-sets, a route-set into
  route-sets and as-sets (RFC 2622 §5.1-5.2), an rtr-set into rtr-sets, a
  peering-set into peering-sets, a filter-set into filter-sets; a route-set
  inside an as-set is not followed. `ExpandAS` takes an as-set, the prefix expansions an as-set or
  route-set; anything else returns `ErrSetClass`. Ranges come back in canonical
  form, so equivalent spellings count once.
- **Fan-out guards** — `MaxPrefixes` is checked *during* enumeration (duplicates
  are free), `MaxVisited` bounds the sets fetched, and `MaxDepth` bounds nesting;
  each returns a `*SetTooLargeError{Name, Limit, Max, Count}` naming the cap rather than
  OOM-ing or truncating silently. `AS-ANY`/`RS-ANY` return `AnySetError`.
- **AFI constraint** — `AFIv4` drops IPv6 members and vice versa; `any`/unspecified
  keeps both.

## In-memory expansion

`NewMemSource` indexes a decoded corpus — the backend for tests and for callers
that have loaded an IRRd snapshot or `.db` dump into memory.

```go
src := resolve.NewMemSource([]object.Object{
	decodeObject("as-set: AS-CONE\nmembers: AS1\nmembers: AS2\nsource: TEST\n"),
	decodeObject("route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"),
	decodeObject("route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n"),
})

e := &resolve.Expander{Src: src, AFI: types.AFIv4}
name, _ := types.ParseSetName("AS-CONE")

asns, _ := e.ExpandAS(context.Background(), types.Ref(name))        // [AS1 AS2]
prefixes, _ := e.ExpandPrefixes(context.Background(), types.Ref(name)) // 10.0.0.0/8, 192.0.2.0/24
```

This is copied from a runnable `Example` test
([`example_test.go`](example_test.go)).

## Live backends

Swap the `Source` to resolve against a real registry; the `Expander` code is
unchanged.

| Sub-package | Talks to | Membership handling |
| --- | --- | --- |
| `resolve/irrd` | IRRd query port (`whois.radb.net:43`, NTT, …) via `!i`/`!g`/`!6` | server-side; `MembersByRef` is a no-op (already folded into `!i`) |
| `resolve/whois` | plain WHOIS (`whois.ripe.net:43`, or an IRRd server such as `whois.radb.net:43`) | resolves indirect membership itself via inverse queries + `ClaimAllowed` (mntner and same-source check) |
| `resolve/rdap` | RDAP registration metadata (`rdap.db.ripe.net`) | registration lookups only — not a `Source` (RDAP has no IRR set objects) |

```go
import "github.com/rkolesnichenko/rpsl/resolve/irrd"

irr := &irrd.Source{
	Addr:      "whois.radb.net:43",
	Sources:   []string{"RADB", "RIPE"},
	Timeout:   10 * time.Second,
	KeepAlive: true, // pool persistent connections; call Close() when done
}
defer irr.Close()

e := &resolve.Expander{Src: irr, AFI: types.AFIv4}
asns, err := e.ExpandAS(ctx, types.Ref(name))
```

Every `irrd` and `whois` query honours its context: cancelling it (or its deadline
passing) aborts a pending read at once, and `Timeout` (default `DefaultTimeout`,
60 s; negative = none) bounds each query even under `context.Background()` —
one deadline covering the wait for a `MaxConns` slot, the dial, the I/O and any
retry. `rdap.Client.Timeout` bounds each RDAP request the same way.
`irrd.MaxConns` (default 4) bounds concurrent connections; with `KeepAlive`, a
pooled connection the server has closed is retried once on a fresh one, and a
refused `!s` source list is an error rather than "not found". For scoped lookups
`irrd` learns the server's registries once, with IRRd's `!j-*`, and kept until
`Close`: a registry not listed is `ErrNotFound` without a query, so data naming
any number of made-up registries costs nothing more (a server that refuses `!j`,
or hangs up on it twice in a row, is asked per registry, with up to 1,024
refusals remembered). IRRd lists its real sources, not the aliases it may also
accept in `!s`, so a scoped lookup of an alias is `ErrNotFound`: scope by the
registry's own name, the one an object's `source:` gives. IRRd answers
`!i` for an existing set with no members as for a missing one, so `irrd`
confirms with `!m` and returns such a set empty (not in `Missing()`). Like
`irrd`, `whois` takes a set defined in several sources from the first in
`Sources`. A whois server
error other than "no entries" is returned as `whois.ServerError` (e.g. RIPE's
`%ERROR:201` rate limiting, or IRRd's `%% ERROR:` for an unknown source), never
as an empty result.

Without `KeepAlive`, `irrd` still sends `!!` first on every connection: IRRd
closes a connection after one command otherwise, and the `!s` source selection
would consume it.

The `irrd` and `whois` sources accept a `Dial func(ctx) (net.Conn, error)` hook,
which the test suite uses to drive in-process fake servers without real network.
The fakes model IRRd's one-command-without-`!!` behaviour. `RPSL_LIVE=1 go test
-run TestLiveSmoke .` checks all three backends read-only against RADB, RIPE
whois and RIPE RDAP.

## Correctness

Every `go test` expands thousands of random IRRs — nested and cyclic sets in
two sources, range operators, indirect members honored and rejected, missing
sets — with the engine and with a brute-force model of RFC 2622, through
`MemSource`, `irrd.Source` and `whois.Source` (served by the in-process IRRd in
`internal/irrtest`), and requires the same AS numbers, prefixes and `Missing()`.

When `bgpq4` is installed, `bgpq4` itself expands the same random IRRs through
`irrtest`, and the golden expansions of the snapshot in `testdata/` are its
output. The engine and bgpq4 agree everywhere except the cases pinned in
[`testdata/bgpq4/divergences.md`](testdata/bgpq4/divergences.md). On the RIPE
dumps (`RPSL_REALDATA`), 304 of 305 sampled sets that fit `MaxPrefixes` expand
exactly as bgpq4 expands them; the other uses `^n`, which bgpq4 drops.

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/resolve).

## Expanding the other set classes

`rtr-set` and `peering-set` expand the same way as-sets do — breadth-first,
cycles skipped, missing nested sets reported rather than fatal:

```go
routers, _ := e.ExpandRouters(ctx, types.Ref(mustSet("RTRS-EXAMPLE")))   // addresses and inet-rtr names
peerings, _ := e.ExpandPeerings(ctx, types.Ref(mustSet("PRNG-EXAMPLE"))) // nested references replaced
```

A `filter-set` is different in kind: it holds an expression, not a member list.
`EvalFilter` evaluates one into the prefix ranges it denotes, and
`ExpandFilterSet` does the same for a named set:

```go
ranges, err := e.EvalFilter(ctx, filter) // filter is a policy.Filter
```

Only the part of the filter language with a finite answer in prefixes is
evaluated: `ANY`, prefix lists, route-set/as-set/filter-set references, AS
numbers and AS expressions, `OR`, and `AND` (the intersection of what the two
sides denote). `NOT`, `PeerAS`, community tests, AS-path regexps and per-peer
templates need a routing table or a peer, so they return a
`*NotEnumerableError` naming the term — never a quietly smaller answer.

## Sources that need no network

```go
src, err := resolve.LoadDump(f)              // an IRR bulk dump; wrap f in gzip.NewReader if needed
cached := resolve.NewCache(live, time.Hour)  // a caching Source over any other
```

`Cache` is safe for concurrent use, caches "not found" as the real answer it is,
and collapses identical lookups already in flight into one backend call.
`DumpLoader` reads several files into one Source and reports what it saw.

What it holds is a `Corpus`: sets and membership claimants whole, every other
route as its prefix, origin and source, nothing of the rest — RIPE's dumps in
460 MB rather than the 3.7 GB their decoded objects take. `Corpus.Merge`
combines dumps, mirrors (`nrtm4.Client.CopyTo`) and RPKI pseudo routes, and
`Corpus.Source("RIPE", "RADB")` builds the `MemSource` with a precedence.

## RPKI-aware expansion (`resolve/rpki`)

IRRd 4 validates every route object against the RPKI (RFC 6811) and hides the
invalid ones, and serves each ROA as a route of the source `RPKI`; RADB lists
that source by default. A registry's own dump, or a whois server, does neither.
`resolve/rpki` does both for any `Source`:

```go
vrps, err := rpki.ReadJSON(f)            // rpki-client's or Routinator's JSON export
vrps, err = vrps.ApplySLURM(slurm)       // optional: RFC 8416 local overrides
src := &rpki.Filter{Src: mem, VRPs: vrps} // invalid routes left out, as IRRd does
err = vrps.WriteRPSL(w)                  // IRRd's pseudo objects, for DumpLoader.Read
```

`Filter` leaves a route-set's listed prefixes alone, as IRRd does: it
suppresses route objects, not members. Over an IRRd that is not RPKI-aware,
the indirect route members `!i` folds into a set are beyond it; RADB
suppresses those itself.

## A mirror kept current (`resolve/nrtm4`)

A dump is out of date the day it is written. Where a registry publishes
NRTMv4 — the RIPE Database does, for `RIPE` and `RIPE-NONAUTH` — a
`nrtm4.Client` keeps a verified mirror current:

```go
c := &nrtm4.Client{
	URL:       "https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose",
	Database:  "RIPE",
	PublicKey: key, // PEM, from https://ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt
}
c.Sync(ctx)                   // the snapshot, then the deltas since
go c.Run(ctx, time.Minute, nil)
e := &resolve.Expander{Src: c.Source()} // one version, whole, per expansion
```

Every file is verified — the notification file's ES256 signature (with
in-band key rotation), each snapshot's and delta's SHA-256 — and a delta
applies whole or not at all. Persist `Status().CurrentKey`: after a rotation
it, not the key you started with, verifies.

## Evaluating policy (`peval`)

`resolve/peval` evaluates an aut-num's `import:`/`export:`/`*-via:`/`default:`
policies for one BGP session — what IRRToolSet's `RtConfig` computes before
printing a router configuration:

```go
import "github.com/rkolesnichenko/rpsl/resolve/peval"

v := &peval.Evaluator{Src: resolve.NewMemSource(objs)}
p, err := v.Import(ctx, peval.Session{
	Local: 1, Peer: 2, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast},
})
for _, c := range p.Clauses {
	fmt.Println(c.Actions[0], "|", c.Filter) // pref = 10 | {10.2.0.0/16}
}
```

This is trimmed from a runnable `Example` test
([`peval/example_test.go`](peval/example_test.go)).

A `Policy`'s `Clauses` are in RFC 2622 §6.1 specification order, each with its
filter already normalized (`resolve.NormalFilter`, PeerAS bound to the
session's peer). A term the evaluator cannot decide for this session — a
peering that names a router the session doesn't give, a peering regexp, or a
protocol other than BGP4 — is never guessed at either way: it lands in
`Policy.Undecided` with a reason, and contributes no clause. `NormalizeFilter`
is the same disjunctive-normal-form evaluation `EvalFilter` uses where it can
answer; where it can't (AS-path regexps, community tests), the term is kept
symbolic rather than dropped, so a printer — or a human reading
`NormalFilter.String()` — sees exactly what the filter says, never a quietly
narrower approximation. `rpslconf -e` (see
[`docs/rpslconf.md`](../docs/rpslconf.md)) exposes this on the command line.

## Concurrency

`Expander.Concurrency` fetches a whole breadth-first level at once, which hides
a live registry's latency. It changes no result: the level's answers are merged
in the level's own order, and a test compares serial against parallel over two
hundred random set graphs.
