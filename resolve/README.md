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
	GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error)
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)
	MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error)
}
```

`GetSet` returns `ErrNotFound` for a missing set: a missing *nested* set expands to
nothing and is listed by the result's `Missing()`, while a missing top-level set is
an error. `MembersByRef` backs the indirect `mbrs-by-ref` membership mechanism;
implementations should filter with `resolve.ClaimAllowed(obj, set)`, and the engine
re-checks every returned claim anyway. `NewMemSource(objs, "RIPE", "RADB")` takes an optional
source precedence for set names defined in several IRRs.

## The `Expander`

```go
type Expander struct {
	Src         Source
	MaxDepth    int       // cap on shortest nesting distance from the top (default 32)
	MaxPrefixes int       // cap on output prefixes, or ranges (default 1<<20)
	MaxVisited  int       // cap on distinct sets fetched (default 1<<17)
	AFI         types.AFI // address-family constraint; Unspecified/Any = both
}

func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASNSet, error)
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error)
func (e *Expander) ExpandRouters(ctx context.Context, n types.SetName) (RouterSet, error)
func (e *Expander) ExpandPeerings(ctx context.Context, n types.SetName) (PeeringSet, error)
func (e *Expander) ExpandFilterSet(ctx context.Context, n types.SetName) (RangeSet, error)
func (e *Expander) EvalFilter(ctx context.Context, f policy.Filter) (RangeSet, error)
```

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

asns, _ := e.ExpandAS(context.Background(), name)        // [AS1 AS2]
prefixes, _ := e.ExpandPrefixes(context.Background(), name) // 10.0.0.0/8, 192.0.2.0/24
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
asns, err := e.ExpandAS(ctx, name)
```

Every `irrd` and `whois` query honours its context: cancelling it (or its deadline
passing) aborts a pending read at once, and `Timeout` (default `DefaultTimeout`,
60 s; negative = none) bounds each query even under `context.Background()` —
one deadline covering the wait for a `MaxConns` slot, the dial, the I/O and any
retry. `rdap.Client.Timeout` bounds each RDAP request the same way.
`irrd.MaxConns` (default 4) bounds concurrent connections; with `KeepAlive`, a
pooled connection the server has closed is retried once on a fresh one, and a
refused `!s` source list is an error rather than "not found". IRRd answers
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
routers, _ := e.ExpandRouters(ctx, mustSet("RTRS-EXAMPLE"))   // addresses and inet-rtr names
peerings, _ := e.ExpandPeerings(ctx, mustSet("PRNG-EXAMPLE")) // nested references replaced
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

## Concurrency

`Expander.Concurrency` fetches a whole breadth-first level at once, which hides
a live registry's latency. It changes no result: the level's answers are merged
in the level's own order, and a test compares serial against parallel over two
hundred random set graphs.
