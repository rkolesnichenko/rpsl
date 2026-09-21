# rpsl/resolve

`import "github.com/rkolesnichenko/rpsl/resolve"`

The set-expansion engine: it expands `as-set`/`route-set` references into concrete
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
	GetSet(ctx context.Context, name types.SetName) (object.Set, error)
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)
	MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error)
}
```

`GetSet` returns `ErrNotFound` for a missing set: a missing *nested* set expands to
nothing and is listed by the result's `Missing()`, while a missing top-level set is
an error. `MembersByRef` backs the indirect `mbrs-by-ref` membership mechanism;
implementations should filter with `resolve.ClaimAllowed`, and the engine re-checks
every returned claim anyway. `NewMemSource(objs, "RIPE", "RADB")` takes an optional
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

func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error)
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
func (e *Expander) ExpandPrefixRanges(ctx context.Context, n types.SetName) (RangeSet, error)
```

`ASSet`/`PrefixSet`/`RangeSet` are deduplicated sets with `Has`, `Len`, a sorted
`List`, and `Missing` (nested sets that were referenced but not found).
`ExpandPrefixRanges` returns ranges before materialization — bgpq4's `le`/`ge`
form — which is the only usable form for sets containing ranges like `/8^+`.

### Engine semantics

- **Two phases** — discovery walks the set graph breadth-first, fetching each set
  once, so a set's depth is its shortest nesting distance and the result never
  depends on member order; evaluation then builds the result without further I/O.
  Each AS's routes are fetched once per call.
- **Cycle detection** — a revisit is *skipped, not an error* (matches `bgpq4`). A
  cycle re-entered under a different range operator (`RS-A` lists `RS-B^+`,
  `RS-B` lists `RS-A`) returns `ErrCyclicOperator` instead of an undersized result.
- **Range operators on members** — `RS-FOO^+` and `AS1^24` apply to every range of
  the set or route of the AS, composing along the path (RFC 2622 §5.2).
- **Dual membership** — direct `members:`/`mp-members:` unioned with indirect
  `member-of:` claims, the latter honored only via `mbrs-by-ref:` + the mntner
  check. Skipping that check is a silent, hijack-relevant bug, so the engine
  enforces it through `MembersByRef`.
- **Fan-out guards** — `MaxPrefixes` is checked *during* enumeration (duplicates
  are free), `MaxVisited` bounds the sets fetched, and `MaxDepth` bounds nesting;
  each returns `ErrSetTooLarge{Name, Limit, Count}` naming the cap rather than
  OOM-ing or truncating silently. `AS-ANY`/`RS-ANY` return `ErrAnySet`.
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
| `resolve/whois` | plain WHOIS (`whois.ripe.net:43`) | resolves indirect membership itself via inverse queries + local mntner check |
| `resolve/rdap` | RDAP registration metadata (`rdap.db.ripe.net`) | registration lookups only — not a `Source` (RDAP has no IRR set objects) |

```go
import "github.com/rkolesnichenko/rpsl/resolve/irrd"

irr := &irrd.Source{
	Addr:      "whois.radb.net:43",
	Sources:   "RADB,RIPE",
	Timeout:   10 * time.Second,
	KeepAlive: true, // pool persistent connections; call Close() when done
}
defer irr.Close()

e := &resolve.Expander{Src: irr, AFI: types.AFIv4}
asns, err := e.ExpandAS(ctx, name)
```

Every `irrd` and `whois` query honours its context: cancelling it (or its deadline
passing) aborts a pending read at once, and `Timeout` (default `DefaultTimeout`,
60 s; negative = none) bounds each query even under `context.Background()`.
`irrd.MaxConns` (default 4) bounds concurrent connections; with `KeepAlive`, a
pooled connection the server has closed is retried once on a fresh one, and a
refused `!s` source list is an error rather than "not found". A whois server
error other than "no entries" is returned as `whois.ErrServer` (e.g. RIPE's
`%ERROR:201` rate limiting), never as an empty result.

Without `KeepAlive`, `irrd` still sends `!!` first on every connection: IRRd
closes a connection after one command otherwise, and the `!s` source selection
would consume it.

The `irrd` and `whois` sources accept a `Dial func(ctx) (net.Conn, error)` hook,
which the test suite uses to drive in-process fake servers without real network.
The fakes model IRRd's one-command-without-`!!` behaviour. `RPSL_LIVE=1 go test
-run TestLiveSmoke .` checks all three backends read-only against RADB, RIPE
whois and RIPE RDAP.

## Correctness

`resolve` ships a small synthetic snapshot (`testdata/`) with hand-checked golden
expansions, compared on every `go test`, plus property tests that check expansion
against an independent reachability oracle on random cyclic graphs. Only the
optional live differential, gated on `RPSL_BGPQ4_SERVER` / `RPSL_BGPQ4_SET`, runs
`bgpq4` itself (and compares ASNs).

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/resolve).
