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

`GetSet` returns `ErrNotFound` for a missing set (the engine treats it as an empty
expansion, not a fatal error). `MembersByRef` backs the indirect `mbrs-by-ref`
membership mechanism, performing the mntner check.

## The `Expander`

```go
type Expander struct {
	Src         Source
	MaxDepth    int       // set-nesting depth cap (default 32)
	MaxPrefixes int       // hard cap on prefix output (default 1<<20)
	AFI         types.AFI // address-family constraint; Unspecified/Any = both
	Sources     []string  // IRR source precedence (advisory; the Source decides)
}

func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error)
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error)
```

`ASSet`/`PrefixSet` are deduplicated sets with `Has`, `Len`, and a sorted `List`.

### Engine semantics

- **Cycle detection** — DFS with a visited set keyed by canonical set name; a
  revisit is *skipped, not an error* (matches `bgpq4`).
- **Dual membership** — direct `members:`/`mp-members:` unioned with indirect
  `member-of:` claims, the latter honored only via `mbrs-by-ref:` + the mntner
  check. Skipping that check is a silent, hijack-relevant bug, so the engine
  enforces it through `MembersByRef`.
- **Fan-out guard** — `MaxPrefixes` is checked *during* enumeration; a too-large
  expansion returns a typed `ErrSetTooLarge{Name, Count}` rather than OOM-ing.
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
| `resolve/rdap` | RDAP registration metadata (`rdap.db.ripe.net`) | registration lookups only; its `SetSource` is a no-op adapter (RDAP has no IRR set objects) |

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

The `irrd` and `whois` sources accept a `Dial func(ctx) (net.Conn, error)` hook,
which the test suite uses to drive in-process fake servers without real network.

## Correctness

`resolve` ships a checked-in golden snapshot (`testdata/`) diffed against expected
`bgpq4` output on every `go test`; an optional live `bgpq4` differential is gated
on `RPSL_BGPQ4_SERVER` / `RPSL_BGPQ4_SET`.

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/resolve).
