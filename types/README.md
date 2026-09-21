# rpsl/types

`import "github.com/rkolesnichenko/rpsl/types"`

The leaf value types every higher RPSL layer is built from. They are built on
`net/netip` (so they interoperate with `bart`/`netipx` and the rest of a modern
Go networking stack) and are **comparable** where possible — `ASN`, `SetName`,
`PrefixRange`, `AddrFamily`, and `NICHandle` all work as map keys and in tests.

This module has no dependencies, so a consumer who only needs to parse ASNs or
prefix-ranges pays nothing for the rest of the library.

## Types at a glance

| Type | Parses | Notes |
| --- | --- | --- |
| `ASN` | `ParseASN("AS65001")`, `"AS1.10"` | 32-bit; accepts plain and asdot, emits plain |
| `SetName` | `ParseSetName("AS3333:AS-CUSTOMERS")` | hierarchical; strict RFC 2622 syntax (safe to put on the wire); `Class()` inferred; `Canonical()` is the identity/map key |
| `PrefixRange` | `ParsePrefixRange("192.0.2.0/24^25-28")` | `^+ ^- ^n ^n-m`; `Materialize(cap)` enumerates |
| `RangeOperator` | `ParseRangeOperator("24-32")` | an operator without a prefix, as in `RS-FOO^+`; `Apply` composes per RFC 2622 §5.2 |
| `AddrFamily` / `AFI` / `SAFI` | `ParseAddrFamily("ipv4.unicast")` | RFC 4012 afi dictionary; `any` means both |
| `NICHandle` | `ParseNICHandle("EX1-RIPE")` | preserves original case |

## ASNs

```go
a, _ := types.ParseASN("AS65001")
b, _ := types.ParseASN("AS1.10") // asdot: 1*65536 + 10

fmt.Println(a)         // AS65001
fmt.Println(b)         // AS65546 — normalized to plain form
fmt.Println(uint32(b)) // 65546
```

## Prefix ranges

The `^operator` is a first-class type with an explicit, capped `Materialize` — so
a pathological `^0-32` cannot blow your memory budget. Passing a cap smaller than
the enumeration returns `ErrTooManyPrefixes`.

```go
r, _ := types.ParsePrefixRange("192.0.2.0/24^25-26")

prefixes, err := r.Materialize(100)
fmt.Println("range:", r)             // 192.0.2.0/24^25-26 — round-trips
fmt.Println("count:", len(prefixes)) // 6 — two /25s + four /26s
fmt.Println("err:", err)             // <nil>
```

Both snippets are copied from runnable `Example` tests
([`example_test.go`](example_test.go)).

See the [root README](../README.md) and
[GoDoc](https://pkg.go.dev/github.com/rkolesnichenko/rpsl/types).
