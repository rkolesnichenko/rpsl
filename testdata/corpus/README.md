# Lossless round-trip corpus

Every `.txt` file in this directory is fed through `TestRoundTrip`
(`roundtrip_test.go`), which asserts:

```go
rpsl.ParseObject(text).String() == text  // byte-for-byte
```

Failing this test is the single hardest correctness bar in the library and is
deliberately impossible to weaken without changing the test. Adding a fixture
that hits a previously-uncovered case is a welcome PR; removing or relaxing one
needs a very good reason.

## What's in here

Each file pins a real-world or RFC-derived shape that has historically broken
naive parsers. They are anonymized real objects (registry/handle/email values
substituted for safe stand-ins) unless the filename indicates a fully
synthetic shape (`no-trailing-newline.txt`).

| File | Class / shape it exercises |
| --- | --- |
| `aut-num-ripe.txt` | Vanilla RIPE `aut-num` with `import:`/`export:`. |
| `aut-num-rpslng.txt` | RFC 4012 `mp-*`, `afi`-scoped policy, `except`/`refine`. |
| `as-set.txt` | `as-set` with both `members:` and `mp-members:`. |
| `route-set-mp.txt` | `route-set` with `mp-members:` carrying IPv6 ranges. |
| `route-radb.txt` | RADB-style `route` with mixed casing. |
| `mntner-ripe.txt` | `mntner` with multi-line `auth:` (kept raw). |
| `inetnum.txt`, `organisation.txt`, `peering-set.txt` | Class-coverage fixtures. |
| `remarks-gnarly.txt` | `remarks:` block with `+`-continuation including blank lines — the classic round-trip breaker. |
| `no-trailing-newline.txt` | Object that ends without a trailing newline. |
| `dump-multi.txt` | Multiple blank-line-separated objects (streaming-parser fixture). |

## Adding fixtures

1. Drop a `.txt` file in this directory.
2. Either use anonymized real data (preferred for messy historical shapes) or
   document the synthetic origin in a top-of-file comment.
3. Run `go test -run TestRoundTrip ./...` and confirm it passes.
4. If the fixture shows new behavior (e.g. a new lexer edge case), update the
   relevant section of `docs/rpsl-go-design.md` §3 or §10.
