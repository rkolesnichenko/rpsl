# Security policy

`rpsl` is a library that parses untrusted text (IRR dumps and WHOIS/RDAP
responses from the public internet) and turns it into structured Go values,
and it includes network backends that talk to third-party registries. Both
attack surfaces are taken seriously.

## Reporting a vulnerability

Please email **rokolg@gmail.com** with details. Include a minimal reproducer
if you have one. Public GitHub issues are not the right channel for an
embargoed report — open an issue only after we've coordinated disclosure.

I'll acknowledge within 72 hours and aim to have a fix candidate within two
weeks for issues affecting parsing safety, engine purity, or network
backends. Timelines for other classes of issue are negotiated case by case.

## What's already hardened

These are the invariants the library currently enforces; treat a regression in
any of them as a security-relevant bug.

### Parser

- **Resilient parsing, no panics on hostile input.** The lexer is a total
  partition of the input (every byte belongs to exactly one token), and
  malformed lines become `KindMalformed` tokens that surface as
  `lexer/malformed-line` diagnostics rather than crashes. Fuzz coverage on
  `FuzzTokenize`, `FuzzParseImport`, and `FuzzParseASPathRegexp` enforces this
  property.
- **Streaming-mode memory cap.** `rpsl.ParseOptions.MaxObjectBytes` (default
  `DefaultMaxObjectBytes`, 64 MiB, also applied by `Parse`) bounds each object,
  the run of blank/comment lines before it, and every line as it is read, so a
  hostile dump — no blank-line separators, a multi-GB line, or endless blank
  lines — cannot drive the parser to OOM. A negative value disables the cap.
- **Read errors are never hidden.** A failing reader (e.g. a corrupt gzip dump)
  ends the stream with an `rpsl/read-error` diagnostic instead of looking like a
  clean end of input.

### Engine

- **Pure resolver, no implicit I/O.** `cd resolve && go list -deps .` does not
  include `net`. All sockets live in `resolve/irrd`, `resolve/whois`, and
  `resolve/rdap`; the engine itself is context-cancellable with explicit
  limits.
- **Three fan-out budgets, all typed.** `MaxPrefixes` (default `1<<20`),
  `MaxVisited` (default `1<<17`), and `MaxDepth` (default 32, measured as the
  shortest nesting distance) return `ErrSetTooLarge` naming the `Limit` on
  breach. A pathological IRR graph — wide, deep, or cyclic — cannot drive the
  engine to OOM, and no cap truncates a result silently.
- **Cycle detection on every traversal.** Discovery fetches each set once;
  revisits are skipped (`bgpq4` semantics), not errored. A cycle re-entered
  under a different range operator returns `ErrCyclicOperator`.

### Network backends

- **Cancellation and timeouts.** Every `irrd`/`whois` query honours its
  context (cancellation aborts a pending read at once) and a per-query
  `Timeout` (default 60 s), so a stalled or hostile server cannot hang a caller.
- **`resolve/irrd`** — fresh connection per query by default; idle pool only
  with explicit opt-in (`KeepAlive`); `MaxConns` bounds concurrent connections;
  `MaxResponse` caps a frame, and memory grows only with bytes actually
  received, never with the length a header claims; set names are validated by
  construction, so no query can carry an injected command.
- **`resolve/whois`** — per-response `MaxResponse` body cap; server errors are
  surfaced (`ErrServer`), so rate limiting cannot silently shrink a filter;
  injected `Dial` for testability and for isolating the socket from the engine.
- **`resolve/rdap`** — HTTPS-only base URL, bounded response body, capped
  redirect chain, scheme-checked on every hop; the built-in client refuses
  private, loopback, link-local and special-purpose addresses *at dial time*
  (so hostnames, numeric forms and DNS rebinding are caught). A caller-supplied
  `HTTP` client is not guarded — guard its dialer yourself.
- **Indirect membership (`mbrs-by-ref`).** The mntner check is enforced; an
  unverified `member-of:` claim does not contribute to an expansion. Skipping
  this check is a hijack-relevant correctness bug.

## Scope

In scope:

- Memory safety, panics, and resource exhaustion in the parser or engine.
- Bypasses of the indirect-membership mntner check.
- Network-backend response-handling bugs (unbounded reads, scheme/redirect
  bypass, etc.).
- Output divergence from `bgpq4` on the differential corpus, when the
  divergence has security implications (over-collecting a customer cone, etc.).

Out of scope:

- Disagreement with another tool's behavior in a benign way (e.g. cosmetic
  diagnostic wording).
- Bugs in third-party registries themselves.
