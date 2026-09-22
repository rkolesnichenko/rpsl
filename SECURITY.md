# Security policy

`rpsl` is a library that parses untrusted text (IRR dumps and WHOIS/RDAP
responses from the public internet) and turns it into structured Go values,
and it includes network backends that talk to third-party registries. Both
attack surfaces are taken seriously.

## Reporting a vulnerability

Please report it privately through GitHub:
**[Report a vulnerability](https://github.com/rkolesnichenko/rpsl/security/advisories/new)**
(also on the repository's Security tab). The report stays private between you
and the maintainer until an advisory is published. If you can't use GitHub,
email **rokolg@gmail.com** instead.

Include a minimal reproducer if you have one. Public GitHub issues are not the
right channel for an embargoed report — open an issue only after we've
coordinated disclosure.

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
  `lexer/malformed-line` diagnostics rather than crashes. Twelve fuzz targets,
  one for every parser that takes untrusted text (listed in
  [README.md](README.md#testing)), enforce this property.
- **Streaming-mode memory cap.** `rpsl.ParseOptions.MaxObjectBytes` (default
  16 MiB) and `MaxObjectLines` (default 262,144), also applied by `Parse`, bound
  each object, the run of blank/comment lines before it, and every line as it is
  read, so a hostile dump — no blank-line separators, a multi-GB line, or
  endless short lines — cannot drive the parser to OOM: with the defaults the
  worst case peaks at about 150 MB. Lexer diagnostics are capped per object.
  A negative value disables a cap. `ParseObject` applies no caps.
- **Policy parser bounds.** A policy value over 1,048,576 tokens is refused
  (`policy/too-long`), diagnostics stop after 100 per value, and AND/OR chains
  are flat nodes while nesting is capped, so neither memory nor the depth of the
  AST (and of any recursive walk over it) is attacker-controlled.
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
  shortest nesting distance) return `SetTooLargeError` naming the `Limit` on
  breach. A pathological IRR graph — wide, deep, or cyclic — cannot drive the
  engine to OOM, and no cap truncates a result silently.
- **Cycle detection on every traversal.** Discovery fetches each set once;
  revisits are skipped (`bgpq4` semantics), not errored. Evaluation states are
  (set, operator stack) pairs with stacks compared by effect, so cycles through
  range operators terminate at the RFC's fixpoint, and `MaxVisited` bounds the
  states. Cancellation is checked inside the enumeration of a single range.

### Network backends

- **Cancellation and timeouts.** Every `irrd`/`whois` query honours its
  context (cancellation aborts a pending read at once) and one per-query
  `Timeout` deadline (default 60 s) covering the slot wait, dial, I/O and any
  retry; every `rdap` request has the same (`Client.Timeout`). A stalled or
  hostile server cannot hang a caller.
- **`resolve/irrd`** — fresh connection per query by default; idle pool only
  with explicit opt-in (`KeepAlive`); `MaxConns` bounds concurrent connections;
  `MaxResponse` caps a frame's payload and status lines are capped at 1 KiB,
  so memory grows only with bytes actually received, never with the length a
  header claims; set names are validated by
  construction, so no query can carry an injected command.
- **`resolve/whois`** — per-response `MaxResponse` body cap; server errors are
  surfaced (`ServerError`), so rate limiting cannot silently shrink a filter;
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
