<!-- What does this change, and why? Link the issue it fixes, if there is one. -->

## Checklist

- [ ] `scripts/check.sh` passes (it covers every module; `go test ./...` covers only the root).
- [ ] Tests cover the change. A new round-trip case is a fixture in `testdata/corpus/`, and an input a fuzz target found is committed under `testdata/fuzz/`.
- [ ] A change users can see (API, behaviour, a diagnostic rule) has a line in `CHANGELOG.md` under `## [Unreleased]`.
- [ ] A new or changed diagnostic rule is listed in `docs/diagnostics.md` with its severity.
- [ ] If behaviour changed, `docs/rpsl-go-design.md` says so.
- [ ] Nothing in [Non-negotiables](https://github.com/rkolesnichenko/rpsl/blob/main/CONTRIBUTING.md#non-negotiables) is relaxed: lossless round-trip, no panics on any input, a pure `resolve` engine, imports that run strictly downward.
