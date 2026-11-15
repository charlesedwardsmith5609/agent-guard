# Step 9: LOW findings 6 to 10

Status: implemented (check passes). Details of what shipped are in the commit and docs.

## Items

- 6: halt does not stop upstream traffic. Approved: check in `ServeHTTP` before forward, reusing step 8's propose/Commit/Abort protocol with cleanup on every early return.
- 7: `engine.go:163` `hostAllowed`: candidates must pass `validHost` or be an IP literal, so
  `evil.example%2f.github.com` no longer matches `*.github.com`.
- 8: `looseIPv4` (`sensitive.go:72`): parse decimal, `0x`, leading-0 octal by hand; reject `0b`,
  `0o`, underscores.
- 9: docs: write halt file via temp + rename. Fix `TestHaltRaceDuringTraffic` the same way.
- 10: the remaining missing tests: `count_tokens` header stripping, duplicate identity headers.
  (Tests for findings 1 to 3, 5, 7 live in steps 7 and 8 and here for 7.)

## Files

`internal/rules/engine.go`, `internal/rules/sensitive.go`, `internal/rules/*_test.go`,
`internal/proxy/proxy.go` (item 6), `internal/proxy/*_test.go`, `docs/` halt page.

## Tests (failing first)

- `evil.example%2f.github.com` BLOCK; `http://0b1111111.0.0.1/` and `0o`/`_` forms are not
  127.0.0.1; decimal/hex/octal still canonical (existing table)
- halted proxy: await the halted response, then send an allowed sentinel through the same proxy and inspect the upstream's synchronized request log: only the sentinel
- `ProfileFor` on halt refusal (moved from step 8)
- header stripping on `count_tokens`; two `X-Agent-Guard-Identity` headers

## Ownership

None new. Item 6 reads through `halt.Switch.Read` (owner: its mutex).

## Out of scope

Finding 4; anything in steps 7 and 8.
