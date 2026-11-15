# Step 7: HIGH findings 1 and 2 (URL host extraction)

Status: implemented (check passes). Details of what shipped are in the commit and docs.

## Goal

Findings 1 and 2 from `.review/findings.md`: an allowed host must not hide the real host,
and special schemes without `//` must still yield a host.

## Design

- Replace `urlRe` + `authorityHost` (`internal/rules/extract.go:38`, `:350-363`) with a scanner:
  1. Find `scheme:` (letters/digits/+.-). For special schemes (http, https, ws, wss, ftp) accept
     any run (including none) of `/` or `\` after the colon. Other schemes still need `//`.
  2. Strip tab, CR, LF from the remainder (WHATWG).
  3. The authority ends at the first `/ ? #` (and `\` for special schemes). Whitespace also
     ends it. Quotes, `)`, `<`, `>` do NOT end it, so `github.com'@evil.example` keeps the `@`.
  4. Split on the last `@`; drop port and brackets.
  5. If the host has characters outside the host alphabet (`validHost` or IP literal), BLOCK
     as "unparseable host". An empty host on a special scheme also BLOCKs.
- Scanner is one linear pass: no per-match copy of the remainder; tab/CR/LF skipped inline;
  keep `ctx.Err()` checks and existing input limits.
- BLOCK path: the walker already returns an error that the proxy guard turns into BLOCK
  (`engine.go:42`). Assumption: reuse that, with a distinct error text. A distinct rule name
  would need `findings`; I will check which fits when writing the test.
- Check that `docs/policy.md` ("after the last @") matches the final behavior.

## Files

- `internal/rules/extract.go` (scanner, `scan`)
- `internal/rules/hostnorm_test.go` (new cases)
- `docs/policy.md` (wording only, if needed)

## Tests (written first, from the repro inputs, must fail before the fix)

With github.com allowed, each expects BLOCK:
- `http://github.com'@evil.example/`, `)`, `<`, `"` variants
- `http://github.com<TAB>@evil.example/` and newline variant
- `http://github.com\@evil.example/`
- Bash: `curl 'http://github.com'"'"'@evil.example/'`
- `http:/evil.example/x`, `http:evil.example/x`, `http:\\evil.example\x`
- `node -e "fetch('http:/evil.example/')"`
- empty host: `http:///` BLOCK (unparseable-host error asserted)
- `http:///github.com/x` stays ALLOW (slashes skipped)
- malformed host not otherwise disallowed (e.g. allowlist contains it) still errors
- through the loopback proxy, streaming and non-streaming: tool_use with a malformed host is not released
Near-misses that must stay ALLOW: `https://github.com/x`, `https://user@github.com/x`,
`https://github.com:443/x?a=b@evil.example`, `http://github.com/@evil.example`.

## Ownership

None. The engine is immutable after Parse; the walker is per call. No new shared state.

## Out of scope

Halt (step 8), low items (step 9), finding 4.
