# Step 14: close the eight redaction gaps

The maintainer approved fixing all eight gaps pinned in step 12 ("fix all gaps"). This step
changes `internal/audit/redact.go`. Standard library only.

## Problem

Eight shapes reach `args_preview` unredacted (list and probe results in `plans/step-12.md`):

1. AWS secret key containing `/`, bare in text.
2. AWS secret key containing `/`, INI form `aws_secret_access_key = value`.
3. AWS secret key containing `/`, `AWS_SECRET_ACCESS_KEY: value` form.
4. `Authorization: Bearer <token>` with a token under 8 characters.
5. `Authorization: Token <letters-only token>`.
6. Database URL whose password contains a literal `@`.
7. `redis://:password@host`, letters-only password.
8. `redis://:password@host`, mixed password, short host.

## Change (one function-level edit per cause, all in `redact.go`)

- **Assignments with spaces or a colon (2, 3).** `envAssign` accepts `NAME=value` only. Widen the
  separator to `[ \t]*[=:][ \t]*` and keep the separator in the output. The value must start with
  a character that is neither whitespace nor `=`, so `key := f()` and `a == b` are untouched.
  Accepted cost, documented: prose such as `token: enabled` or `monkey: banana` is now redacted
  (the name pattern matches inside a word). Config such as `password: x` is the shape this
  protects, so the colon form is not narrowed.
- **Header values (4, 5).** Regex finds `Authorization`, `Proxy-Authorization` or `X-Api-Key`
  followed by an optional quote, `:` or `=`, and optional spaces. A small Go function then picks
  the end of the value (RE2 has no back-references): if the character just before the header name
  is a quote, the value ends at the next unescaped copy of that quote (a `\"` does not end it, so
  `Authorization: Digest username=\"u\", response=\"s\"` is covered whole); if the value itself
  starts with a quote, it ends at the next copy of that quote; otherwise it ends at the end of the
  line. The value is replaced by `[REDACTED]` and the header name is kept. This covers any scheme
  and any token length. An unquoted header followed by more words on one line loses those words
  too (over-redaction, documented). The bare `Bearer` and `Basic` patterns stay for text without a
  header name. Prose such as "the Authorization header is required" has no `:` or `=` and is
  untouched.
- **URL userinfo (6, 7, 8).** The userinfo is everything between `://` and the last `@` before
  the first `/`, `?`, `#`, whitespace, quote (`"` or `'`), `<`, `>` or backslash:
  `(://)[^\s/?#"'<>\\]*@`. That handles `@` inside a password and an empty user, and stops at a
  quote so `https://u:p@h"x@y` keeps `h`. A URL with no `@` in its authority
  (`https://host/users/@me`) does not match. A `,` or `;` is allowed inside userinfo, so
  `https://a.com,me@x.com/` is read as userinfo (over-redaction, accepted: a leaked password is
  worse than a hidden word).
- **Bare 40-character base64 secret (1).** A new pass, written as a manual scan (RE2 has no
  look-around), finds maximal runs of `A-Za-z0-9/+` and treats a run as a secret only when it is
  exactly 40 characters, is not preceded or followed by `.`, `_` or `-` (so slugs, UUIDs and
  JWT parts are not read as keys), contains an
  upper-case letter, a lower-case letter and a digit, at most 3 `/`, and do not start with `/`.
  Such a run is replaced. This is AWS's secret key format. Known costs, to be written in
  `docs/operations.md`: an unusual 40-character relative path, or any other unpadded 40-character
  mixed-case base64 or mixed-case hex string, is redacted; a secret that starts with `/` or has
  4 or more `/` is not found by this pass (a `NAME=value` context still catches it).

Not changed: the `curl -u` pattern (it also redacts the argument of any `-u` option; over-redaction,
not a leak), the long-word heuristic, key-name redaction, the preview limits.

## Types and ownership

No types change. The new patterns are package-level compiled regular expressions, immutable, same
as the existing ones. `redactString` stays a pure function with no shared state. RE2 matching is
linear in the input, and inputs are already bounded (64 KiB preview limit, 200-byte reason limit).

## Tests (agreed list, natural language; written first)

1. The eight pinned rows become plain must-be-redacted rows (the `leaks` mechanism is removed
   because no row needs it). Run once before the fix: exactly those eight fail.
2. New row: an `X-Api-Key` header with a mixed token.
3. New controls that must pass through unchanged: a URL with `@` in its path or query, a Go `:=`
   assignment, an `==` comparison, a quoted URL followed by text that contains `@`.
   New rows: a Digest `Authorization` header with embedded quotes (whole value gone), a quoted
   header followed by another argument (the argument stays), a 40-character secret preceded by
   `.` or `-` is not read as a key and a 39 or 41-character run is not either (documents the exact
   length rule; not a claim those are safe).
4. All existing audit tests stay green (`TestRedaction`, canaries, reason and id redaction).
5. Mutation check: with the new patterns removed the eight rows fail again.

Decision on limits: a secret with 4 or more `/` is not found by the bare pass. It is not put in
the table as a pinned leak, since that would bring the pinning mechanism back for a case the
documentation already states. It is described in `docs/operations.md` only.

## Result (recorded after the change)

- All eight pinned rows pass as redacted; the `leaks` mechanism was removed. Before the change the
  eight rows and eight new rows failed (16 failures); after it everything passes.
- Review by a second model (gpt-5.6-sol-high) of this plan found: stopping at any quote leaks
  later Digest fields (fixed: quote-aware end scan and a Digest test), unbounded value for an
  unquoted header (accepted and documented), userinfo crossing quotes (fixed: stops at quotes),
  RE2 has no look-around (fixed: manual run scan, with boundary tests), prose false positives for
  the colon form (accepted and documented), SHA and base64 collisions (accepted and documented).
- During implementation a probe found two more problems, both fixed with tests: the `X-Api-Key`
  name matched the assignment rule and swallowed the closing quote, and a quoted value with spaces
  leaked its tail (the old `NAME=\S+` rule had the same flaw).
- Review of the code by the same second model found three issues: `password=[REDACTED]tail` kept
  its tail (fixed: skip only when the rest of the value has no letters or digits), a quoted header
  value continued after an escaped or raw newline leaked its tail (fixed: a quoted value runs to
  its closing quote across lines, with a once-per-string memo so unclosed quotes stay linear), and
  a 40-character key with no digit is not found by the bare pass (kept, since the digit rule keeps
  camel-case paths out; documented, about one key in a thousand).
- Not changed: the `curl -u` pattern, the long-word heuristic, key-name redaction, preview limits.

## Files

- internal/audit/redact.go
- internal/audit/redact_shapes_test.go
- docs/operations.md
- CHANGELOG.md
- plans/step-14.md
