# Step 12: audit redaction table tests

Covers requirement 27 only. Tests only. `internal/audit/redact.go` is NOT changed in this step:
the unredacted shapes are reported and the human decides what to fix.

## Problem

README threat model item 10 says argument previews are redacted heuristically and can leak.
There is a general table in `TestRedaction` but no table organised by credential shape, so it is
not clear which shapes (AWS keys, GitHub tokens, JWT, Bearer header, database URLs) are covered
and which are not. Tool arguments that carry application config (AntiFox-linked intrusions) are
the same leak path into the audit log.

## Change

New file `internal/audit/redact_shapes_test.go`.

- Cases are a table: name, shape group, input (a JSON tool input or a string wrapped as
  `{"command": ...}`), `gone` (secret fragments that must not appear), `kept` (substrings that
  must stay, for example the host) and `leaks` (the exact fragments that still appear today; a
  non-empty `leaks` marks a known gap).
- The oracle is per fragment, not per whole secret. A partial redaction can remove the whole
  secret string while leaving a unique tail (`user:p@tail@host`, a slash-separated AWS secret). So
  every case lists the secret's distinctive fragments (at least the first 8 and last 8
  characters, and each side of a `/` or `@` split) in `gone`, and the test fails if any appears.
  A gap case lists the residual fragment in `leaks` and the test asserts that exact fragment is
  still present.
- Fixtures use realistic lengths and alphabets, so a gap is a gap in the real shape and not an
  artifact of a toy value: AWS access key id is 20 characters (`AKIA` or `ASIA` plus 16 of
  `A-Z2-7`); AWS secret access key is 40 characters from the base64 alphabet; `ghp_`, `gho_`,
  `ghu_`, `ghs_`, `ghr_` are followed by 36 alphanumerics; `github_pat_` is followed by 22
  alphanumerics, `_`, and 59 alphanumerics; the JWT has realistic header, payload and signature
  segments; Bearer tokens are 20 or more characters except in the one short-token case.
- Every secret-shaped literal is assembled at run time from fragments, as `audit_test.go`
  already does, so no secret-shaped literal exists in the source. The new file has its own
  helper and does not edit `audit_test.go`.
- Interface under test: a real `Writer` receives `policy.Event` values through `Observe`, writes
  JSONL to a buffer, and the test reads `args_preview` from the parsed record. This is the
  interface the audit log uses. `redactString` and `preview` are covered through it.
- Shapes, each with the forms that are common in practice:
  - AWS access key id: `AKIA` and `ASIA` prefixes, bare and as `AWS_ACCESS_KEY_ID=`.
  - AWS secret access key in KEY=value form: `AWS_SECRET_ACCESS_KEY=value` (with and without a
    `/` in the value, quoted and exported), the INI form `aws_secret_access_key = value` and the
    `NAME: value` form, and a JSON key `aws_secret_access_key`.
  - GitHub tokens: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_`.
  - JWT: a three-part token, and an unsigned token with an empty third part.
  - Authorization header: `Bearer` in a curl command, in lower case, as a JSON `Authorization`
    key, a short Bearer token, and a non-Bearer scheme.
  - Database URL with a password: postgres, mysql and mongodb+srv userinfo, a password with `%40`,
    a password containing a literal `@`, an empty user (`redis://:pw@host`), and the query form
    `?password=`.
- Gaps: a case with `leaks` asserts that residual is still present and fails with "now
  redacted: clear leaks" when it stops leaking, so a fix cannot go unnoticed and a gap cannot be
  mistaken for intended behavior. The subtest name is prefixed `KNOWN-GAP/`. No `t.Skip` (the
  misbehavior check flags it, and a skip would hide a fix).
- Controls: each group has a benign input that must pass through unchanged (a host, a path).
- Output of the step: the list of shapes not redacted today, copied into the PR description.
  Probe results so far (to be confirmed by the tests): a bare AWS secret key containing `/` leaks
  (the word splitter breaks it into pieces under 20 characters); `aws_secret_access_key = v`
  and `AWS_SECRET_ACCESS_KEY: v` leak when `v` has a `/`; a password with a literal `@` leaks the
  part after the second `@`; `redis://:pw@host` with a password that has no letter-digit mix
  leaks entirely; a Bearer token under 8 characters and a non-Bearer `Authorization` scheme
  leak in shell text.

## Result (recorded after the tests ran)

Eight rows pin a leak today (all other rows pass as redacted):

1. AWS secret key containing `/`, bare in text.
2. AWS secret key containing `/`, INI form `aws_secret_access_key = value`.
3. AWS secret key containing `/`, `AWS_SECRET_ACCESS_KEY: value` form.
4. `Authorization: Bearer` with a token under 8 characters.
5. `Authorization: Token <letters-only token>`.
6. Database URL whose password contains a literal `@` (the part after the second `@` leaks).
7. `redis://:password@host` (empty user) with a letters-only password.
8. `redis://:password@host` (empty user) with a mixed password and a short host.

Side findings, not leaks: the `curl -u` pattern also redacts the argument of any `-u` option
(`redis-cli -u ...`); the long-word heuristic redacts a host next to a password when they form one
word of 20 or more characters; several rows pass only because of that heuristic and are named so.
Review by a second model (gpt-5.6-sol-high) found two issues, both fixed: an `Observe` call
without a deadline, and row 8 missing.

## Types and ownership

No production type changes. Test-local types only. No shared state: each test builds its own
`Writer` (one writer goroutine owns the buffer; the test reads the buffer through the existing
mutex-guarded `lockedBuf` after `Close`). Every wait uses the existing `closeOK` helper with its
timeout.

## Tests (agreed list, natural language)

1. Every secret in a shape that is redacted today is absent from `args_preview`, and the benign
   part of the same input is still there.
2. Each of the six shapes has at least one case that must be fully redacted.
3. Each shape that leaks today has a case that pins the exact residual fragment (`leaks`).
4. The control inputs (a host, a path, a short harmless word) are unchanged.
5. The Writer's JSON line stays one valid record per input, so redaction cannot break the log.

These are written first. Cases 1 and 2 pass on the current code for the covered shapes. The
gap cases pin the residuals. Before the gaps are pinned, a draft with those cases as plain
must-be-redacted rows (`gone` only) is run once to confirm they fail, and that output is kept in
the report. Each case's `gone` fragments are also checked against a deliberately broken
redactor (a copy of the input) in one test, to prove the oracle can fail.

## Files

- internal/audit/redact_shapes_test.go
- CHANGELOG.md
- plans/step-12.md
