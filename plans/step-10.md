# Step 10: MEDIUM finding 4 (identity header is a label)

Covers finding 4 only (D7). Findings 1 to 3 and 5 to 10 were verified fixed (see
`.review/plan-summary.md`). Docs only; no Go source changes.

## Problem

`docs/policy.md` and `docs/running-many-agents.md` present profiles as access control. The
header is self-asserted, so any client that can reach the listener can claim the most
permissive profile. README and operations already say the proxy has no authentication, but
the profile docs never connect the two.

## Change

- `docs/policy.md` (profiles section): state that the identity is a label, not authentication.
  A profile limits an honest agent; it does not stop a client from sending another identity.
- `docs/running-many-agents.md`: say that for isolation, run one proxy per agent (already
  documented) and keep each listener reachable only by that agent.
- `README.md`: one sentence next to the "no authentication" line pointing to the profile docs.
- Do not claim listener binding or secrets exist. Suggestions (not built): bind a profile to
  a listener or unix socket; per-agent secret compared in constant time and never logged;
  reject duplicate identity headers as unknown.

## Types and ownership

No types and no shared state change.

## Tests (failing first)

Behavioral code tests do not apply to prose. One test pins the claim against the code:

- a client that sends `X-Agent-Guard-Identity` naming a permissive profile gets that
  profile (real listener on `127.0.0.1:0`, real HTTP request, audit `profile` field checked),
  proving the docs' statement. Likely already covered by `TestProfileAuditAndHeader`; if so,
  add no test and say so.
- A docs check: the profile section of `docs/policy.md` contains the word "authentication".

## Files

- `docs/policy.md`
- `docs/running-many-agents.md`
- `README.md`
- `internal/proxy/profile_test.go` (only if the existing test does not cover the claim)
