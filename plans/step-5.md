# Step 5: canary / sensitive egress BLOCK

**Status: awaiting requirements confirmation and design answers.** Do not implement until
Charles approves this plan and the open questions in `REQUIREMENTS.md` (item 1, Q1–Q7).

Source: 2026-11-09 TLDR / The Register (agents revealing secrets to peer forums). Branch:
`improve/tldr-2026-11-09`. One commit for this item. No new modules.

## Goal

If a tool call's arguments contain a configured canary token (or a value matching
`sensitive.go` patterns) and the call is headed to a non-allowed host or a message/forum-style
tool → **BLOCK** and audit.

## Files (expected; adjust after design answers)

- `internal/rules/config.go` — parse optional canary (and forum-tool) policy keys; validate.
- `internal/rules/engine.go` — new finding in `Decide`; rule name TBD.
- `internal/rules/sensitive.go` and/or new helper — how "sensitive.go patterns" participate (Q3).
- `internal/rules/config_test.go`, `engine_test.go` — load/validation and table cases.
- `internal/proxy` and/or `cmd/agent-guard` tests — loopback `127.0.0.1:0`, fake upstream with
  `tool_use` containing the canary; streaming + non-streaming; deadline on every read.
- `docs/policy.md`, `examples/policy.yaml`, `README.md` (decision table row), `REQUIREMENTS.md`
  decisions once answered.
- `plans/README.md` — index this step.

## Types / state

- Canary strings (and any forum-tool patterns) stored on `Engine` after `Parse`.
- **Ownership:** `Engine` remains immutable after load; no new shared mutable state; no new
  mutex or owner goroutine. Concurrent `Decide` stays read-only on the engine.
- Proxy/audit/telemetry ownership unchanged (audit writer goroutine; request goroutine owns
  per-request parse state).

## Behaviour sketch (pending Q1–Q7)

1. Scan tool input string values for configured canaries (match semantics TBD).
2. Optionally treat sensitive path/host classifications as an additional "payload" trigger (Q3).
3. Determine whether the call is an **egress channel**: extracted host not allowlisted (mention
   policy TBD) **or** tool name matches forum-style set (TBD).
4. If trigger ∧ egress → finding `{Block, <rule>, <reason>}`; combine with existing rules
   (strictest wins; order TBD).

## Tests

- Unit: config accept/reject; Decide table (canary + forum tool → BLOCK; canary + allowlisted
  non-forum tool → per Q5; no canary → unchanged; sensitive-pattern case per Q3).
- Behavioural: real listener `127.0.0.1:0`; fake upstream returns `tool_use` with canary;
  assert rewritten BLOCK notice and audit record; **streaming and non-streaming**; every read
  has a deadline; no sleeps for sync.
- `bash scripts/check.sh`: gofmt, go vet, govulncheck, `go test -race -count=1`.

## Out of scope for this step

- BishopFox docs (step 6).
- New dependencies, Codex/OpenAI protocols, approval channel, live API tests.

## Open questions

See `REQUIREMENTS.md` Proposed item 1, Q1–Q7. Plan cannot be finalized until those are answered.
