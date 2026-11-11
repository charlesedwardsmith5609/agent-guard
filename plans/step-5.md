# Step 5: canary / sensitive egress BLOCK

**Status: implemented** (see `plans/decisions-step-5-6.md`). One commit. No new modules.
Branch: `improve/tldr-2026-11-09`. Check: gofmt/vet/tests pass; govulncheck needs Go 1.26.11
(approval asked — GO-2026-6859 in net/http on 1.26.10).

## Goal

If tool args contain a configured canary **or** a `sensitive.go` path/host classification,
and the call has an **egress channel** (any extracted host, or forum-style tool) → **BLOCK**
and audit (`egress:canary` or `egress:sensitive:<class>`).

## Files

- `internal/rules/config.go` — optional `canaries`, `forum_tools`; bounds and validation.
- `internal/rules/engine.go` — egress findings first; forum heuristic; canary substring scan.
- `internal/rules/sensitive.go` — reuse `pathClass` / `hostClass` (no new value patterns).
- `internal/rules/*_test.go` — load + Decide tables.
- `internal/audit` — redact configured canary substrings in previews/reasons (read-only list
  owned by Engine, copy passed at writer construction from `main`).
- `cmd/agent-guard` — wire canary list into audit if needed; e2e if appropriate.
- `internal/proxy` and/or `cmd/agent-guard` tests — `127.0.0.1:0`, fake upstream `tool_use`
  with canary; streaming + non-streaming; deadline on every read.
- `docs/policy.md`, `examples/policy.yaml`, `README.md` decision table, `REQUIREMENTS.md`
  status when done.
- `plans/README.md` — already indexes this step.

## Types / ownership

```text
Engine (immutable after Parse):
  canaries []string          // 16–256 bytes each, max 64
  forumExact / forumPrefix   // same shape as tools, max 64 patterns
Audit writer construction:
  optional extra redact needles = copy of canaries  // no mutex; copy at startup
```

No new shared mutable state. Concurrent `Decide` remains read-only on Engine.

## Behaviour

1. Extract hosts/paths as today.
2. Scan string values for canary substrings (case-sensitive; `ctx.Err()` periodically).
3. Egress channel if `len(hosts) > 0` OR tool is forum-style (config or heuristic).
4. If canary hit ∧ egress → `egress:canary` BLOCK.
5. If sensitive class on path/host ∧ egress → `egress:sensitive:<class>` BLOCK.
6. Then existing tool / sensitive / host / scope findings; strictest wins; report first of
   equal rank in order: egress:canary, egress:sensitive:*, tool, sensitive, host, scope.

## Tests

- Config: too-short canary, whitespace edges, caps, unknown keys.
- Decide: canary + host (including allowlisted) → BLOCK; canary + forum tool → BLOCK;
  canary + local Read/Bash with no host → not this rule; sensitive path + forum →
  `egress:sensitive:…` BLOCK even when class is ask; mention does not clear.
- Proxy/e2e: loopback, streaming and non-streaming, deadlines, audit redacts canary.
- `bash scripts/check.sh` all stages green.

## Out of scope

- Step 6 docs, new deps, Codex, live API tests.
