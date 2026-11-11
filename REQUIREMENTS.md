# Requirements and design decisions

Status: **implemented** (phases 1–4; TLDR 2026-11-09 item 1 in progress on
`improve/tldr-2026-11-09`). This file records what was asked for and the decisions made along the
way. For how the program behaves today, read the [README](README.md) and [docs/](docs/); where
they differ from this file, they win.

## The brief

Build `agent-guard`, a small Go service that acts as a local policy proxy between a coding agent
(Claude Code, Codex) and its model API, inspecting each tool call in the model response before the
agent harness executes it.

| # | Requirement | Status | Where |
|---|-------------|--------|-------|
| 1 | YAML config declaring allowed tools, allowed hosts and path scopes | Done | `internal/rules`, [docs/policy.md](docs/policy.md) |
| 2 | Block undeclared tools; block hosts not allowlisted or mentioned in the user prompt; flag reads of `/proc/*/environ`, `~/.ssh`, `.env` files and `169.254.169.254` | Done. Hosts are found heuristically; "flag" means ASK by default and covers any access, not only reads | `internal/rules` |
| 3 | ALLOW / BLOCK / ASK; JSONL audit log; OpenTelemetry spans with decision, matched rule, latency | Done. ASK is a notice, not an approval flow | `internal/audit`, `internal/telemetry` |
| 4 | Fail closed: any parse error or timeout blocks the call | Done | `internal/proxy` (`guard.go`, `proxy.go`, `stream.go`) |
| 5 | Standard library `net/http` plus minimal dependencies; table-driven tests; `go test -race`; govulncheck clean | Done | `go.mod`, `scripts/check.sh` |
| 6 | README with a threat model that states plainly what it does NOT protect against | Done | [README](README.md#threat-model) |
| – | Supports Claude Code **and Codex** | **Partly**: only the Anthropic Messages API is implemented, so Codex is not supported | see decision 1 |

## Phases

1. Design and threat model, then stop for approval. Approved.
2. Proxy skeleton with tests (standard library only).
3. Rules engine (adds `gopkg.in/yaml.v3`).
4. Audit log and OpenTelemetry (adds the OpenTelemetry API, SDK and stdout exporter).

Phases 2 to 4, the hardening and the documentation were carried out unattended, on the owner's
instruction to continue through all phases. Decisions marked **[unattended]** below were made
during that time without asking, and are the ones most worth reviewing.

## Decisions

1. **Protocols.** Anthropic Messages only (streaming and non-streaming). OpenAI chat completions
   and the Responses API (which Codex uses) are not implemented.
2. **Streaming.** Text passes through live; each `tool_use` block is held until it is complete and
   judged.
3. **ASK.** The call is replaced by a "requires approval" notice, the same as BLOCK from the
   harness's point of view, and the decision is recorded as ASK. There is no approval endpoint.
4. **Dependencies.** `gopkg.in/yaml.v3`; OpenTelemetry API, SDK and the stdout trace exporter. No
   OTLP exporter **[unattended]**. govulncheck must stay clean.
5. **"Mentioned in the user prompt".** Whole-word, case-insensitive match against user-role text
   from the whole conversation; tool results are never consulted. A mention never clears a
   sensitive-location rule. **[unattended: whole conversation, not only the latest turn]**
6. **Extraction.** There are no per-tool schemas. Every string in a tool's input is scanned for
   hosts and sensitive path-like text; a fixed list of argument names (`file_path`, `path`, ...)
   is also checked against the path scope. Shell text is parsed heuristically. *(An earlier draft of
   this file promised per-tool schemas; they were not built.)*
7. **Sensitive locations.** Classes `proc_environ`, `ssh`, `dotenv` and `metadata`, each `ask`
   (default) or `block`.
8. **Timeouts.** Separate flags for a decision (`-decide-timeout`), the upstream headers
   (`-upstream-timeout`) and the whole exchange (`-max-response`). All fail closed.
9. **Audit content.** SHA-256 of the tool input plus a redacted, truncated preview; never headers,
   API keys or full bodies. `-audit-preview=false` keeps only the hash.
10. **Rule combination [unattended].** All rules are evaluated and the strictest verdict wins.
11. **Policy shape [unattended].** `tools`, `hosts`, `paths.workdir`, `paths.allow`,
    `sensitive.<class>`. Unknown keys and multiple YAML documents are errors.
12. **Path scope [unattended].** Applied to structured path arguments only; shell text gets the
    sensitive and host checks but no scope check.
13. **Required keys and tool patterns [unattended].** `tools`, `hosts` and `paths.allow` are
    mandatory (an empty list allows nothing). A tool pattern may end in `*` with a prefix of at
    least 3 characters.
14. **Audit failure fails closed [unattended].** An ALLOW is released only after its audit record
    has been written; a failed or late write turns it into BLOCK.
15. **Audit file [unattended].** JSONL, append-only, mode 0600, created exclusively; symlinks,
    FIFOs and permissive existing files are refused. Unix only.
16. **Resource limits [unattended].** In-flight request cap (503), accepted-connection cap,
    absolute response deadline, size limits on every body and stream, and per-write deadlines.

## Not done

- Codex and other OpenAI-style agents.
- An approval channel for ASK (an endpoint or CLI that waits for a human).
- An optional judge model for ambiguous calls (this idea came from reading the public
  `huggingface/safeagents` README for context; none of its code was used).
- An OTLP exporter, log rotation, hot reload of the policy, Windows support for the audit log.
- Broader live validation. The live API (`scripts/live-test.sh`) and a headless Claude Code session
  with the `Read` and `Bash` tools (`scripts/live-claude-test.sh`) have been exercised; the
  interactive interface, other tools, extended thinking and long sessions have not.

## Proposed (2026-11-09 TLDR)

Source brief: egress canary rule + BishopFox sandbox lessons. Branch: `improve/tldr-2026-11-09`.
One commit per item. Go stdlib plus existing modules only. Done means `bash scripts/check.sh`
passes (gofmt, go vet, govulncheck, `go test -race -count=1`).

Design decisions were drafted, cross-reviewed by a different model (GPT-5.6 Sol high), and the
best suggestion per question was taken. Full record: [`plans/decisions-step-5-6.md`](plans/decisions-step-5-6.md).

### Item 1 — Canary / sensitive egress BLOCK (code + tests + policy docs)

| # | Requirement | Status |
|---|-------------|--------|
| 17 | Policy option for configured **canary strings**. If a tool call's arguments contain a configured canary token **or** a value matching `sensitive.go` path/host classes, and the call has an **egress channel** (any extracted host, or a message/forum-style tool), the verdict is **BLOCK** and the decision is audited. | Implemented (awaiting clean govulncheck; see below) |
| 18 | Motivation (docs/comments only): agents shared a private deploy token ~15% of the time when a peer forum asked for it (The Register via TLDR InfoSec, 2026-11-09; https://www.theregister.com/security/2026/11/06/agents-reveal-secrets-when-offered-to-team-up-with-each-other/5308260). | Implemented |
| 19 | Tests: real loopback listener on `127.0.0.1:0`; fake upstream returning a `tool_use` that contains the canary; deadline on every read; **streaming and non-streaming**. | Implemented |

### Locked decisions (item 1)

17. **YAML.** Optional top-level `canaries` and `forum_tools` (flat, like `tools`). Omit or `[]`
    disables that leg; sensitive∧egress still applies when classifications hit.
18. **Match.** Case-sensitive literal substring in parsed JSON string values; canary length
    16–256 **bytes**; reject leading/trailing whitespace in the configured token; max 64
    canaries; max 64 `forum_tools` patterns (same `*` rules as `tools`).
19. **Sensitive patterns.** (A) `pathClass` / `hostClass` hit plus egress channel → BLOCK as
    `egress:sensitive:<class>`, even if `sensitive.<class>` is `ask`. No new value regexes.
20. **Forum-style tools.** Name matches `forum_tools` **or** CamelCase/delimiter fragments
    include `send|post|publish|message|comment|reply`, or (`create|update|add` with
    `issue|discussion|pull_request|pullrequest|pr`). Document over-match risk.
21. **Egress channel.** Any extracted host (allowlist and user mention **ignored** for this
    rule) **or** forum-style tool. Intentional strengthening vs brief “non-allowed host”.
22. **Rules / reasons.** `egress:canary` / `egress:sensitive:<class>`; reasons never include
    matched secrets/paths beyond safe class names. Configured canaries are also redacted in
    audit previews (read-only copy from Engine to audit at startup).
23. **Order.** Findings evaluated for reporting: `egress:canary`, `egress:sensitive:<class>`,
    tool, sensitive, host, scope; strictest verdict wins.
24. **Ownership.** Engine immutable after Parse; no new mutex. Decide scans check `ctx.Err()`
    periodically. Audit holds a copy of canary strings for redaction only.

### Item 2 — BishopFox Claude sandbox lessons (docs only)

| # | Requirement | Status |
|---|-------------|--------|
| 25 | Add **"Lessons from BishopFox's Claude sandbox write-up"** as **new numbered item 11** under README “What it does NOT protect against”: process-level access can read process memory and make network interfaces; **agent-guard is not a sandbox**. Cite https://bishopfox.com/blog/journey-into-claudes-sandbox (TLDR InfoSec 2026-11-09). Docs only. | Decisions locked |
