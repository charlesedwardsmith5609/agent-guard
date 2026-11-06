# Requirements and design decisions

Status: **implemented** (all four phases). This file records what was asked for and the decisions
made along the way. For how the program behaves today, read the [README](README.md) and
[docs/](docs/); where they differ from this file, they win.

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
- Validation against the live Anthropic API and a real Claude Code session.
