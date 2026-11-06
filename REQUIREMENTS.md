# agent-guard: requirements

Status: Phase 1 decisions accepted by the human ("accept all suggestions"). Items marked
**[ASSUMED]** were not explicitly answered and should be confirmed.

## Purpose
A local policy proxy between a coding agent (Claude Code, Codex) and its model API. It inspects
each tool call in the model response before the harness executes it.

## Requirements (from the brief)
1. YAML config declares allowed tools, allowed hosts, and path scopes.
2. Block calls to undeclared tools. Block calls to hosts that are neither allowlisted nor
   mentioned in the user prompt. Flag reads of sensitive paths: `/proc/*/environ`, `~/.ssh`,
   `.env` files, and the metadata endpoint `169.254.169.254`.
3. Decisions are ALLOW, BLOCK or ASK. Write a JSONL audit log. Emit OpenTelemetry spans carrying
   decision, matched rule and latency.
4. Fail closed: any parse error or timeout blocks the call.
5. Go standard library `net/http` plus minimal dependencies. Table-driven tests, `go test -race`,
   govulncheck clean.
6. README with a threat model that states plainly what it does NOT protect against.

## Phases
- Phase 1: design and threat model (this document). Approved.
- Phase 2: proxy skeleton with tests (stdlib only).
- Phase 3: rules engine (adds `gopkg.in/yaml.v3`).
- Phase 4: OTel and audit log (adds OpenTelemetry API + SDK, stdout exporter, optional OTLP).

Each phase gets its own `plans/step-N.md` and plan review. No phase starts without approval.

## Decisions
1. **Protocols:** v1 is Anthropic Messages only. OpenAI Chat Completions and Responses (Codex)
   are later steps, each needing its own plan.
2. **Streaming:** pass text through live. Hold each tool-call block until complete and judged.
3. **ASK:** v1 replaces the call with a "needs approval" notice, behaving like BLOCK for the
   harness, with the decision recorded as ASK. No approval endpoint in v1.
4. **Dependencies approved:** `gopkg.in/yaml.v3` (Phase 3); OpenTelemetry API + SDK, stdout
   exporter, optional OTLP (Phase 4). govulncheck must be clean. Nothing else without approval.
5. **User prompt:** user-role text from the whole conversation; never tool results.
   **[ASSUMED]** whole conversation rather than latest turn.
6. **Extraction:** per-tool argument schemas for known tools (Bash, Read, Write, WebFetch) plus a
   generic scan of every string argument. Shell parsing is heuristic and documented as such.
7. **Sensitive paths:** default ASK, configurable per rule.
8. **Timeouts:** separate configurable values for rule evaluation and the upstream round trip.
   Both fail closed.
9. **Audit log:** SHA-256 of the arguments plus a redacted, truncated preview. Never API keys or
   full bodies.

## Decisions made unattended in Phases 3 and 4 (human to review) [ASSUMED]
10. **Rule combination:** every rule is evaluated; the strictest verdict wins (BLOCK over ASK over
    ALLOW). The first rule in evaluation order that produced that verdict is the matched rule.
11. **Config:** `tools`, `hosts` (exact or `*.suffix`), `paths.workdir`, `paths.allow`
    (directory prefixes), and `sensitive.<class>` = `ask|block` (default `ask`) for the classes
    `proc_environ`, `ssh`, `dotenv`, `metadata`. Unknown keys are an error. `-config` is required.
12. **Path scope** applies to structured path arguments only (`file_path`, `path`, ...). Shell
    command text gets sensitive-path and host checks but no scope check, because absolute paths
    like `/usr/bin/git` would make scope checks unusable. Sensitive checks cover any access, not
    only reads (a shell command cannot be classified reliably).
13. **Host mention** in the user prompt is a whole-token, case-insensitive match against
    user-role text. Mention never overrides a sensitive-class rule (metadata endpoint).
14. **Audit failure fails closed:** if the audit record cannot be queued or the writer has failed,
    an ALLOW becomes BLOCK (`fail-closed:audit`).
15. **OpenTelemetry:** API + SDK + stdout trace exporter only. OTLP is not added (optional in
    decision 4); it can follow later.
16. **Audit file:** JSONL, mode 0600, append-only, one writer goroutine.

17. **Required keys and tool patterns:** `tools`, `hosts`, `paths.allow` are mandatory (empty list
    allows nothing). Tool patterns may end in `*` (prefix of 3+ characters) for MCP names.
18. **Host detection is heuristic:** URLs, `user@host:`, network-command arguments, and tokens
    whose last label is in a built-in common-TLD list.

## Deferred (not in scope)
- Optional judge model for ambiguous calls (outside the four phases).
- Approval endpoint or CLI for ASK.

## Draft threat model (to be refined in README)
Defends against (best effort): a model, steered by prompt injection or error, emitting a tool
call that uses an undeclared tool, reaches an unexpected host, or reads well-known secret
locations.

Does NOT protect against:
- A harness or local process that bypasses the proxy (direct API access, different base URL).
- Obfuscated arguments: base64, shell variable or command substitution, globbing, encoded URLs.
  Shell command parsing is heuristic.
- Exfiltration through an allowlisted host, or through DNS.
- Symlink or TOCTOU tricks: the path is checked at proxy time, not at execution time.
- Tool results and MCP servers acting on their own, since only model-emitted calls are inspected.
- Harmful text in model replies (only tool calls are policed).
- A compromised local machine, the proxy host, or the config/audit files.
- Anything the user explicitly approves.
- Upstream API compromise. Request-side injection is only mitigated, not detected.
