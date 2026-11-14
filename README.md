# agent-guard

A small local policy proxy that sits between a coding agent and its model API. It reads each
model response, checks every **tool call** in it against your policy, and replaces the calls the
policy does not allow *before the agent harness can run them*. Every decision is written to an
audit log and, if you enable it (`-otel stdout`), emitted as an OpenTelemetry span.

```
agent (Claude Code) ──HTTP──▶ agent-guard (127.0.0.1) ──HTTPS──▶ api.anthropic.com
                                   │  inspects each tool_use block
                                   ├─▶ ALLOW  passes through unchanged
                                   ├─▶ ASK    replaced by a "requires approval" notice
                                   └─▶ BLOCK  replaced by a "blocked by policy" notice
```

Written in Go. Beyond the standard library it uses `gopkg.in/yaml.v3` and OpenTelemetry (API,
SDK and the stdout exporter), plus their transitive modules. MIT licensed.

> **Read the [threat model](#threat-model) before relying on this.** agent-guard reduces the
> damage a misled model can do. It is not a sandbox and it does not stop a determined attacker.

## Status

Pre-1.0. The behaviour described here is covered by automated tests that run the real code over
real loopback sockets against fake upstreams, including the documented Anthropic streaming event
format. It has also been run against the **live Anthropic API** with a small model, streaming and
non-streaming (`scripts/live-test.sh`, 17 checks), and with a **real Claude Code session**
(`scripts/live-claude-test.sh`, 7 checks, Claude Code 2.1.319): allowed, asked and blocked calls,
a response mixing allowed and blocked calls, and the API key staying out of the logs.

That is still narrow: one small model, Claude Code in headless mode (`-p`) with only the `Read` and
`Bash` tools, short sessions. The interactive interface, other tools (`Write`, `Edit`, `WebFetch`,
sub-agents, MCP), extended thinking and long sessions have not been tried, so expect rough edges.

## What it supports

- **Anthropic Messages API only**: `POST /v1/messages`, streaming and non-streaming.
  `POST /v1/messages/count_tokens` is forwarded without inspection. Every other path returns 404.
- **Not supported:** Codex and any OpenAI-style agent (chat completions or responses APIs). They
  use a different protocol that is not implemented, so they are not protected.
- Policy in YAML: allowed tools, allowed hosts, path scopes, and how to treat sensitive
  locations (see [docs/policy.md](docs/policy.md)). Optional named profiles, selected by the
  `X-Agent-Guard-Identity` header. Without that map every caller shares one policy. With it, a
  missing or unknown identity is denied.

## Quick start

Requires Go 1.26.11 or newer.

```sh
go build -o agent-guard ./cmd/agent-guard
cp examples/policy.yaml policy.yaml            # then edit it: workdir, paths, tools, hosts
mkdir -p -m 700 ~/.agent-guard                 # the proxy does not create directories
./agent-guard -config policy.yaml -audit-log ~/.agent-guard/audit.jsonl
```

In another terminal, point your agent at the proxy:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

The proxy refuses to start unless the policy is valid and the audit log can be opened privately.
It logs `msg=listening` to stderr when ready.

**Your first policy will be wrong.** The tool names in `examples/policy.yaml` are a starting point,
and an agent may use tools that are not listed (for example a to-do tool). Those calls are blocked
with `tool-not-declared`. Every decision, including blocked ones, is in the audit log, so run
your agent, then list what it tried:

```sh
jq -r '[.decision, .tool, .rule] | @tsv' ~/.agent-guard/audit.jsonl | sort | uniq -c
```

and add the tools, hosts and paths you actually want to allow. More recipes are in
[docs/operations.md](docs/operations.md#audit-log).

## How decisions work

Every tool call gets **ALLOW**, **BLOCK** or **ASK**. All rules are evaluated and the strictest
verdict wins (BLOCK over ASK over ALLOW).

| Rule | Verdict |
|------|---------|
| `egress:canary` / `egress:sensitive:<class>`: configured canary or sensitive path/host classification on an egress channel (any extracted host, or a message/forum-style tool) | BLOCK |
| `tool-not-declared`: the tool is not in `tools` | BLOCK |
| `host-not-allowed`: a host in the call is not in `hosts` and not mentioned in the user's own messages | BLOCK |
| `path-out-of-scope`: a structured path argument (such as `file_path`) is outside `paths.allow` | BLOCK |
| `sensitive:<class>`: `/proc/<pid>/environ`, any `.ssh` path, `.env` and `.env.*` files, the cloud metadata endpoint | ASK by default; `block` if you configure it |
| none of the above | ALLOW |

What the agent sees instead of a call that was not allowed:

- BLOCK: `[agent-guard] A tool call was blocked by policy (rule: <rule>).`
- ASK: `[agent-guard] A tool call requires approval and was not executed (rule: <rule>). Ask the user to approve it.`

The notice never repeats the tool name or its arguments. If every tool call in a response was
replaced, a `stop_reason` of `tool_use` becomes `end_turn`, so the harness does not wait for
results that will never come.

**ASK is a notice, not an approval flow.** The call is not executed and nothing waits for you.
There is no out-of-band approval channel. What that means for an unattended run, and a proposed
deny-on-timeout flow that is not built, is in [docs/ask-verdict.md](docs/ask-verdict.md).

**What happens next depends on the rest of the response** (observed with Claude Code):

- If *every* tool call in a response is replaced, the turn ends: the notice is shown as the
  assistant's final message, and the model does not get to react until your next message.
- If at least one call in the response is allowed, the agent runs it, and the notice sits in the
  same message, so the model sees it on its next step. In testing it reported the block accurately
  and did not try to work around it.

**Halt.** `-halt-file` is a text file the proxy reads at the start of every tool-call decision.
One mutex owns that state. There is no poll loop. `running` lets the policy run. `halted`, a
missing file, or anything the proxy cannot parse refuses every tool call. The worst-case time
from a completed write of that file to the first blocked call is the wait until the next
decision starts, plus one file read. A decision already inside the rules engine is not
interrupted. Halt, resume, and each refusal are audit lines. Details are in
[docs/operations.md](docs/operations.md#halt).

**Fail closed.** Anything unexpected blocks the call: a policy error, tool input that cannot be
parsed, a decision that takes too long, a malformed or oversized upstream response, an SSE event
whose name disagrees with its payload, too many tool calls in one response, or a failure to write
the audit record. An ALLOW is released only after its audit record has been *written*; if the
write fails or does not finish within the decision timeout, the call is blocked
(`fail-closed:audit`).

## Documentation

| Document | What is in it |
|----------|---------------|
| [docs/policy.md](docs/policy.md) | Every policy key, exactly how hosts, paths and sensitive locations are detected and matched, and how to answer "why was this blocked?" |
| [docs/operations.md](docs/operations.md) | Flags, fixed limits, HTTP behaviour, streaming, the audit log format and recipes, OpenTelemetry, shutdown, troubleshooting |
| [docs/development.md](docs/development.md) | Building, testing, repository layout, conventions |
| [docs/ask-verdict.md](docs/ask-verdict.md) | What Ask does today, the gaps, and a proposed deny-on-timeout for unattended runs |
| [SECURITY.md](SECURITY.md) | Scope and how to report a vulnerability |
| [examples/policy.yaml](examples/policy.yaml) | A commented starting policy (tested to load) |
| [REQUIREMENTS.md](REQUIREMENTS.md), [plans/](plans/) | Requirements, design decisions and the design history |

## Threat model

### What it is for

A coding agent can be steered by a prompt injection (a poisoned web page, issue, dependency
README or tool result) or can simply make a mistake. agent-guard puts a policy check on the
model's tool calls: undeclared tools, unexpected network destinations, files outside the project,
and the usual credential locations.

### What it does NOT protect against

1. **A client that does not use the proxy.** Anything that talks to the API directly, uses another
   base URL, or runs outside the agent is not covered. The proxy has **no authentication**: any
   local process that can reach its port can use it, and nothing enforces that `-listen` is a
   loopback address.
2. **Anything that is not a `tool_use` block in a Messages response.** Server-side tools
   (`server_tool_use`), MCP servers acting on their own, the harness's own file and network
   activity, and text in the model's replies are not inspected. Other protocols (OpenAI chat or
   responses, Codex) are not handled at all.
3. **Shell obfuscation.** Command text is parsed with heuristics, not a shell parser. The guard
   sees tool arguments, not packets: it does not watch DNS, sockets, or bytes on the wire. A
   destination that never appears in the arguments is not checked. Variable
   expansion, command substitution, base64 or other encodings, globbing, `eval`, here-documents,
   aliases, and scripts the agent writes and then runs can all hide a host or a path. Tokenizing
   is not quote-aware, only `curl` and `wget` option values are understood, and unusual
   top-level domains are only recognised after known network commands. Host detection can both
   miss destinations (false negatives) and flag file names (false positives); the details are in
   [docs/policy.md](docs/policy.md#what-the-host-detection-cannot-do).
4. **Path tricks.** Paths are cleaned lexically. Symlinks, hard links, mounts, case-insensitive
   filesystems and time-of-check/time-of-use changes are not handled. Path *scopes* apply only to
   structured arguments such as `file_path`; shell text gets the sensitive-location checks but no
   scope check. Relative paths are assumed to be relative to `paths.workdir`.
5. **Exfiltration through allowed channels.** An allowlisted host can still receive data (a public
   gist, an issue comment, a package upload). DNS lookups and other covert channels are not
   examined. A host the user names in any message becomes allowed, including text the user pasted
   from an untrusted source.
6. **Approval.** ASK does not wait for you. The model may retry in another form, and a user or
   harness that approves everything has bypassed the control.
7. **A compromised machine, proxy host, policy file or audit file.** The audit log is plain
   append-only text with no integrity protection, and the proxy sees your API key in transit.
   Traffic from the agent to the proxy is plain HTTP on loopback.
8. **A malicious upstream.** A compromised API endpoint is outside what this tool can defend.
   Prompt injection is mitigated by blocking its effects, not detected.
9. **Availability.** Failing closed means a broken policy, a full disk or a slow sink blocks the
   agent (each decision waits for its audit write, up to the decision timeout). Resource limits
   are best effort, not a denial-of-service defence.
10. **Secrets in the audit log.** Argument previews are redacted heuristically and can leak
    secrets that do not look like secrets. Use `-audit-preview=false` to record hashes only.
11. **Lessons from BishopFox's Claude sandbox write-up.** An agent with process-level access can
    read process memory and create network interfaces. agent-guard inspects model `tool_use`
    blocks only; it is **not a sandbox** and does not confine the harness or the OS. See
    [BishopFox, “A Journey into Claude's Sandbox”](https://bishopfox.com/blog/journey-into-claudes-sandbox)
    (TLDR InfoSec 2026-11-09).

## Architecture

```
cmd/agent-guard       flags, wiring, graceful shutdown
internal/proxy        reverse proxy, SSE rewriting, limits, fail-closed guard, connection cap
internal/rules        YAML policy engine (immutable after load; safe for concurrent use)
internal/audit        JSONL writer: one writer goroutine owns the file
internal/telemetry    one OpenTelemetry span per decision
internal/policy       shared types: Verdict, Decision, Decider, Observer
internal/halt         halt-file switch; one mutex owns the state
```

Shared state has exactly one owner. The policy engine is immutable; the audit file belongs to one
writer goroutine fed by a bounded channel; the halt switch is one mutex; the in-flight and
connection caps are channel semaphores; per-request parsing state belongs to that request's
goroutine.

## License

MIT. See [LICENSE](LICENSE).
