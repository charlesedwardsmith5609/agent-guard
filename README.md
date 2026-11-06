# agent-guard

A small local policy proxy that sits between a coding agent and its model API. It reads each
model response, inspects every **tool call** in it, and replaces the ones your policy does not
allow *before the agent harness can run them*. Every decision is written to an audit log and
emitted as an OpenTelemetry span.

```
agent (Claude Code) ──HTTP──▶ agent-guard (127.0.0.1) ──HTTPS──▶ api.anthropic.com
                                   │  inspect tool_use blocks
                                   ├─▶ ALLOW  pass through
                                   ├─▶ ASK    replace with "requires approval" text
                                   └─▶ BLOCK  replace with "blocked by policy" text
```

Go, standard library plus three small dependency groups (`gopkg.in/yaml.v3`, OpenTelemetry API
and SDK, and the OpenTelemetry stdout exporter). MIT licensed.

> **Read the [threat model](#threat-model) before relying on this.** agent-guard reduces risk
> from a misled model. It is not a sandbox, and it does not stop a determined attacker.

## What it supports today

- **Anthropic Messages API only** (`POST /v1/messages`, streaming and non-streaming).
  `count_tokens` is forwarded uninspected. **Codex and other OpenAI-style agents are not
  supported**: they speak a different protocol, which is not implemented.
- Policy in YAML: allowed tools, allowed hosts, path scopes, and sensitive-location handling.

## Quick start

```sh
go build -o agent-guard ./cmd/agent-guard
cp examples/policy.yaml policy.yaml            # edit it
mkdir -p -m 700 ~/.agent-guard                 # the proxy does not create directories
./agent-guard -config policy.yaml -audit-log ~/.agent-guard/audit.jsonl
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

The proxy refuses to start without a valid policy and a writable, private audit log.

| Flag | Default | Meaning |
|------|---------|---------|
| `-config` | required | YAML policy file |
| `-audit-log` | required | JSONL audit file (created 0600; an existing file must already be 0600). Unix only: the proxy refuses to start elsewhere |
| `-audit-preview` | `true` | include a redacted argument preview (`false` records only the hash) |
| `-otel` | `none` | `stdout` writes spans as JSON to stderr |
| `-listen` | `127.0.0.1:8787` | address to listen on. **There is no authentication**; keep it on loopback |
| `-upstream` | `https://api.anthropic.com` | upstream API |
| `-max-inflight` | 64 | concurrent requests before the proxy answers 503 |
| `-max-conns` | 256 | concurrent accepted connections |
| `-max-response` | 10m | absolute limit on one upstream exchange |
| `-decide-timeout` | 5s | per-decision timeout |
| `-upstream-timeout` | 30s | wait for upstream response headers |

## Decisions

Every tool call gets **ALLOW**, **BLOCK** or **ASK**. All rules are evaluated and the strictest
verdict wins (BLOCK over ASK over ALLOW).

| Rule | Verdict |
|------|---------|
| `tool-not-declared`: the tool is not in `tools` | BLOCK |
| `host-not-allowed`: a host in the call is not in `hosts` and not mentioned in the user's messages | BLOCK |
| `path-out-of-scope`: a structured path argument is outside `paths.allow` | BLOCK |
| `sensitive:<class>`: `/proc/<pid>/environ`, any `.ssh` path, `.env`/`.env.*`, the cloud metadata endpoint | ASK by default, `block` if configured |
| otherwise | ALLOW |

**ASK is a notice, not an approval flow.** The harness receives text saying the call "requires
approval" and was not executed. The model, or you, can then react. There is no out-of-band
approval channel.

**Host mentions.** A host that appears as a whole token in a *user-role* message anywhere in
the conversation counts as allowed. Tool results are never consulted. The metadata endpoint is
never authorised by a mention.

### Fail closed

Anything unexpected blocks the call: policy error, unparseable tool input, decision timeout,
a panicking or overloaded decider, a malformed upstream response, an oversized stream, an SSE
event whose name disagrees with its payload, a tool-call limit, or a failure to write the audit
record (an ALLOW is only released after its audit record has been *written*; if the write fails
or does not finish within the decision timeout, it becomes BLOCK).

## Audit log

One JSON object per line:

```json
{"ts":"2026-11-06T12:00:00.0125Z","tool":"Bash","tool_use_id":"toolu_01","decision":"ASK",
 "rule":"sensitive:dotenv","reason":"sensitive path \".env\"",
 "args_sha256":"…","args_preview":"{\"command\":\"cat .env\"}","latency_ms":0.4,"stream":false}
```

It never contains headers, API keys or full request bodies. `args_preview` is capped at 256
bytes (inputs over 64 KiB get a placeholder) and redacted on a best-effort basis (secret-looking
keys, common token formats, Basic/Bearer credentials, URL credentials, `--password x`-style
options, `curl -u`, `NAME_KEY=value` assignments, and long high-entropy words). **Redaction can miss
secrets**; use `-audit-preview=false` if that matters, and protect the file. The log is not
tamper-evident.

## OpenTelemetry

One span `agent_guard.decide` per decision, with attributes `agent_guard.decision`, `.rule`,
`.tool`, `.tool_use_id`, `.latency_ms` and `.stream`. Arguments and reason text are never
attached. Only the stdout exporter is built in; OTLP is not included.

## Threat model

### What it is for

A coding agent can be steered by a prompt injection (a poisoned web page, issue, dependency
README or tool result) or just make a mistake. agent-guard puts a policy check on the model's
tool calls: undeclared tools, unexpected network destinations, files outside the project, and
the usual credential locations.

### What it does NOT protect against

Be plain about these:

1. **A client that does not use the proxy.** Anything that talks to the API directly, uses
   another base URL, or runs outside the agent is not covered. The proxy has **no
   authentication**; any local process that can reach the port can use it.
2. **Anything that is not a `tool_use` block in a Messages response.** Server-side tools
   (`server_tool_use`), MCP servers acting on their own, the harness's own file or network
   activity, and text in the model's replies are not inspected. Other protocols (OpenAI chat
   or responses, Codex) are not handled at all.
3. **Shell obfuscation.** Command text is parsed with heuristics, not a shell parser. Variable
   expansion, command substitution, base64 or other encodings, globbing, `eval`, here-documents,
   aliases, and scripts the agent writes and then runs can all hide a host or path. Tokenizing
   is not quote-aware; only `curl` and `wget` option values are understood; unusual top-level
   domains are only recognised after network commands. Host detection can both miss
   destinations (false negatives) and flag file names (false positives).
4. **Path tricks.** Paths are cleaned lexically. Symlinks, hard links, mounts, case-insensitive
   filesystems and time-of-check/time-of-use changes are not handled. Path *scopes* apply only
   to structured arguments such as `file_path`; shell text gets the sensitive-location checks
   but no scope check. Relative paths are assumed to be relative to `paths.workdir`.
5. **Exfiltration through allowed channels.** An allowlisted host can still receive data
   (a public gist, an issue comment, a package upload). DNS lookups and other covert channels
   are not examined. Any host the user happens to name in a message becomes allowed, including
   text pasted from an untrusted source.
6. **Approval.** ASK does not wait for you. The model may retry in another form, and a harness
   or user that approves anything has bypassed the control.
7. **A compromised machine, proxy host, config, or audit file.** The audit log is plain
   append-only text with no integrity protection, and the proxy sees your API key in transit.
   Client-to-proxy traffic is plain HTTP on loopback.
8. **The upstream.** A compromised or malicious API endpoint is outside the model. Prompt
   injection is mitigated by blocking its effects, not detected.
9. **Availability.** Fail-closed means a broken policy, full disk or slow sink blocks the
   agent (each decision waits for its audit write, up to the decision timeout). Resource limits
   are best effort, not a denial-of-service defence. A telemetry sink that blocks inside
   `Write` cannot be interrupted; its bounded queue then drops spans.
10. **Redaction.** Audit previews can leak secrets that do not look like secrets.

### Known limits of the host and path heuristics

See `plans/step-3.md` ("Known heuristic limits") for the list found by review, including
option handling for commands other than `curl`/`wget`, URLs inside request data being counted
as hosts, and remote file names after `ssh host` being read as hosts.

## Architecture and ownership

```
cmd/agent-guard       flags, wiring, graceful shutdown
internal/proxy        reverse proxy, SSE rewriting, limits, fail-closed guard, LimitListener
internal/rules        YAML policy engine (immutable after load, safe for concurrent use)
internal/audit        JSONL writer: one writer goroutine owns the file
internal/telemetry    OpenTelemetry span per decision
internal/policy       shared types: Verdict, Decision, Decider, Observer
```

Shared state has exactly one owner: the policy engine is immutable; the audit file belongs to
one writer goroutine fed by a bounded channel; the in-flight and connection caps are channel
semaphores; per-request parsing state belongs to that request's goroutine.

## Development

```sh
bash scripts/check.sh      # gofmt, go vet, govulncheck, go test -race -count=1
```

Tests use real loopback listeners and raw TCP connections with deadlines. The design history
(requirements, plans and review notes) is in `REQUIREMENTS.md` and `plans/`.

## License

MIT. See [LICENSE](LICENSE).
