# Operations guide

## Running it

```sh
agent-guard -config policy.yaml -audit-log ~/.agent-guard/audit.jsonl
```

Point the agent at it by setting the agent's API base URL. For Claude Code:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

Your API key stays with the agent: agent-guard forwards request headers (including the key) to the
upstream unchanged and never records them.

The connection from agent-guard to the upstream uses the system certificate store and honours the
standard `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` environment variables. The connection from the agent to
agent-guard is plain HTTP, so keep `-listen` on a loopback address (the default). **Nothing enforces
that**, and there is no authentication.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-config` | *required* | Path to the [policy](policy.md) file |
| `-audit-log` | *required* | Path of the [audit log](#audit-log). Created with mode 0600. An existing file must already be a regular file with no group or other permissions, and must not be a symlink. The directory must exist. Unix only: on other systems the proxy refuses to start |
| `-audit-preview` | `true` | Include a redacted argument preview in each record. `-audit-preview=false` records only the hash |
| `-otel` | `none` | `none` or `stdout`. `stdout` writes one JSON span per decision to **stderr** |
| `-listen` | `127.0.0.1:8787` | Address to listen on |
| `-upstream` | `https://api.anthropic.com` | Upstream base URL (`http` or `https`) |
| `-max-inflight` | `64` | Requests handled at once. More get `503` immediately |
| `-max-conns` | `256` | Connections accepted at once. More wait in the operating system's queue |
| `-max-response` | `10m` | Absolute time limit for one upstream exchange, however much data keeps arriving |
| `-decide-timeout` | `5s` | Time allowed for one decision, including waiting for its audit write |
| `-upstream-timeout` | `30s` | Time to wait for the upstream's response headers |
| `-halt-file` | *unset* | Path of the halt control file. Omit it and the proxy does not halt. See [Halt](#halt) |

Flag values that are not positive, an unknown `-otel` value or a missing required flag print an
error and exit with status 2.

### Fixed limits

These are not configurable.

| Limit | Value |
|-------|-------|
| Request body | 32 MiB (`413` above this) |
| Non-streamed response body; total size of one streamed response | 32 MiB |
| Tool calls judged per response | 64 (further ones are blocked, `fail-closed:too-many-calls`) |
| Bytes held while a streamed tool call is being assembled | 1 MiB |
| One SSE line / one SSE event | 1 MiB |
| Pass-through responses (upstream errors, `count_tokens`) | 1 MiB |
| Time to read a request body | 30 s |
| Time for any single write to the agent | 30 s |
| Silence tolerated on an upstream response body | 60 s |
| Request header size | 64 KiB (`431` above this) |
| Time to read request headers | 10 s |
| Decisions running concurrently | 64 |
| Audit records queued | 4096 |
| Policy file | 1 MiB |

## What the agent experiences

### Requests and statuses

| Request | Result |
|---------|--------|
| `POST /v1/messages` | Forwarded and inspected |
| `POST /v1/messages/count_tokens` | Forwarded; response passed through uninspected |
| any other method or path | `404`, and the connection is closed |
| request body is not valid JSON, or cannot be read in time | `400` |
| request body over 32 MiB | `413` |
| more than `-max-inflight` requests in flight | `503` |
| upstream unreachable, too slow, or its response cannot be parsed or is too large | `502` with a JSON error body |
| upstream answers with a non-2xx status | passed through as is (up to 1 MiB, else `502`) |

The query string and all request headers except hop-by-hop ones are forwarded. Responses are
requested uncompressed so they can be inspected.

### Replaced tool calls

A tool call that is not allowed is replaced, at the same position, by a text block. The exact
text is in the [README](../README.md#how-decisions-work). If no tool call survives and the
`stop_reason` was `tool_use`, it is changed to `end_turn`. Consequently a response whose calls were
*all* replaced ends the agent's turn: the notice is the assistant's last message and the model only
sees it when you send the next one. A response that still contains an allowed call continues
normally, with the notice next to it in the same message.

### Streaming

Streamed responses are rewritten on the fly. Text and thinking blocks reach the agent
immediately. A `tool_use` block is **held** until it is complete, then judged, then either sent on
or replaced, so tool calls arrive slightly later than they would without the proxy. A held block
is never partly released.

If the upstream stream breaks a rule (invalid JSON, blocks out of order, an event whose `event:`
name differs from its `type`, a tool call that carries arguments in its start event, an oversized
event, a stream that ends before `message_stop`, or a stream that goes silent), the held data is
dropped and the stream ends with an SSE `error` event of type `api_error` and the message
`agent-guard: response rejected (fail closed)`.

## Halt

`-halt-file` points at a small text file. The proxy reads it under one mutex at the start of every tool-call decision. There is no background poll. One `Switch` owns the state; the rest of the proxy does not keep a halt flag.

| File contents (trimmed, case-insensitive) | Effect |
|-------------------------------------------|--------|
| `running`, `run`, or `0` | Tool calls are judged as usual |
| `halted`, `halt`, or `1` | Every tool call is replaced with a block notice (`rule: halt`) |
| anything else, including an empty file | Treated as halted (corrupt) |
| missing file, symlink, directory, or a file larger than 64 bytes | Treated as halted (unreadable or corrupt) |

A change is noticed by the next decision that starts after the write. A decision that has already entered the rules engine is not interrupted. The worst-case time from a completed write of the control file to the first blocked call is therefore the time until the next tool-call decision starts, plus one file read. That wait is not a poll interval.

Each transition (`halt` or `resume`) is one audit line (`"event":"halt"` or `"event":"resume"`, `"decision":"HALT"` or `"RESUME"`). Each refused call is its own line (`"event":"refusal"`, `"decision":"BLOCK"`, `"rule":"halt"`). The first time a process reads a halted or unreadable file, that read is recorded as `halt`. Starting already running does not write a line.

If the transition cannot be written to the audit log, the call is blocked (`fail-closed:audit`).

## Audit log

One JSON object per line, written before the call is released. This is a real record produced by
the program:

```json
{"ts":"2026-11-06T16:29:01.737178685Z","tool":"Bash","tool_use_id":"toolu_01","decision":"ASK","rule":"sensitive:dotenv","reason":"sensitive path \".env\"","args_sha256":"b6218ddedfe764104f20ea34fe9a3aa7363552a74ab3e546b5a2aadcc70d21c0","args_preview":"{\"command\":\"cat .env\"}","latency_ms":0.116753,"stream":false}
```

| Field | Meaning |
|-------|---------|
| `ts` | When the decision finished (UTC, RFC 3339) |
| `tool`, `tool_use_id` | The model's tool name and call id, reduced to letters, digits and `_ . : / -`, at most 128 bytes, with credential-shaped text removed |
| `decision` | `ALLOW`, `BLOCK` or `ASK` |
| `rule` | The rule that decided; see [policy](policy.md#why-was-this-blocked) |
| `reason` | A short explanation; may quote a host or path from the call (redacted, at most 200 bytes) |
| `args_sha256` | SHA-256 of the tool's raw input JSON, for matching a record to a payload without storing it |
| `args_preview` | Redacted, compact JSON of the input, at most 256 bytes. Omitted with `-audit-preview=false`. `[unparseable]` or `[too large to preview]` (inputs over 64 KiB) when it cannot be shown |
| `latency_ms` | How long the decision took, not including the audit write |
| `stream` | Whether the response was streamed |
| `profile` | The policy profile that applied. `default` when the file has no `profiles` map. Empty when the call was refused before a profile applied |
| `agent` | The agent identity from `X-Agent-Guard-Identity`, reduced the same way as tool names. Omitted when the request had none |
| `event` | `halt`, `resume`, or `refusal` for the halt switch. Omitted on an ordinary decision |

It never contains request headers, API keys or complete request bodies.

**Redaction is best effort.** It covers secret-looking JSON keys (`key`, `token`, `secret`,
`password`, `authorization`, `credential`, `cookie`, `bearer`, `auth`), common token formats (OpenAI,
GitHub, AWS, Slack, JWT, private-key headers), `Basic` and `Bearer` credentials, passwords in URLs,
`--password x` and similar options, `curl -u`, `NAME_KEY=value` assignments, and long mixed
letter-and-digit words. It can miss a secret that looks like none of those. Treat the file as
sensitive.

The file is append-only text. It is opened once and **not rotated** by agent-guard: to rotate,
stop it, move the file, and start it again (or use a `copytruncate` style tool). It is not
tamper-evident.

### Recipes (using `jq`)

```sh
# What did my agent try, and what happened to each kind of call?
jq -r '[.decision, .tool, .rule] | @tsv' audit.jsonl | sort | uniq -c | sort -rn

# Everything that was not allowed, with the reason
jq -r 'select(.decision != "ALLOW") | [.ts, .decision, .tool, .reason] | @tsv' audit.jsonl

# Which tools should I add to `tools:`?
jq -r 'select(.rule == "tool-not-declared") | .tool' audit.jsonl | sort | uniq -c

# Which hosts were refused?
jq -r 'select(.rule == "host-not-allowed") | .reason' audit.jsonl | sort | uniq -c

# Slowest decisions
jq -r '[.latency_ms, .tool, .rule] | @tsv' audit.jsonl | sort -rn | head
```

## OpenTelemetry

With `-otel stdout`, each decision produces one span named `agent_guard.decide`, started when the
decision began and ended when it finished, printed as JSON on stderr (mixed with the proxy's own log
lines). Attributes: `agent_guard.decision`, `agent_guard.rule`, `agent_guard.tool`,
`agent_guard.tool_use_id`, `agent_guard.latency_ms`, `agent_guard.stream`. Tool arguments and the
reason text are never attached. Spans are exported in batches through a bounded queue; if the
destination cannot keep up, spans are dropped rather than slowing the proxy. Only the stdout
exporter exists; there is no OTLP exporter.

## Logging

agent-guard logs to **stderr** in `key=value` form: startup (`msg=listening`), upstream failures,
rejected responses, decisions that failed, and audit or telemetry problems. It does not log request
or response bodies, headers or tool arguments.

## Shutdown and exit status

`SIGINT` or `SIGTERM` starts a graceful shutdown: the listener closes and in-flight requests get up
to 10 seconds to finish (remaining connections are then cut), after which the audit log is drained
and spans are flushed under a fresh 10-second limit. Exit status: `0` after a clean stop, `1` if the
proxy failed to start or something failed while stopping, `2` for bad flags.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `audit: ... has mode 644; want 0600` at start | The audit file already exists and is readable by others. Run `chmod 600` on it (agent-guard will not change permissions on a file it did not create) |
| `open ...: no such file or directory` for the audit log | The directory does not exist. Create it first |
| `config: tools, hosts and paths.allow are required` | A required key is missing; use `[]` for "none" |
| The agent keeps saying a call was blocked | Read the rule in the notice, then the record in the audit log. See [Why was this blocked?](policy.md#why-was-this-blocked) |
| Many `tool-not-declared` for tools you use | Add them to `tools` (see the recipe above) |
| `host-not-allowed` for something that is not a host | A file name or word was read as a host. The `reason` shows what. Add it to `hosts` or avoid the form; see [what host detection cannot do](policy.md#what-the-host-detection-cannot-do) |
| `503` from the proxy | More than `-max-inflight` requests at once. Raise the flag, or reduce concurrency |
| `502` from the proxy | Upstream unreachable, slow or invalid. See stderr for the cause |
| Stream ends with `agent-guard: response rejected (fail closed)` | The upstream stream broke a rule; see [Streaming](#streaming). stderr says which |
| Calls blocked with `fail-closed:audit` | The audit log cannot be written (disk full, file removed). Fix it and restart |
| A feature of the agent stops working through the proxy | It may use an endpoint other than `/v1/messages`; those return `404` |
