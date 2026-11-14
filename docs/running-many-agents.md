# Running many agents

agent-guard is one process. It has one listen address, one config file, one audit log, and one
halt file. This page is how to use that for more than one agent. It does not add a supervisor.

## One proxy per agent

Run a separate process for each agent.

- Give each process its own `-listen` port, `-audit-log`, and `-halt-file`.
- Point that agent at its own port (`ANTHROPIC_BASE_URL`, or the equivalent for the client).
- The config file can be a copy, or the same path. The halt switch is still per process: writing
  `halted` into one file does not affect the others.
- Audit correlation is the file. You do not need the identity header for that, because each log
  belongs to one agent. Set `X-Agent-Guard-Identity` as well if you want the `agent` field inside
  the line.

Use this when a halt or a bad audit disk for one agent must not stop the others, and when you
want to delete or rotate one log without touching the rest.

## One proxy, profiles for each agent

Run one process. Put a `profiles` map and an `agents` map in the config. See
[profiles](policy.md#profiles-and-agents).

Each client sends `X-Agent-Guard-Identity` with the identity you listed. The proxy strips that
header before it forwards the request. A missing identity is denied (`profile-missing`). An
identity that is not in the map is denied (`profile-unknown`). There is no fallback profile, so
a client that forgets the header does not run as another agent.

Use this when the agents can share a fate. One process means one halt file. Setting it to
`halted` refuses every tool call from every agent on that proxy, on the next decision each of
them starts. See [Halt](operations.md#halt) for the worst-case wait.

## Audit correlation

Each tool call is one JSON line. The fields that tie a line to an agent are:

| Field | What it tells you |
|-------|-------------------|
| `agent` | The identity header, when the client sent one. Omitted when it did not |
| `profile` | The profile that applied, or `default` when the file has no profiles. Empty when the call was refused before a profile applied |
| `ts` | When the decision finished |
| `tool`, `tool_use_id` | The call inside that response. The id is not unique across agents or days |
| `rule`, `decision` | Why it was allowed, blocked, or asked |
| `args_sha256` | Hash of the raw arguments, if you still have the payload |

A shared proxy mixes every agent in one file. Filter on `agent` and `profile`. One proxy per
agent keeps that split in the filesystem instead.

OpenTelemetry, when `-otel stdout` is on, emits one span per decision. Those spans carry the
decision, rule, tool, tool-use id, latency, and whether the response was streamed. They do not
carry `agent` or `profile`. Use the audit log to correlate agents.

## Halt scope

The halt file is read by the process that was started with that `-halt-file`. It is not a
cluster-wide switch.

- Shared proxy: one file halts every agent using that process.
- One proxy per agent: halt the agent whose file you write. The others keep running.

A missing or corrupt file fails closed for that process only. It does not reach a process that
was started without `-halt-file`.

There is no fan-out. If you need every agent halted at once, write each file, or run them on one
proxy and write that one file.
