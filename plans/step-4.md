# Step 4 (Phase 4): audit log and OpenTelemetry

New dependencies (approved in REQUIREMENTS decision 4, scoped by decision 15): `go.opentelemetry.io/otel`
(+ `otel/trace`), `go.opentelemetry.io/otel/sdk`, `go.opentelemetry.io/otel/exporters/stdout/stdouttrace`.
No OTLP exporter. Everything else is the standard library.

## Files
- `internal/policy/observe.go`: `Event`, `Observer`, `SafeID` (the seam between proxy and sinks).
- `internal/proxy/proxy.go`, `nonstream.go`, `stream.go`: `Config.Observer`; a single `p.decide`
  helper that times the decision, handles the call-count limit, notifies the observer, and fails
  closed on audit failure. All three call sites use it, so no decision bypasses observation.
- `internal/audit/audit.go`: JSONL writer (`Open`, `NewWriter`, `Observe`, `Close`), `Record`.
- `internal/audit/redact.go`: argument preview with redaction and truncation.
- `internal/telemetry/telemetry.go`: `NewObserver(trace.TracerProvider)`, `Setup(mode, io.Writer)`.
- `cmd/agent-guard/main.go`: `-audit-log` (required) and `-otel none|stdout`; ordered shutdown.
- Tests in each package; an end-to-end test in `cmd/agent-guard`.

## Types
```go
type Event struct {
    Call       policy.ToolCall   // ID, Name, Input (raw)
    Decision   policy.Decision
    Start, End time.Time
    Stream     bool
}
type Observer interface { Observe(ctx context.Context, e Event) error }
```
`Config.Audit` is **required** (`proxy.New` rejects nil, so an un-audited proxy cannot start).
`Config.Telemetry` is optional. Order inside `p.decide`: (1) decide, (2) `Audit.Observe`; if it
returns an error and the verdict is ALLOW the verdict becomes BLOCK `fail-closed:audit`, (3)
`Telemetry.Observe` receives the final decision (errors are logged, never change the verdict).
Observers run with a context detached from request cancellation and bounded by `DecideTimeout`,
so a client disconnect cannot suppress the record. Observers must not block: the audit enqueue
is non-blocking and telemetry uses a bounded batch processor that drops when full. There is no
generic timeout wrapper.

## Audit record (one JSON object per line)
`ts` (UTC RFC 3339 nano), `tool`, `tool_use_id`, `decision`, `rule`, `reason`, `args_sha256`
(hex of the raw input bytes), `args_preview` (redacted, at most 256 bytes, cut on a rune
boundary), `latency_ms`, `stream`. Never headers, API keys, or full bodies.
`tool` and `tool_use_id` are sanitized to `[A-Za-z0-9_.:/-]`, at most 128 bytes. Non-JSON input
gets the fixed preview `[unparseable]`. `-audit-preview=false` records only the hash. Besides
known formats, any word of 20+ characters that mixes letters and digits with Shannon entropy of
3.5+ bits per character is replaced. Redaction is best effort and is documented as such.
Redaction: object keys that look secret (key, token, secret, password, passwd, authorization,
credential, cookie, bearer) have their values replaced; token patterns (sk-..., ghp_/gho_/ghs_/
github_pat_, AKIA..., xox?-, JWT, `Bearer ...`), URL userinfo and `NAME_KEY=value` shell
assignments are replaced inside strings. `reason` gets the same string redaction.
File: opened append-only with mode 0600. A symlink or non-regular file is rejected, and so is an
existing file whose mode allows group or other access (it is not silently chmod-ed).

## Ownership
- The audit `Logger` has one writer goroutine that owns the file and encoder. Callers only send
  `Record` values on a bounded channel (default 4096) with a non-blocking send; a full queue is
  an error (never blocks a request). `closed` is guarded by a `sync.RWMutex` that protects only
  the lifecycle flag and the channel close; the queue itself is owned by the writer. `Observe`
  holds the read lock across its non-blocking send, `Close` takes the write lock, sets `closed`,
  closes the channel (no sender can be mid-send), then waits for the writer to drain and exit.
  `Close(ctx)` returns `ctx.Err()` if the writer is blocked past the deadline; the blocked writer
  goroutine is abandoned (the process is shutting down) and the failure is reported.
- On a write error the writer sets an atomic `failed` flag, keeps draining (discarding) so the
  queue cannot fill, and every later `Observe` returns an error.
- The OTel tracer provider is owned by `main`; the observer only holds a `trace.Tracer`.
- `Event` values are copied; `Input` is read-only (the audit hashes and previews it before queueing).

## Spans
One span `agent_guard.decide` per decision, backdated to `Event.Start` and ended at `Event.End`:
attributes `agent_guard.decision`, `agent_guard.rule`, `agent_guard.tool`,
`agent_guard.tool_use_id`, `agent_guard.latency_ms`, `agent_guard.stream`. No arguments, no
reason text (it may contain values). `-otel stdout` writes spans to stderr; `-otel none` uses the
no-op provider.

## Shutdown order
`http.Server.Shutdown` (in-flight decisions finish) then `audit.Close(ctx)` (drains) then the
tracer provider's `Shutdown(ctx)` (flushes spans), all under one shared deadline.

## Tests (loopback listener on port 0, no sleeps, every wait has a timeout)
- audit: fields and JSON shape; hash; redaction table (keys, token patterns, URL userinfo,
  env assignments, nested, non-JSON); rune-safe truncation; file mode 0600; Close drains
  everything queued; Observe after Close errors; full queue returns an error without blocking
  (writer gated on a channel); write failure makes later Observe fail; concurrent Observe under
  `-race` loses nothing; Open on an unwritable path, a symlink, a directory and a pre-existing
  0644 file all fail; Close with a blocked writer returns the context error; unknown-format
  secrets are redacted by the entropy rule; tool/id sanitizing; `-audit-preview=false`.
- telemetry: in-memory exporter sees one span per event with name, attributes, backdated
  start/end; no argument or reason text in attributes; `Setup` modes (`none`, `stdout`,
  invalid).
- proxy: `New` rejects a nil Audit observer; observer sees every decision in stream and non-stream (allow, block, ask, guard
  timeout, call-limit); latency non-negative; failing observer turns ALLOW into BLOCK
  `fail-closed:audit` (call replaced) and leaves BLOCK/ASK alone; observer still called when the
  client has gone (detached context).
- main: parse `-audit-log`/`-otel`; end to end writes real JSONL with the expected records and a
  planted secret absent from the file; unwritable audit path refuses to start.

## Check
`bash scripts/check.sh`, per stage.

## Addendum: cross-review outcomes
- `Setup("stdout", nil)` is rejected (a nil writer would panic the exporter later).
- Tool names, tool_use ids and rule names go through `audit.RedactID` (character allow-list, then
  credential-shape redaction) before they are recorded or exported.
- Accepted limit: an `io.Writer` that blocks cannot be interrupted, so a stuck stdout/stderr sink
  makes the batch exporter drop spans once its bounded queue fills; shutdown honours its context.
- Test fixtures that look like credentials are assembled at run time, so no secret-shaped literal
  exists in the repository (a secret scan is part of publishing).
- **Acknowledged writes.** `Observe` waits (bounded by its context, i.e. the decision timeout)
  for the writer's answer, so an ALLOW is only released after its record was written; a write
  error or timeout turns it into BLOCK `fail-closed:audit`. This replaces the "return once
  queued" design in the first draft of this plan.
- `Open` creates new files with `O_EXCL`, opens existing ones with `O_NOFOLLOW|O_NONBLOCK` and
  checks the opened file (regular, no group/other access). `Close` closes the destination once
  and closes it early if the writer is stuck past the deadline.
- Preview is skipped (placeholder) for inputs over 64 KiB; more patterns (Basic, `--password x`,
  `curl -u`).
- `main` stops the server (force-closing after 10 s), then drains sinks under a fresh 10 s
  deadline, including after an unexpected `Serve` failure.
