# Step 2 (Phase 2): proxy skeleton (revised after plan review)

Scope: a reverse proxy for Anthropic Messages that extracts each tool call from the response,
asks a `Decider`, and passes or replaces it. Standard library only. No YAML, no OTel, no audit
file, no real rules (Phases 3 and 4). `go.mod` gains no requirements.

## Files
- `internal/policy/policy.go`: `Verdict` (Allow/Block/Ask), `ToolCall`, `Context{UserText}`,
  `Decision{Verdict, Rule, Reason}`, `Decider` interface, `DenyAll`.
- `internal/proxy/proxy.go`: `Config`, `New`, routing, forwarding, header filtering.
- `internal/proxy/nonstream.go`: parse a JSON response and rewrite blocked `tool_use` blocks.
- `internal/proxy/stream.go`: SSE reader and rewriter.
- `internal/proxy/guard.go`: `guard.decide`: timeout, error, panic, unknown verdict, overload.
- `cmd/agent-guard/main.go`: flags, `http.Server` timeouts, graceful shutdown, deny-all decider.
- Tests in `internal/proxy/*_test.go`.

## Behaviour
- Routes: `POST /v1/messages` (inspected) and `POST /v1/messages/count_tokens` (forwarded,
  not inspected). Everything else is 404.
- Request: body read through `MaxBytesReader` (413 over `MaxBody`) under an inbound body
  deadline (`BodyTimeout`). Parse JSON (400 on failure). Collect user-role text from the whole
  conversation (string content and `text` blocks; `tool_result` excluded). Forward headers
  minus hop-by-hop; set `Accept-Encoding: identity`. Auth headers are never logged.
- Upstream status: non-2xx is passed through unmodified (bounded copy). Response headers:
  hop-by-hop removed (including names listed in `Connection`); `Content-Length`, `ETag`,
  `Content-MD5` always dropped, and `Content-Length` recomputed for rewritten JSON bodies.
- Non-stream: bounded read, parse (502 on any failure, original bytes never forwarded).
  Non-ALLOW `tool_use` blocks become `text` blocks. If no `tool_use` remains and
  `stop_reason` was `tool_use`, it becomes `end_turn`.
- Stream: non-tool events pass through live. A `tool_use` block is held until its
  `content_block_stop`, then decided. Replacement is a text block at the same index.
  `stop_reason` is rewritten in `message_delta` as above.
- Stream limits (all fail closed, ending the stream with an SSE `error` event and dropping held
  bytes): one open block at a time (overlap, duplicate or mismatched index is a violation);
  `MaxToolCalls` per response (calls beyond it are replaced with BLOCK, no decider call);
  `MaxHeldBytes` per held block; max SSE line size; invalid JSON in any event or in the
  assembled tool input; stream ending before `message_stop`.
- Timeouts: `UpstreamTimeout` (time to response headers), `StreamIdle` (no upstream body
  bytes), `DecideTimeout`, `WriteTimeout` (deadline set before every write+flush; a write error
  cancels the upstream request), `BodyTimeout` inbound, `ReadHeaderTimeout` on the server.
- Replacement text is fixed per verdict and never echoes arguments or the tool name:
  - BLOCK: `[agent-guard] A tool call was blocked by policy (rule: R).`
  - ASK: `[agent-guard] A tool call requires approval and was not executed (rule: R). Ask the
    user to approve it.`
  Rule `R` is sanitized (printable ASCII, length-capped).
- `guard.decide`: acquires a slot from a semaphore of size `MaxInflightDecisions` without
  blocking (full means BLOCK `fail-closed:overloaded`). It runs the Decider in one goroutine
  that sends its result on a buffered channel (cap 1) and releases the slot only when the
  Decider returns. Timeout, error, panic or unknown verdict gives BLOCK `fail-closed`.
  Deciders must honor `ctx`. A Decider that ignores it can only consume slots, never more than
  `MaxInflightDecisions` goroutines, after which calls fail closed.

## Ownership
- `Config`, `Proxy` and `guard` fields are immutable after `New`. The semaphore channel is the
  only shared mutable object in the proxy, and it is a channel, not a mutex.
- Per-request state (parser, held buffer, counters) is owned by that request's handler
  goroutine only.
- A `Decider` must be safe for concurrent calls. Each implementation owns its own state (the
  Phase 2 `DenyAll` has none).

## Tests
All use a loopback listener on port 0. Requests use `net.Dial` with a deadline on the
connection; every wait has a timeout; no sleeps.
- Non-stream (table): no tools; ALLOW; BLOCK; ASK; mixed; all blocked rewrites `stop_reason`;
  decider error; too many calls; malformed JSON, missing `content` and oversized all give 502;
  `Content-Length` matches the rewritten body and `ETag` is dropped.
- Stream (table): text only; ALLOW; BLOCK; ASK; mixed; split `input_json_delta`; decider error;
  too many calls. Violations (each must end with an `error` event, no `message_stop`, and no
  held bytes): malformed event, overlapping blocks, index mismatch, truncated stream, invalid
  assembled JSON, held-bytes overflow, `message_stop` while holding.
- Live delivery: text reaches the client while the upstream is gated on a channel, proving
  there is no whole-response buffering.
- Stream idle timeout: stalled upstream ends the stream with an `error` event.
- Request: user text collected and `tool_result` excluded; 400; 413; auth header and identity
  encoding reach upstream; 404 for other paths and methods; `count_tokens` forwarded; upstream
  down gives 502; upstream non-2xx passthrough; client disconnect cancels the upstream request.
- Guard: error, panic, timeout, unknown verdict, overload each give BLOCK; the Decider
  goroutine exits after timeout when it honors ctx; concurrent calls under `-race`.
- Not covered by a test: the per-write deadline for a non-reading client (kernel socket buffers
  make it nondeterministic). It is implemented and noted in the report.

## Check
`bash scripts/check.sh`, reported per stage.
