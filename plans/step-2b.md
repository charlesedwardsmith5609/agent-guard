# Step 2b: fixes from the Phase 2 cross-model review

Scope: review findings 1, 2, 3, 6, 7, 8 only. Findings 4 (connection caps) and 5 (absolute
response deadline) are deferred to a later step. Standard library only; `go.mod` unchanged
except the already-approved toolchain bump.

## Changes
Files touched: `internal/proxy/stream.go`, `internal/proxy/proxy.go`, and tests in
`internal/proxy/stream_test.go`, `proxy_test.go`.

1. **Start-event input (stream).** Parse `content_block.input` on a `tool_use`
   `content_block_start`. Absent or an empty object is fine; anything else is a violation
   (fail closed: SSE `error` event, held bytes dropped, `message_stop` not forwarded).
2. **message_start content (stream).** Parse `message.content`. Absent or an empty array is
   fine; any element is a violation.
3. **Event size (stream).** `sseReader.next` enforces an aggregate cap per event
   (`maxSSEEvent` = 1 MiB, covering all lines of one event); exceeding it is a violation. The
   initial `tool_use` start event is counted against `MaxHeldBytes` (it alone exceeding the cap
   is a violation).
6. **Write deadlines everywhere.** The write deadline (`WriteTimeout`) is set before every
   `WriteHeader`/`Write`: `serveJSON`, `passThrough`, the stream headers, and proxy-generated
   JSON errors (`writeJSONError` takes the `ResponseController`).
7. **Pass-through overflow.** `passThrough` reads up to `maxPassThroughBody` (1 MiB constant;
   error bodies and `count_tokens` replies are tiny, and this bounds per-request memory) plus
   one byte before sending any header. Overflow or read error returns 502 (`upstream response
   rejected`). Upstream headers are copied only after successful buffering, so a rejected
   response carries no upstream headers. The body is sent with a recomputed `Content-Length`.
8. **URL copy.** `New` stores a copy of `cfg.Upstream`.

## Ownership
Unchanged from step 2. No new shared state. Per-request values stay owned by the request's
handler goroutine; the copied URL is immutable after `New`.

## Tests (loopback listener, raw `net.Dial` with deadlines, no sleeps)
- Stream violations table gains: non-empty start `input`; `message_start` with a tool block in
  `content`; one event made of many sub-limit lines; oversized start event vs `MaxHeldBytes`.
  Each asserts an `error` event, no `message_stop`, and no leaked input.
- Stream OK cases: `input: {}` and empty `message.content` still pass (existing tests).
- Pass-through: oversized `count_tokens` response and oversized non-2xx response give 502 with
  no partial body; small ones still pass through with a correct `Content-Length`.
- URL copy: mutate the caller's `*url.URL` after `New`; requests still reach the original
  upstream.
- Pass-through: an upstream that declares a longer `Content-Length` than it sends (sensitive
  prefix then close) gives 502 with no prefix; rejected responses carry no upstream sentinel
  headers (`Content-Encoding`, `Set-Cookie`).
- JSON write deadline: a client that sends a request and never reads a response larger than the
  socket buffers, with a short `WriteTimeout`; a wrapper around the handler signals completion on
  a channel and the test waits on it with a timeout. If this proves nondeterministic it is
  dropped and reported.

## Deferred (human decision)
Findings 4 (connection caps) and 5 (absolute response deadline) stay deferred to a later step.

## Check
`bash scripts/check.sh`, per stage.
