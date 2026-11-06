# Step 2c: hardening (deferred review findings 4 and 5)

Scope: bound the resources an unauthenticated local client or a slow upstream can consume.
Standard library only. Fixes arising from the per-piece cross-reviews are in the addendum at the end.

## Files touched
- `internal/proxy/proxy.go` (config fields, defaults, semaphore, deadline, transport cap)
- `internal/proxy/listener.go` (new: `LimitListener`)
- `cmd/agent-guard/main.go` (flags, wraps listener, `MaxHeaderBytes`)
- Tests: `internal/proxy/hardening_test.go` (new), `internal/proxy/listener_test.go` (new),
  `cmd/agent-guard/main_test.go` only if flag validation is extracted (otherwise none)

## Changes
1. **Absolute response deadline (finding 5).** New `Config.MaxResponseDuration` (default 10
   minutes, flag `-max-response`). `ServeHTTP` derives the upstream context with
   `context.WithTimeout`, so the deadline covers waiting for headers, a non-stream body and a
   whole stream. Expiry cancels the upstream request. Stream: the existing violation path sends
   an SSE `error` event and drops held bytes. JSON and pass-through: 502. The idle timeout
   stays; this is an upper bound on top of it (a trickling upstream can no longer reset it
   forever). The deadline bounds time spent reading the upstream. After it fires, only data
   already buffered is written, and each write is still bounded by `WriteTimeout` and the
   existing body caps.
2. **In-flight request cap (finding 4).** New `Config.MaxInflightRequests` (default 64, flag
   `-max-inflight`). `Proxy` owns a buffered channel used as a semaphore. A matching request
   acquires a slot without blocking before reading its body and releases it on return. When
   full, the proxy answers 503 with a JSON error immediately (fail closed, no queueing, no
   upstream call). 404 routes do not take a slot.
3. **Upstream connection cap.** The cloned `http.Transport` gets
   `MaxConnsPerHost = MaxInflightRequests`, so upstream connections can never exceed the
   in-flight cap.
4. **Accepted-connection cap (finding 4).** New `proxy.LimitListener(ln, n) (net.Listener,
   error)`: `n <= 0` is an error. The wrapper's `Accept` selects on a buffered-channel slot and a
   `done` channel (closed once by `Close`), so a full cap never blocks shutdown (`Accept` then
   returns `net.ErrClosed`). The slot is released on any underlying `Accept` error. The returned
   conn releases its slot exactly once on `Close` (`sync.Once`). `main` wraps the listener with it (flag `-max-conns`, default 256). Server
   `MaxHeaderBytes` is set to 64 KiB.

## Ownership
- The two semaphores are channels owned by `Proxy` and `limitListener`. Slots are acquired and
  released only by the goroutine handling that request or connection, and a connection's slot
  is released by whichever goroutine closes it first, guarded by `sync.Once`. No mutex, no map.
- `Config` stays immutable after `New`.

## Tests (loopback listener on port 0, raw `net.Dial` with deadlines, no sleeps)
- Absolute deadline, stream: upstream sends a ping on a ticker (stopped, and the handler exits
  on `r.Context().Done()`, with a timed wait for the exit) so the idle timeout never fires; with `MaxResponseDuration` short the client receives an `error` event and no
  `message_stop`.
- Absolute deadline, JSON: upstream sends headers then trickles; client gets 502.
- Absolute deadline, pass-through: a trickling `count_tokens` response gives 502.
- `MaxHeaderBytes`: a raw request with a header far over the limit is rejected (431) and the
  connection ends; the upstream is never called.
- Inflight cap: with `MaxInflightRequests=1` and the first request parked on a gate channel,
  a second request gets 503 immediately; after the first is released a third succeeds. 404
  requests do not consume a slot.
- Slot release: slots are returned after success, rejection and client disconnect (a loop of
  requests larger than the cap all succeed).
- LimitListener: with n=1, the second `Accept` unblocks only after the first conn is closed;
  double `Close` releases once (a third `Accept` still blocks until a real second close);
  `Close` while the cap is full unblocks a pending `Accept` with an error; `n <= 0` is
  rejected; `http.Server.Shutdown` completes while the cap is full.
- Config defaults: zero values take the documented defaults.

## Addendum: fixes from the per-piece cross-reviews
Files touched: `internal/proxy/guard.go`, `stream.go`, `nonstream.go`, `cmd/agent-guard/main.go`,
and tests in `guard_test.go`, `stream_test.go`, `proxy_test.go`, `helpers_test.go`.
- **A1 guard race.** After receiving a result, `guard.decide` re-checks `dctx.Err()`; a result
  that arrives after the deadline or cancellation is BLOCK `fail-closed:timeout`. Test: already
  cancelled context with a decider returning ALLOW gives BLOCK.
- **A2 SSE event name.** `sseReader` records the `event:` name. For any event that has data, the
  name must equal the JSON `type`; a mismatch or a missing name is a violation (the real API
  always sends both). Tests: name/type mismatch (including a tool block hidden under
  `event: ping`) and a missing name.
- **A3 cumulative stream bytes.** `streamer` sums the size of every raw upstream event as it is
  read, before any filtering or replacement; more than `MaxBody` is a violation (reuses the
  existing cap, no new setting). Tests: small `MaxBody` with plain text; an evasive stream of
  many small blocked tool calls whose total exceeds `MaxBody`.
- **A6 early deadline for rejected requests.** `ServeHTTP` sets the read deadline
  (`BodyTimeout`) before routing. 404, 503 and 413 responses carry `Connection: close`, so the
  server does not drain an unread body. Tests: a 404 and a 503 request with a never-completed
  body each get their response and the connection then ends within the deadline.
- **A7 testable entrypoint.** `cmd/agent-guard` gets `parseOptions(args)` and
  `newServer(opts) (*http.Server, net.Listener, error)`; `main` only calls them. Test builds the
  real server on `127.0.0.1:0`: oversized header gives 431, `GET /` gives 404 through the proxy,
  and with `-max-conns 1` a second connection is served after the first closes.
- **T5** `LimitListener` test with a scripted listener whose `Accept` fails once after a slot is
  taken; the next `Accept` still succeeds (slot released).
- **T6** absolute-deadline stream test starts a tool call containing a sentinel and keeps the
  stream alive; after expiry the sentinel and tool events are absent.
- **T4 refinement:** `MaxBody` and `MaxResponseDuration` are set far above the data volume and
  test length, a `slog` handler writes to a mutex-guarded buffer, and the test asserts the
  "client write failed" line, so the write deadline (not another limit) ended the handler.
- **A4 stop_reason strictness.** In `rewriteMessage`, a present `stop_reason` that is not a
  string or null is an error (502). Absent is allowed. Test.
- **A5 SIGTERM.** `main` shuts down on `SIGTERM` as well as `os.Interrupt`.
- **T1** guard timeout/overload tests run `decide` in a goroutine and wait with `recv`.
- **T2** the request-recording channel in `TestRequestHandling` is sent to without blocking.
- **T3** `BodyTimeout` test: a raw request with `Content-Length: 100` and 5 bytes sent; the
  proxy answers 400 within the deadline and the upstream is never called.
- **T4** streaming write deadline test: upstream streams large text events until its context
  ends; the client never reads; a handler wrapper signals completion on a channel, awaited with
  a timeout.
- Not changed (disagreed): validation inside `newGuard` (the exported `New` already defaults
  non-positive values).

## Addendum 2: fixes from the cross-review of the fix and hardening commits
- **B1** `capReader` under the SSE scanner counts every upstream byte (blank lines and comments
  included) against `MaxBody`; it replaces the per-event total from A3. Test: blank-line flood.
- **B2** The SSE `event:` value is parsed per spec (at most one leading space removed, nothing
  else trimmed). Tests: trailing tab, two leading spaces.
- **B3** `main` logs the upstream scheme and host only. **B4** `newServer` closes the listener if
  `LimitListener` fails.

## Check
`bash scripts/check.sh`, per stage.
