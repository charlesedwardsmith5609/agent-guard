# Go network service: concurrency and hardening

Load before writing or reviewing any long-lived TCP service. General guidance, not a solution
to any specific problem.

## 1. Ownership

- Every piece of shared mutable state has exactly one owner. Prefer one goroutine that owns the
  state and receives commands over channels. A `sync.Mutex` is fine for small, simple state; say
  which you chose and why. Do not mix both for the same data.
- Other goroutines never read the owner's maps or slices directly. They send a request, or the
  owner hands out a copy.
- The owner must never block on a slow peer. If one blocked write can stall the owner, the
  whole service stalls.

## 2. Connection lifecycle

- Accept loop: one goroutine per accepted connection. Handle `Accept` errors; on a closed
  listener, exit cleanly.
- Per connection, separate the reader (parses input, sends commands to the owner) from the
  writer (drains a buffered outbound channel to the socket). This keeps a slow socket from
  blocking anyone else.
- **Slow consumer policy is a decision, not an accident.** When a peer's outbound buffer is full,
  either drop the message for that peer or disconnect the peer. Never block the owner on it.
  State the choice.

## 3. Shutdown and cleanup (where AI code is most often wrong)

- Only one goroutine closes a given channel, and it is the owner. "Send on closed channel"
  panics come from a second goroutine closing or sending after removal.
- On disconnect: the reader notices the error, tells the owner, the owner removes the peer and
  closes that peer's outbound channel, the writer sees the close and exits, and the connection
  is closed once (use `sync.Once` if more than one path can close it).
- Every goroutine you start needs a known exit path. If you cannot say how it ends, it leaks.
- Support graceful shutdown with a `context.Context` or a `done` channel, and close the listener
  to stop the accept loop.

## 4. Input handling (security)

- `bufio.Scanner` defaults to a 64 KiB token limit. Set an explicit, smaller max with
  `scanner.Buffer(buf, max)` and handle `bufio.ErrTooLong` by rejecting or disconnecting. Always
  check `scanner.Err()` after the loop.
- Telnet and Windows clients send `\r\n`. Trim `\r`.
- Treat all peer input as untrusted text that will be shown on other people's terminals. Reject
  or strip control characters, especially ESC (`0x1b`), to prevent terminal escape injection.
  Validate UTF-8.
- Identifiers chosen by peers (names, handles) get an allowlist: length bounds and a character
  set. Decide case sensitivity for uniqueness. Reserve names that could impersonate the system.

## 5. Resource limits

- Idle timeout: `conn.SetReadDeadline` refreshed per read. Write deadline on every write.
- Cap concurrent connections (a buffered-channel semaphore in the accept loop), and consider a
  per-remote-address cap.
- Per-peer message rate limit. A simple token bucket with `time.Now()` is enough;
  `golang.org/x/time/rate` is an external dependency and needs approval.
- Bound every buffer and queue. Unbounded `append` or unbuffered fan-out per message is a
  memory or goroutine exhaustion bug.

## 6. Observability

- `log/slog` with a connection id and remote address on every line about that connection.
- Log connects, disconnects with reason, rejections, and limit hits. Do not log message bodies
  by default.

## 7. Testing patterns

- Start the server on `127.0.0.1:0`, read the real address from the listener.
- Test helpers: `dial(t)` and `readLine(t, conn)` with a short deadline that calls `t.Fatal` on
  timeout.
- Cover: two peers exchange data; a third peer outside the scope does not receive it; a peer
  disconnects in the middle of a fan-out; oversized input is rejected; the server shuts down
  without leaked goroutines.
- Run with `-race -count=1`. The race detector only sees paths the tests execute, so the tests
  must exercise the concurrent paths.

## 8. AI suggestions to reject on sight

- A mutex and a channel both guarding the same map.
- `go func()` per message per recipient (unbounded goroutines).
- Writing to sockets from the owner goroutine.
- Closing a peer's channel from the peer's own reader goroutine.
- `time.Sleep` in tests to "wait for" delivery.
- Ignoring `scanner.Err()` or write errors.
- Pulling in a web or chat framework for a plain TCP service.
