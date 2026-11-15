# Step 8: MEDIUM findings 3 and 5 (halt file); finding 4 is held

Status: implemented (check passes). Details of what shipped are in the commit and docs.

## Goal

- 3: bounded, non-blocking, no-follow halt read with I/O outside the mutex.
- 5: a transition takes effect only after its audit record is written.
- 4 is a **DECISION**. Not touched, including the "document as labels" wording.

## Design

Finding 3 (`internal/halt/switch.go`):
- `readControl`: `os.OpenFile(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`, `f.Stat()`, require
  `Mode().IsRegular()` and `Size() <= 64`, read via `io.LimitReader(f, 65)`, error if over 64.
  Open errors for ELOOP (symlink) and a FIFO or directory map to corrupt (halted).
- `Read` calls `readControl` and `interpret` before taking the lock. Lock only to compare and
  update `known`/`halted`.
- Unix only (`syscall.O_NOFOLLOW`), consistent with the audit file (decision 15). I will check
  the build for non-unix targets.

Finding 5:
- `Read` no longer commits. It returns the proposed transition and the committed `halted`.
  New `Commit(transition)` is called by `refuseIfHalted` after `recordControl` succeeds.
- If the record fails, state stays at the old value, so the next decision proposes the same
  transition again (retried pending transition). While a resume is uncommitted the call is
  BLOCK `fail-closed:audit`. A failed halt record: the call is already refused (halted), and
  the transition is retried.
- Effective halted for the decision: proposing halt means refuse now; proposing resume means
  refuse until committed.
- Resolved (approved): one recorder per transition. `Read` returns a proposal token and a
  generation; `Commit(token)` is rejected if the generation moved (stale observation);
  `Abort(token)` runs on every failure path (audit error, cancel, early return). Other callers
  are refused while a token is outstanding.
- Superseded question: two concurrent decisions may both propose the same transition and both record
  it (duplicate audit lines). Options: accept duplicates, or hold a pending flag under the
  mutex so one caller records and others refuse. I plan the pending flag; please say if you
  prefer otherwise.

## Files

- `internal/halt/switch.go`, `internal/halt/switch_test.go`
- `internal/proxy/proxy.go` (`refuseIfHalted`)
- `internal/proxy/*_test.go`

## Tests (failing first)

- halt file is a FIFO: decision returns halted within a deadline, audited (finding 3)
- symlink to a large or endless file: halted, bounded memory
- directory, and file over 64 bytes: halted, fail-closed
- Read does not hold the mutex during I/O: injectable gated control-reader seam pauses one
  observation, a second caller enters; every gate wait has a timeout
- real FIFO test only for non-blocking rejection
- stale proposal ordering (A reads resume, B commits halt, A's commit rejected) with gates
- failed record then Abort: next call re-proposes (retry), no permanent refusal
- resume with failing audit: call BLOCK `fail-closed:audit`, next call still refused until a
  record succeeds, then resume takes effect
- startup halt record is written
All network tests: listener on `127.0.0.1:0`, deadline on every read, no sleeps.

## Ownership

`Switch.mu` is the single owner of `known`, `halted`, `pending`. Callers go through `Read`
and `Commit`. File I/O touches no shared state. No channel is added.

## Out of scope

Finding 4, step 9 items.
