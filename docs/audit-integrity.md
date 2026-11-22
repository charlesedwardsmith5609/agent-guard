# Audit log integrity: a design note

Status: a note only. Nothing described under "Options" is built, and nothing in
`internal/audit` changes because of it. The question at the end is open.

## Why this note exists

The README says the audit log is "plain append-only text with no integrity protection"
([README.md](../README.md), threat model item 7), and the operations guide says it "is not
tamper-evident" ([operations.md](operations.md#audit-log), lines 165-167).

A vendor write-up (TLDR InfoSec 2026-11-17, link truncated in the digest, so it was not read) says
Detectify's agent tooling logs every request, payload and response in an append-only ledger that
Detectify writes, not the agent. That is a vendor claim and was not checked. The idea worth testing
here is "the record is written by the control, not by the thing controlled". agent-guard already
meets that for the agent: the agent never writes audit rows, the proxy does. It does not meet it
for whoever owns the proxy's host or user account.

## How rows are written today

- One writer goroutine owns the file and a `json.Encoder`, and calls `Encode` once per record
  (`internal/audit/audit.go`, `run`, lines 255-273). Callers queue an item and wait for the
  writer's acknowledgement (`enqueue`, lines 195-229). Line order is the order the writer takes
  items off the queue. It is not strictly `ts` order, because `ts` is the decision's end time
  (`record`, line 234) set before queueing.
- The file is opened with `O_WRONLY|O_APPEND|O_CREATE|O_EXCL` and mode 0600 for a new file, or
  `O_APPEND` with no-follow and non-blocking for an existing one. It must be a regular file with no
  group or other permission bits (`Open`, `internal/audit/audit.go` lines 108-139; flags in
  `internal/audit/open_unix.go`). Nothing else protects the content: there is no checksum, no
  signature and no rotation (`docs/operations.md` lines 165-167).
- What is stored is the redacted row. `record` (`internal/audit/audit.go` lines 231-253) passes
  `tool`, `tool_use_id`, `rule` and `agent` through `RedactID`, the reason through
  `redactWithCanaries` and `truncate` (200 bytes), and the arguments through `preview`
  (`internal/audit/redact.go` lines 334-349: decode, `redactValue`, re-encode, cut to 256 bytes).
  `args_sha256` is the hash of the raw input (`audit.go` line 232); the raw input itself is never
  stored. Halt and resume lines come from `RecordControl` (`audit.go` lines 174-193). Any integrity
  scheme would cover this redacted row, not the original call.
- Who can write the file: the proxy runs as some user and the file is that user's 0600 file. In the
  default quick start the agent runs as the same user (README.md "Quick start"), so the agent's
  process could rewrite or delete the file. That is the case threat model item 7 describes.
- Rows can be missing without any edit. A failed audit write refuses the call
  (`fail-closed:audit`, README.md lines 132-137), but a proxy that is killed, or a disk that is
  replaced, leaves no trace of what it never wrote.

## Options

### (a) Hash chain

Each row carries `prev`, the SHA-256 of the previous line's bytes. The first row of a file carries
a fixed genesis value, or the last hash of the previous file.

- Detects: an edited, deleted, inserted or reordered row anywhere before the newest hash that is
  held somewhere else.
- Does not detect: a rewrite of the whole file by anyone who can write it (the chain has no secret,
  so they recompute it); truncation of the tail after the last externally held hash; rows that were
  never written.
- Where the anchor must live: the latest hash has to be copied somewhere the agent's user cannot
  write (another uid, another host, a write-once store). Without that, the chain proves nothing
  against that user.
- Fit with the code: the writer goroutine in `run` is already the only owner of the encoder, so it
  could own the chain head without a new lock. It does not fit `copytruncate` rotation
  (`docs/operations.md` line 166) unless the new file starts from the old head.

### (b) Periodic signed checkpoints

Every N rows or T seconds the writer appends a checkpoint row carrying a signature (HMAC-SHA256 or
Ed25519, both in the Go standard library) over the chain head and the row count.

- Detects: changes to anything before the last checkpoint by anyone without the key, including a
  whole-file rewrite.
- Does not detect: changes after the last checkpoint (a window of N rows or T seconds); anything
  done by someone who can read the key; **rollback**. Truncating the file back to an older, validly
  signed checkpoint removes every later row and checkpoint without needing the key. A signature
  gives authenticity, not completeness. Completeness needs the latest checkpoint, or a monotonic
  row counter, held outside the host.
- Where the anchor must live: the key. The proxy must be able to read it and the agent must not,
  which means a different uid or a key kept off the host. On the same-user setup this adds nothing
  over (a). Key handling is new attack surface (a startup flag, file mode checks like `Open` does
  today).

### (c) Ship rows to a sink the agent host cannot write

Each row is also sent to, or pulled by, a remote append-only store: syslog or journald under
another uid, a log collector, an object store with a retention lock.

- Detects: the local copy differing from the remote copy, for every row the sink received.
- Does not detect: rows lost before shipping; a compromised proxy sending false rows (the record is
  still written by the proxy, not by an independent observer).
- Where the anchor must live: the sink itself.
- Costs: a network path out of the proxy, and a new failure mode that interacts with failing
  closed. Every ALLOW waits for its audit write (README.md lines 132-137, threat model item 9),
  so a design must say whether shipping joins that wait. The OpenTelemetry spans are not a
  substitute: only a stdout exporter exists, and spans carry no `profile`, `agent` or arguments
  preview (`docs/operations.md` lines 188-196, `docs/running-many-agents.md` lines 57-59).

## What none of them does

None of the three makes the proxy an independent observer of the agent's host. The proxy only
records what it was shown: tool calls in a Messages response (README.md threat model items 1 and
2). They also cannot help with a client that bypasses the proxy.

## Open question (recorded, not decided)

Does any of these belong in this repository, or is integrity a deployment concern (run the proxy
under its own uid and ship the file off the host)? If anything were built, option (a) is the
smallest step (no key, fits the single writer), and it is only useful with an off-host anchor.
