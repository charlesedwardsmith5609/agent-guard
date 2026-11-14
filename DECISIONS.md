# Decisions

## 2026-11-13 Halt control is a file read on each decision

Context: The proxy needs a way to refuse every tool call, fail closed when the control cannot be read or is corrupt, and record halt, resume, and each refusal. The worst-case time from setting the control to the first blocked call has to be documented.

Options:

1. A file the proxy reads when a decision starts.
2. A loopback-only HTTP endpoint that flips an in-memory flag.
3. A background poll of a file into an atomic bool.

Choice: Option 1. One mutex inside `internal/halt.Switch` owns the last state. No other package stores a halt flag. `-halt-file` is optional so existing deployments keep their current behaviour; when the flag is set, a missing, unreadable, or corrupt file is halted.

Why: A file is one code path and has a natural corrupt state. An endpoint would be a second listener that needs its own bind address and would still need a durable representation to fail closed across a restart. A poll interval would add a delay and a second writer of the flag. Reading the file under the mutex on each decision keeps a single owner and makes the worst-case wait the time until the next decision plus one read, which is the zero-poll case (not an in-memory flag, because the file is the source of truth).
