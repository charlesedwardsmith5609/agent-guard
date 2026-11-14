# Decisions

## 2026-11-13 Halt control is a file read on each decision

Context: The proxy needs a way to refuse every tool call, fail closed when the control cannot be read or is corrupt, and record halt, resume, and each refusal. The worst-case time from setting the control to the first blocked call has to be documented.

Options:

1. A file the proxy reads when a decision starts.
2. A loopback-only HTTP endpoint that flips an in-memory flag.
3. A background poll of a file into an atomic bool.

Choice: Option 1. One mutex inside `internal/halt.Switch` owns the last state. No other package stores a halt flag. `-halt-file` is optional so existing deployments keep their current behaviour; when the flag is set, a missing, unreadable, or corrupt file is halted.

Why: A file is one code path and has a natural corrupt state. An endpoint would be a second listener that needs its own bind address and would still need a durable representation to fail closed across a restart. A poll interval would add a delay and a second writer of the flag. Reading the file under the mutex on each decision keeps a single owner and makes the worst-case wait the time until the next decision plus one read, which is the zero-poll case (not an in-memory flag, because the file is the source of truth).

## 2026-11-13 Policy could not differ per agent

Context: `internal/rules.Engine` holds one tools list, one host list, and one path scope. `Decide` does not read an identity. The proxy did not look at any request field to choose a policy. Checked on main at e6d149c before this branch.

Options:

1. Leave the single policy and only document the gap.
2. Add named profiles selected by a new request header, and deny when the identity is missing or unknown.
3. Infer identity from an Anthropic message field.

Choice: Option 2. The header is `X-Agent-Guard-Identity`. It is stripped before the upstream request. A file with no `profiles` key keeps today's single policy, and the audit profile is `default`. A file with `profiles` requires `agents` as well. An agent entry that names a profile which does not exist fails at load. At request time a missing identity is `profile-missing` and any other unmatched identity is `profile-unknown`. Both are BLOCK. The profile name is the `profile` field on every audit record (empty when none applied).

Why: Option 3 would invent an API field. Option 1 does not meet the request. Denying unknown identities is the fail-closed default. Keeping the single-file form means existing policies do not start denying every call the moment this ships. The header is operator-supplied; nothing in the model protocol already carried an agent id.

