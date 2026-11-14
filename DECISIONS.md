# Decisions

## 2026-11-13 Halt control is a file read on each decision

Context: The proxy needs a way to refuse every tool call, fail closed when the control cannot be read or is corrupt, and record halt, resume, and each refusal. The worst-case time from setting the control to the first blocked call has to be documented.

Options:

1. A file the proxy reads when a decision starts.
2. A loopback-only HTTP endpoint that flips an in-memory flag.
3. A background poll of a file into an atomic bool.

Choice: Option 1. One mutex inside `internal/halt.Switch` owns the last state. No other package stores a halt flag. `-halt-file` is optional so existing deployments keep their current behaviour; when the flag is set, a missing, unreadable, or corrupt file is halted.

Why: A file is one code path and has a natural corrupt state. An endpoint would be a second listener that needs its own bind address and would still need a durable representation to fail closed across a restart. A poll interval would add a delay and a second writer of the flag. Reading the file on each decision, with the state under one mutex, keeps a single owner and makes the worst-case wait the time until the next decision plus one read, which is the zero-poll case (not an in-memory flag, because the file is the source of truth).

## 2026-11-13 Policy could not differ per agent

Context: `internal/rules.Engine` holds one tools list, one host list, and one path scope. `Decide` does not read an identity. The proxy did not look at any request field to choose a policy. Checked on main at e6d149c before this branch.

Options:

1. Leave the single policy and only document the gap.
2. Add named profiles selected by a new request header, and deny when the identity is missing or unknown.
3. Infer identity from an Anthropic message field.

Choice: Option 2. The header is `X-Agent-Guard-Identity`. It is stripped before the upstream request. A file with no `profiles` key keeps today's single policy, and the audit profile is `default`. A file with `profiles` requires `agents` as well. An agent entry that names a profile which does not exist fails at load. At request time a missing identity is `profile-missing` and any other unmatched identity is `profile-unknown`. Both are BLOCK. The profile name is the `profile` field on every audit record (empty when none applied).

Why: Option 3 would invent an API field. Option 1 does not meet the request. Denying unknown identities is the fail-closed default. Keeping the single-file form means existing policies do not start denying every call the moment this ships. The header is operator-supplied; nothing in the model protocol already carried an agent id.

## 2026-11-13 Host spelling is canonicalized before the allowlist

Context: Decimal, hex, and octal IPv4 spellings were already rewritten to dotted form. Bracketed IPv6 after userinfo was not: the URL match stopped at `[`, so `http://github.com@[2001:db8::1]/` produced an empty host and the call could be allowed. Trailing dots were trimmed only once. Mixed case and ports were already handled for ordinary URLs.

Options:

1. Add tests only where the current code already blocks.
2. Keep one stored form per address (dotted IPv4, compressed IPv6, IPv4-mapped addresses unmapped) and parse the authority through the last `@`, including brackets.

Choice: Option 2. The allowlist is stored in that same form. A mention matches the stored form, which is what the code already did for loose IPv4; the docs that said the opposite were corrected. This does not treat a name that later resolves to a forbidden address as that address. The guard still sees tool arguments, not packets.

Why: An empty host is an allow. Matching `::ffff:127.0.0.1` to an allowlisted `127.0.0.1` is the same address, not a new destination. Leaving the bracket case unparsed would hide the real host behind an allowlisted name in the userinfo.

## 2026-11-13 Ask stays a notice

Context: Allow, Block, and Ask already exist. Ask replaces the tool call with a notice and does not run it. Nothing waits for a person.

Options:

1. Add a new "Needs approval" verdict and an approval service.
2. Write down the current Ask behavior, the gaps, and a proposed unattended flow that denies on timeout. Do not build it.

Choice: Option 2, in `docs/ask-verdict.md`. The proposal reuses Ask, denies when no approval arrives, and treats an unreachable approver as a deny. No timer or new verdict was added.

Why: A second verdict would overlap Ask. Building an approver needs a channel the model cannot write to, which is a product decision, not something to invent in this pass. Deny on timeout is the fail-closed default for a run with nobody watching.

## 2026-11-13 Many agents stay a deployment choice

Context: The proxy is one process with one halt switch. Profiles, added in this branch, can differ per identity. Spans do not carry the agent id.

Options:

1. Document one process per agent versus one shared process with profiles, including what a halt covers and which audit fields correlate.
2. Build a supervisor that launches and halts many proxies.

Choice: Option 1, in `docs/running-many-agents.md`. Halt scope is the process that holds the switch. Correlation for a shared proxy is the `agent` and `profile` audit fields. Spans are not described as carrying those fields, because they do not.

Why: A supervisor would be a new service. The two layouts already fall out of the flags that exist. Docs only.


## 2026-11-14 The halt file read has a deadline and fails closed

Context: A read of the control file on a stalled network or FUSE mount can block in the kernel and cannot be cancelled. Every decision reads the file, so one stuck read could stall every request.

Options:

1. Read inline and accept the stall.
2. Run each read in a goroutine, give up after a deadline, treat that as halted, and refuse at once while an abandoned read is stuck or too many reads are running.

Choice: Option 2. The deadline is 2 seconds, or the decision's own deadline if that is shorter. At most 8 reads run at once. The abandoned goroutine stays until the kernel returns it. File I/O stays outside the mutex.

Why: A hung filesystem must not turn into a hung proxy or an allowed call. The cost is that a slow but healthy mount halts the proxy; the docs say to use a local filesystem.

## 2026-11-14 A repeated identity header is an unknown identity

Context: A client (or an intermediary) can send `X-Agent-Guard-Identity` twice. Taking the first or last value would let whoever controls one copy choose the profile.

Choice: With `profiles` set, a request with more than one copy of the header is `profile-unknown` (BLOCK) and the audit record has no `agent`. Without `profiles` the header is ignored. This does not make the identity authentication; it is still a label the client sets.

Why: Fail closed on ambiguity. `plans/step-10.md` listed this as a suggestion; it was implemented afterwards.
