# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is pre-1.0
and has no tagged releases; everything below is on branch `improve/tldr-catchup-2026-11-13`
(not yet merged to `main`).

## [Unreleased] - 2026-11-14

### Added
- [docs/audit-integrity.md](docs/audit-integrity.md): a design note, nothing built. It compares a
  hash chain, signed checkpoints and an off-host sink for the audit log, and ends with an open
  question about whether any belongs in this repository.
- `-halt-file`: a control file (`running` or `halted`) read when a request arrives and at the
  start of every tool-call decision. A missing, unreadable, corrupt, symlinked or oversized file
  halts. Halt, resume and each refusal are audit records (`event` field). See
  [docs/operations.md](docs/operations.md#halt).
- Policy profiles: `profiles` and `agents` in the policy file, selected by the
  `X-Agent-Guard-Identity` request header, which is removed before forwarding. Audit records gain
  `profile` and `agent` fields. New rules `profile-missing` and `profile-unknown`. The identity is a
  label, not authentication. See [docs/policy.md](docs/policy.md#profiles-and-agents) and
  [docs/running-many-agents.md](docs/running-many-agents.md).
- [docs/ask-verdict.md](docs/ask-verdict.md): what Ask does today and a proposed (not built)
  deny-on-timeout flow.
- Helper checks `scripts/misbehavior-check.sh` and `scripts/assertion-check.sh`, run by
  `scripts/check.sh`.
- `DECISIONS.md` and this changelog.
- [docs/credential-brokering.md](docs/credential-brokering.md): a design note, nothing built. It
  compares agent-guard with a containment list (read-only ephemeral credentials, a
  credential-swapping proxy, an egress allowlist, an independent judge on another model), and
  evaluates an optional placeholder-token mode for the API key that passes through the proxy.
  The question it ends with is answered: a placeholder-token mode is not built for now (see
  [DECISIONS.md](DECISIONS.md)).
- Table tests for audit redaction by credential shape (`internal/audit/redact_shapes_test.go`):
  AWS access key id, AWS secret access key, GitHub token prefixes, JWT, `Authorization` header and
  database URLs with a password. Secret-shaped values are generated at run time.

### Changed
- Audit redaction closes eight gaps found by the new tests: an AWS secret key containing `/`
  (bare, `name = value` and `NAME: value` forms); `Authorization`, `Proxy-Authorization` and
  `X-Api-Key` header values of any scheme and length; a URL password containing `@` and URLs with
  an empty user (`redis://:pw@host`). Values of secret-looking names may now be quoted and contain
  spaces. Redaction hides somewhat more harmless text than before; see
  [docs/operations.md](docs/operations.md#audit-log) for the known costs and limits.
- The halt control-file read has a 2 second deadline. A read that does not finish counts as
  halted (fail closed), and further checks are refused at once while it is stuck. Keep the file on
  a local filesystem.
- A request that carries `X-Agent-Guard-Identity` more than once is treated as an unusable identity
  (`profile-unknown`) when profiles are configured. Previously the first value was used.
- A request arriving while halted gets HTTP 503 and is not forwarded; a tool call in flight when the
  halt lands is replaced with a block notice (`rule: halt`).
- Hosts are canonicalized before the allowlist and the user-mention check: numeric and IPv6
  spellings, trailing dots, case and ports. A mention must contain the stored form.
- URL host extraction no longer lets an allowed host hide the real one: the host is the part after
  the last `@` (including bracketed IPv6), `http:/evil.com/` and backslash forms yield a host, an
  empty or invalid host is BLOCK. See [docs/policy.md](docs/policy.md).
- The review scripts were refreshed from the pairing kit.

### Fixed
- Documentation that said a mention in a different spelling authorises a call; the code compares
  the stored (canonical) host.
