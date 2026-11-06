# Development guide

## Prerequisites

- Go 1.26.10 or newer (the version in `go.mod`).
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the vulnerability
  stage: `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- Optional: [`gitleaks`](https://github.com/gitleaks/gitleaks), used by the review scripts to scan
  what they send out.

## Build and test

```sh
go build -o agent-guard ./cmd/agent-guard
bash scripts/check.sh        # the validation gate
```

`scripts/check.sh` runs four stages and reports each: `gofmt`, `go vet`, `govulncheck`, and
`go test -race -count=1 ./...`. A change is not done until it passes. If govulncheck reports a
vulnerability, report it with the affected call path before changing dependencies or the Go version.

## Layout

| Path | Contents |
|------|----------|
| `cmd/agent-guard` | `main`: flag parsing (`parseOptions`), wiring (`newServer`), shutdown |
| `internal/proxy` | `proxy.go` (config, routing, limits, the `decide` step), `nonstream.go`, `stream.go` (SSE parsing and rewriting), `guard.go` (fail-closed wrapper), `listener.go` (connection cap) |
| `internal/rules` | `config.go` (YAML to `Engine`), `engine.go` (the rules), `extract.go` (hosts and paths), `sensitive.go` (sensitive classes, IPv4 spellings) |
| `internal/audit` | JSONL writer (`audit.go`), redaction (`redact.go`) |
| `internal/telemetry` | the OpenTelemetry observer and setup |
| `internal/policy` | shared types: `Verdict`, `Decision`, `ToolCall`, `Decider`, `Event`, `Observer` |
| `examples/` | the example policy (tests check that it loads) |
| `plans/`, `REQUIREMENTS.md` | design history; see `plans/README.md` |
| `scripts/`, `skills/` | the validation gate and the review workflow described below |

## Conventions

- **Standard library first.** The only third-party modules are `gopkg.in/yaml.v3` and
  OpenTelemetry. Do not add another without a reason you can state.
- **One owner for shared state.** Every piece of shared mutable state has exactly one owner
  goroutine or one mutex, never both. Say which in the code comment. Today: the policy engine is
  immutable; the audit file belongs to one writer goroutine; the in-flight and connection caps are
  channel semaphores; per-request parsing state belongs to the request's goroutine.
- **Fail closed.** Any new error path that touches a tool call must end in BLOCK, not ALLOW.
- **Tests exercise real interfaces.** Network tests listen on `127.0.0.1:0`, connect with
  `net.Dial` or a real HTTP client, and put a deadline on every read. Every wait in a test has a
  timeout; do not use sleeps to synchronise. Tests are table-driven where that fits, and run under
  `-race`.
- **No secret-shaped literals.** Test fixtures that look like credentials are assembled at run
  time (see `fixtures` in `internal/audit/audit_test.go`), so secret scanners stay quiet and the
  repository never contains something that looks like a leaked key.
- **Docs are tested.** `cmd/agent-guard/docs_test.go` checks that the flags in the docs match the
  program, that complete YAML examples in the docs load, and that relative links resolve. Update the
  docs in the same change as the behaviour.

## Common changes

- **A new flag**: add it in `parseOptions`, wire it in `newServer`, and add it to the flag table in
  `docs/operations.md` (the docs test fails until you do).
- **A new sensitive class**: add the constant and to `classes` in `config.go`, detect it in
  `sensitive.go`, add cases to `engine_test.go`, and document it in `docs/policy.md`.
- **A new rule or policy source**: implement `policy.Decider`. It must be safe for concurrent use,
  own any state it keeps, and stop when its context is cancelled. Return an error (not ALLOW)
  when it cannot decide.
- **Another API protocol (for example OpenAI)**: this needs its own request/response handling next
  to `proxy/nonstream.go` and `proxy/stream.go`, and its own plan in `plans/`.

## The review workflow

This project was built in "pairing mode" (`CLAUDE.md`, `AGENTS.md`): a plan is written for each
step, reviewed by a second AI model with `scripts/plan-review.sh`, implemented, and the diff is
reviewed with `scripts/cross-review.sh`. You do not need this to contribute. If you want to use the
scripts, configure a reviewer as described at the top of `scripts/review-call.sh` (Cursor's CLI, or
an OpenAI or Anthropic API key). They send the diff to that provider, and refuse to if `gitleaks`
finds a secret in it.
