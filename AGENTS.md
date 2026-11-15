# Pairing mode: working agreements

A human engineer directs this work and owns every design decision: what to build, what to
accept, what to reject, and how to verify it. You implement scoped asks and keep your reasoning
visible so each decision can be reviewed before it lands.

## Rules

1. **Plan before code, and get it reviewed.**
   - Before the first plan, write the agreed requirements to `REQUIREMENTS.md` and ask the human
     to confirm them.
   - For each step, write the plan to `plans/step-N.md`: types, who owns any shared state, the
     tests you will add, and a `## Files` section listing every path this step may touch as
     markdown bullets (for example `- path/one.go`). The validation gate uses that list when
     present; omit it only when the human says the step has no file scope yet.
   - Then run `bash scripts/plan-review.sh plans/step-N.md`. Present the plan's key points, each
     reviewer finding with your assessment (agree or disagree, with a reason), and wait for
     approval before writing code.
   - When the human approves with changes, update the plan file to match before implementing.
   - Exception: when the human says "scaffold", write boilerplate directly.
2. **Stay inside the approved step.** When the approved step is done, stop and report. Do not
   continue into later steps, even if they were mentioned. Do not add features that were not
   asked for; list them under "Suggestions" instead.
3. **No new dependencies without approval.** Each language section below lists what is already
   allowed. To propose anything else, name it and say what it replaces and why.
4. **Done means the check passes.** After every change, run `bash scripts/check.sh` and report
   the result per stage. A clean compile is not done. Never claim something builds or passes
   without running it. Set `PAIRING_STRICT=1` to turn agent-misbehavior warnings into failures.
5. **Test-first.** Before writing code for a step, agree a natural-language test list with the
   human. Write those tests so they fail, then implement until they pass. The test list in
   `plans/step-N.md` is that agreed list. Exception: when the human says "scaffold", write
   boilerplate directly.
6. **Behavioral tests.** Test through real interfaces (a real listener on `127.0.0.1` port 0,
   real HTTP requests, real DOM). Every wait in a test has a timeout so a broken test fails
   instead of hanging. No sleeps for synchronization.
7. **Name the ownership.** For any change that touches shared state, state which thread,
   goroutine, task or component owns it and how others reach it.
8. **Load the skills first.** Read the skill files listed in the relevant language section
   before writing code in that area.
9. **Ask, don't guess.** If a requirement is ambiguous, ask. If you must assume, put the
   assumption at the top of your reply.
10. **Keep replies short:** plan or change summary, check result, open questions, suggestions.
    Prefer lists over wide tables; the terminal may be narrow.
11. **Tool-call policy.** Stay inside the project's tool settings and this allowlist unless the
    human expands it in the approved plan.
    - Network: only `127.0.0.1` / `localhost` for tests. Any other host needs prior approval.
    - Do not read `/proc/*/environ`, `.env` / `.env.*`, `/var/run/secrets/**`, or cloud instance
      metadata (`169.254.169.254`, `metadata.google.internal`).
    - Do not invent tools. `WebFetch` and other network tools require an ask/approval; Cursor
      has no harness interceptor here, so the agreements plus `scripts/check.sh` are the gate.

## Security defaults

- Validate and bound every external input before it is used.
- Deny outbound hosts by default; allow a host only when the plan names it (SSRF).
- Never log or echo secrets, tokens, or credentials.
- Keep secrets out of prompts, config, and source.
- Parameterize queries; do not concatenate untrusted input into them.
- Never paste tokens or credentials into a tool call, forum, issue comment, or sub-agent prompt, and never run an install script fetched from a third party without asking.

## Tool context cost

Every enabled tool and every MCP server costs context tokens on every turn, including turns that do not call them. Enable a tool or server for the task that needs it, and disable it when that task is done.

Run the agent in a sandboxed devcontainer when the work can touch the host. The pairing kit repository has a note on this, `docs/sandboxed-devcontainer.md`; that file lives in the kit, not in this project. This paragraph does not add a devcontainer file.

## Commands

| Purpose                                             | Command                        |
|-----------------------------------------------------|--------------------------------|
| Validation gate (every language in this project)    | `bash scripts/check.sh`        |
| Plan review (after writing each plan)               | `bash scripts/plan-review.sh`  |
| Cross-model review (code, at milestones)            | `bash scripts/cross-review.sh` |

Both reviews send work to a different AI provider: the plan review checks a plan against
`REQUIREMENTS.md` before any code exists, and the cross-model review checks the code diff. A
review can take a few minutes, so run them with a 10-minute timeout. When
findings come back, give your assessment of each one (agree or disagree, with a reason) and do not
change the plan or the code until the human decides.

## This project

- `.`: go

### Go (`.`)

- Third-party modules are limited to `gopkg.in/yaml.v3` and OpenTelemetry (see `go.mod`). `go.mod` must not gain other requirements without approval.
- Skill: read `skills/go-network-service.md` before writing server code.
- Shared state has one owner goroutine or one mutex, never both. Name it in every plan.
- Network tests use a real listener on `127.0.0.1:0` and `net.Dial`, with a deadline on every read.
- Check stages: gofmt, go vet, govulncheck (known vulnerabilities), `go test -race -count=1`.
- If govulncheck reports a vulnerability, stop and report it with the affected call path; do not
  upgrade or replace modules without approval.
