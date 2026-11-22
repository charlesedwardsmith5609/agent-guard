# Step 15: TLDR 2026-11-17 (audit integrity note, velocity recipe, layer map)

Branch `improve/tldr-2026-11-17`, cut from `main` at `db58344`. The 2026-11-16 items (PR #4:
credential-brokering note, redaction shape tests, the eight redaction fixes, the decision against
a placeholder-token mode) are already merged and are not repeated here.

All three items are documentation, plus one documentation test. No runtime code changes, no new
dependency (`go.mod` unchanged), no shared state touched. Item 1 is "docs only, do not build": the
note is written, no integrity feature is built.

This step runs unattended (no one answers questions). Where the item says to ask, the question is
recorded under "Open questions" with a recommendation, and nothing is decided.

Sources in the "Reason" lines are vendor or press claims. They are not fetched: CLAUDE.md rule 11
allows only `127.0.0.1` / `localhost` without prior approval. The docs say "claim, not
independently checked" and give the URL. The Detectify URL in the brief is cut off (it ends in
`...running-`); the note says so and does not invent the rest of it.

One commit per item, in the order below, each with a CHANGELOG entry under `[Unreleased]`
("Added"). Every statement about agent-guard in the new text cites a file (and a line or a
function name).

## Item 1: `docs/audit-integrity.md` (design note, docs only, do not build)

### Facts the note must cite (checked against the code on `main`)

- How rows are written today: one writer goroutine owns the file and a `json.Encoder`, one
  `Encode` per record (`internal/audit/audit.go`, `run`, lines 255-273). Callers queue an item and
  wait for the writer's ack (`enqueue`, lines 195-229). The order of lines is the order the writer
  takes items off the queue, not strictly `ts` order (`ts` is the decision's end time, set in
  `record`, line 234, before queueing).
- How the file is opened: `O_WRONLY|O_APPEND|O_CREATE|O_EXCL` with mode 0600 for a new file, or
  `O_APPEND` with no-follow and non-blocking for an existing one; it must be a regular file with no
  group/other bits (`Open`, lines 108-139; flags in `internal/audit/open_unix.go`). Nothing else
  protects the content: no checksum, no signature, no rotation (`docs/operations.md`, "The file is
  append-only text ... It is not tamper-evident", lines 165-167; README threat model item 7,
  README.md lines 202-203).
- The redaction path: `record` (audit.go lines 231-253) redacts `tool`, `tool_use_id`, `rule` and
  `agent` with `RedactID`, the reason with `redactWithCanaries` + `truncate` (200 bytes), and the
  preview with `preview` (`internal/audit/redact.go` lines 334-349: decode, `redactValue`,
  re-encode, truncate to 256 bytes). `args_sha256` is the hash of the raw input (audit.go line 232).
  Halt/resume rows come from `RecordControl` (audit.go lines 174-193). Any integrity scheme would
  cover the *redacted* row, which is what is on disk; the raw input is never stored.
- Who can write the file: the proxy runs as some user; the file is that user's 0600 file. If the
  agent runs as the same user (the default Quick start, README.md lines 55-66), the agent can
  rewrite or delete the file. This is the threat model item 7 case.

### Options compared (each: what it detects, what it does not, where the anchor lives)

(a) **Hash chain.** Each row carries `prev` = SHA-256 of the previous line's bytes (first row of a
file: a fixed genesis value or the last hash of the previous file). Detects: an edited, deleted,
inserted or reordered row anywhere *before* the newest row whose hash is held elsewhere. Does not
detect: a rewrite of the whole file by anyone who can write it (the chain has no secret, so they
recompute it); truncation of the tail after the last externally-held hash; rows that were never
written (proxy killed, `fail-closed:audit`). Anchor: the latest hash must be copied somewhere the
agent's user cannot write (another uid, another host, a WORM store), otherwise the chain proves
nothing against that user. Fits the current design: the writer goroutine in `run` is already the
single owner of the encoder, so the chain head would be owned by it with no new lock. Breaks with
`copytruncate` rotation (operations.md line 166) unless the new file starts from the old head.

(b) **Periodic signed checkpoints.** Every N rows or T seconds, the writer appends a checkpoint row
with a signature (HMAC-SHA256 or Ed25519, both in the standard library) over the chain head and
row count. Detects: changes to anything before the last checkpoint, by anyone without the key,
including a whole-file rewrite. Does not detect: changes after the last checkpoint (window of N
rows / T seconds); anything by someone who can read the key; **rollback**: truncating the file
back to an older, validly signed checkpoint removes every later row and checkpoint without the
key. Signatures give authenticity, not completeness; completeness needs the latest checkpoint (or
a monotonic row counter) held outside the host. Anchor: the key. It must be readable
by the proxy and not by the agent, which means a different uid or a key outside the host; on the
same-user setup this adds nothing over (a). Key handling is new attack surface (startup flag,
file mode checks like `Open` does today).

(c) **Ship rows to a sink the agent host cannot write.** Each row is also sent to (or pulled by) a
remote append-only store: syslog/journald under another uid, a log collector, an object store with
retention lock. Detects: the local copy differing from the remote copy, for every row the sink
received. Does not detect: rows lost before shipping; a compromised proxy sending false rows (the
record is still written by the proxy, not by an independent observer). Anchor: the sink. Costs: a
network egress path from the proxy, a new failure mode that interacts with fail closed (every ALLOW
waits for its audit write, README.md lines 135-137 and item 9 lines 209-211; does shipping join
that wait or not?). The existing OpenTelemetry spans are not a substitute: there is only a stdout
exporter and spans carry no `profile`, `agent` or preview (`docs/operations.md` lines 188-196,
`docs/running-many-agents.md` lines 57-59).

Also say: none of the three makes the proxy an independent observer of the agent's host; the
Detectify point ("the record is written by the control, not the thing controlled") is already met
for the agent (the agent does not write audit rows), but not for the host owner.

### Ends with the open question (recorded, not decided)

"Does any of these belong in this repository, or is integrity a deployment concern (run the proxy
under another uid and ship the file)?"

### Files and tests

- New `docs/audit-integrity.md`; README.md documentation table gets one row for it (README.md
  lines 151-162); README threat model item 7 gets a link to the note (one clause, no new claim).
- Tests: no new test. `TestRelativeLinksResolve` (cmd/agent-guard/docs_test.go lines 107-143)
  already checks every relative link and anchor in `docs/*.md` and README.md, so the new file and
  its links are covered.
- Done: every claim about agent-guard cites a file; `go test ./cmd/agent-guard/` and
  `bash scripts/check.sh` pass.

Build vs note: note only. Nothing in `internal/audit` changes.

## Item 2: velocity recipe in `docs/operations.md`

### Finding about docs_test.go

`docs_test.go` does **not** run any `jq` recipe today (it checks flags, policy examples and links
only, lines 40-143). The brief says "if docs_test.go checks recipes ..., extend it". Since the done
criterion is "recipe works on fixture", the plan adds one new test that runs this recipe only. It
does not retrofit the existing recipes (Suggestion, not built).

### Recipe

A new subsection `### Velocity per profile` under `### Recipes (using jq)` (operations.md line 169).
One command, `jq -rs '<program>' audit.jsonl`, program in single quotes, containing no single quote
(so the test can extract it). Behaviour:

- Drop halt/resume/refusal lines (`select(.event == null)`); they are not tool calls
  (audit.go `Event` field, lines 44-47).
- Group by `profile`; an empty profile (refused before a profile applied, operations.md line 144)
  prints as `(none)`.
- Time: `ts` is RFC 3339 with nanoseconds (operations.md line 130). jq's `fromdateiso8601` does not
  accept fractional seconds, so the program splits the fraction off, converts the whole seconds, and
  adds the fraction back as a number. Sort each group by that time (file order is not strictly `ts`
  order, see item 1).
- Per profile, print one block:
  - `calls` total and `per_minute`: for each UTC minute with any call, `HH:MM count`.
  - `shortest_gaps_s`: the 3 smallest gaps between consecutive calls, in seconds, 3 decimals.
  - `order`: tool names in time order, consecutive repeats collapsed as `Bash x3`.
- Exact output format is fixed by the test (TSV lines, `profile<TAB>field<TAB>value`), so it can be
  grepped.

Text next to the recipe (plain, short):

- A model response with several tool calls produces several rows a few milliseconds apart, so the
  shortest gaps are often within one response, not between turns. The audit row has no request id
  to tell them apart (fields in audit.go lines 28-48).
- `profile` is the policy profile, not the agent; with no `profiles` map every caller is `default`
  (policyset.go line 11, `DefaultProfile`). Filter or group on `agent` for the identity label (running-many-agents.md
  lines 43-55), which is a label, not authentication.
- This is a report, not a verdict. agent-guard has no rate rule.

### Test (written first, fails before the doc text exists)

`TestVelocityRecipe` in `cmd/agent-guard/docs_test.go`:

1. Read `docs/operations.md`, find the `### Velocity per profile` section, extract the single
   `jq -rs '...'` line; fail if not found exactly once.
2. `exec.LookPath("jq")`; if missing, `t.Skip` with a loud message: `jq not found in PATH: the
   velocity recipe in docs/operations.md was NOT exercised`. (`scripts/misbehavior-check.sh`
   line 83 warns on `t.Skip(` in a changed file; that warning is expected and must be reported, not
   suppressed.)
3. Run jq with `exec.CommandContext` and a 10 s timeout on the fixture
   `cmd/agent-guard/testdata/velocity-audit.jsonl`; compare stdout byte-for-byte with the expected
   string in the test.

Fixture (hand-written, 10-12 lines, no secret-shaped values): two profiles (`ci`, `dev`), one row
with empty profile, one `"event":"halt"` row that must not appear, two lines out of `ts` order,
fractional seconds including a sub-second gap, a burst of three rows inside one second, rows
across two minutes, a repeated tool run (`Bash`, `Bash`, `Read`).

Expected output is derived by hand in the test comment so a reader can check it.

### Environment blocker

`jq` is **not installed** on this machine (`command -v jq` fails). The test will SKIP here and the
recipe cannot be shown to work locally, so the done criterion is NOT met in this environment.
The implementer must say so loudly and report item 2 as "built, NOT verified: jq missing". Do not
download jq or a jq binding (`uv pip install jq` would reach PyPI, which CLAUDE.md rule 11 does
not allow without approval). The owner runs `go test ./cmd/agent-guard/ -run TestVelocityRecipe -v`
on a machine with jq before merging.

Strict gate: `scripts/misbehavior-check.sh` line 83 matches the text `t.Skip(` statically, so
`PAIRING_STRICT=1 bash scripts/check.sh` warns-to-fail on docs_test.go whether or not jq is
installed, as long as the file is in the changed set. The brief asks for a clean skip, so the plan
keeps `t.Skip` and records this as open question 8.

Build vs note: recipe and test are built (docs + test are allowed). The rate-limit verdict is not
built.

## Item 3: layer map (docs only)

Where: a new section `## Indirect prompt injection: what is covered` in `docs/policy.md` (after
`## How a call is judged`, policy.md line 154), and one sentence in README threat model item 8
(README.md lines 207-208) linking to it. README item 8 already says "Prompt injection is mitigated
by blocking its effects, not detected"; keep that wording.

Table (Microsoft control → agent-guard), Microsoft guidance marked as vendor guidance, URL given,
not fetched:

| Microsoft control | agent-guard |
|---|---|
| Prompt shields (classifier) | None. No content classifier; requests are forwarded unchanged except the identity header |
| Spotlighting (mark untrusted input in the prompt) | None. agent-guard does not rewrite prompts |
| Plan drift detection | None. Each tool call is judged on its own (`Engine.Decide`, internal/rules/engine.go line 43); no plan or history is kept |
| Information flow control | None in the strict sense. The closest is a per-call co-occurrence check: `egress:canary` and `egress:sensitive:<class>` block a call whose own arguments contain a canary or sensitive path together with an egress channel (engine.go lines 53-75). It does not track data across calls |

Then the deterministic controls it does provide, with rule names:

- Tool allowlist: `tool-not-declared` (`RuleToolNotDeclared`, engine.go line 14).
- Host allowlist after canonicalization: `host-not-allowed` (engine.go line 15; canonicalization
  in `canonicalHost`, internal/rules/extract.go line 177; DECISIONS.md "2026-11-13 Host spelling is
  canonicalized").
- Path scopes: `path-out-of-scope` (engine.go line 16; structured keys, extract.go lines 31-34).
- Sensitive locations: `sensitive:<class>` (engine.go line 19, `rulePrefixSensitive`; classes in
  internal/rules/sensitive.go).
- Sensitive-class and canary egress blocks: `egress:sensitive:<class>` and `egress:canary`
  (engine.go lines 18, 20).
- Profiles: `profile-missing`, `profile-unknown` (internal/rules/policyset.go lines 16-17).
- Halt file: rule `halt`. Note it is **not** in internal/rules: it is set in internal/proxy/proxy.go
  (lines 443, 448) from internal/halt/switch.go. The doc must say where it lives rather than claim
  it is an internal/rules rule.

Tests: no new test; `TestRelativeLinksResolve` covers the new anchor and README link. Done: the
table cites rule names that exist in the code (implementer greps each name), check.sh passes.

Build vs note: docs only.

## Shared state and ownership

None changed. Item 2's test runs one child process per test run with a deadline; no goroutines,
no listeners.

## Gate (run after each item's commit)

```sh
cd /home/charles/code/agent-guard
export PATH="$HOME/go/bin:$PATH"
gofmt -l .
go vet ./...
govulncheck ./...
go test -race -count=1 ./...
bash scripts/check.sh
PAIRING_STRICT=1 bash scripts/check.sh   # report: expected to fail on the static t.Skip( marker in docs_test.go (any jq state)
bash scripts/cross-review.sh             # per item, 10-minute timeout; record findings
```

A SKIP of `TestVelocityRecipe` counts as NOT RUN for item 2's done criterion.

## Open questions for the owner (recorded, not decided)

1. Item 1: does any integrity option belong in this repo? Recommendation: not yet. Document the
   deployment answer (proxy under its own uid, ship the file off-host); if anything is built later,
   (a) hash chain first, because it needs no key and fits the single writer goroutine, and it is
   only useful together with an off-host anchor.
2. Item 2: is a built-in rate rule wanted? Recommendation: no for now. The audit row cannot tell
   one response's batch from separate turns (no request id), so a rate rule would first need a
   request id in the record; gather real recipe output first.
3. Item 2: group by `profile` (as the brief says) or by `agent`? Recommendation: `profile`, as
   asked, with a one-line note that `agent` can be substituted.
4. Item 2: should the existing recipes (operations.md lines 172-185) also be exercised by the test?
   Recommendation: yes, later, as its own small step; not in this step (scope).
5. Item 3: mention information flow control as out of scope? Recommendation: yes, one row saying
   "none; the egress co-occurrence check is not IFC", since leaving it out invites the reading that
   the egress rules are IFC.
6. Item 3: table in docs/policy.md (recommended, it is the rule reference) or in the README threat
   model? Recommendation: policy.md plus a one-sentence README link.
7. CHANGELOG.md header still says "[Unreleased] - 2026-11-14" and names an old branch (lines 3-7).
   Recommendation: leave it to the owner; add entries under the existing `[Unreleased]`.
8. Item 2: a missing jq is a loud `t.Skip` (as the brief says), which trips the strict
   misbehavior gate permanently. Alternative: fail when jq is missing unless
   `AGENT_GUARD_NO_JQ=1` is set. Recommendation: keep the skip as briefed; owner decides.

## Plan review

`bash scripts/plan-review.sh plans/step-15.md`, provider openai, model gpt-6.1-sol, 2026-11-21
(saved under `.reviews/`, not committed). Four MEDIUM findings:

1. Signed checkpoints: rollback to an older valid checkpoint is undetected. **Agree**; folded into
   option (b) (authenticity vs completeness, external latest checkpoint).
2. The `uv pip install jq` workaround reaches PyPI, against the loopback-only rule. **Agree**;
   removed. Item 2 is reported as not verified locally.
3. The recipe test skips here, and the static `t.Skip(` marker fails the strict gate regardless of
   jq. **Agree on the facts**; folded into the gate notes. **Disagree** on making missing jq a
   failure: the brief asks for a clean, loud skip. Recorded as open question 8.
4. REQUIREMENTS.md does not list this step and there is no human approval. **Disagree for this
   run**: the owner's brief sets an unattended policy (docs and tests may be implemented, open
   questions recorded, nothing decided). Recorded here so the owner can confirm; REQUIREMENTS.md is
   not changed in this step.

## Files

- plans/step-15.md
- docs/audit-integrity.md
- docs/operations.md
- docs/policy.md
- README.md
- CHANGELOG.md
- cmd/agent-guard/docs_test.go
- cmd/agent-guard/testdata/velocity-audit.jsonl
