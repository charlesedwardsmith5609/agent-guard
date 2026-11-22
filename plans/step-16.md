# Step 16: can an audit row be replayed against another policy? (question first, do not build)

Branch `improve/tldr-2026-11-20`, stacked on `improve/tldr-2026-11-17` (step 15). This step is a
report only. **Nothing is built**: no code, no doc outside this file, no CHANGELOG entry (no
user-visible change). The "if approved" outline at the end is the owner's spec restated with notes;
it is not approved and must not be implemented in this run.

Reason in the brief: Uber's agent framework is described as combining registration, runtime
authorization and post-deployment replay (InfoQ, 2026-11-18). That is a press description, a
claim; the URL was not fetched (CLAUDE.md rule 11: no host other than localhost without approval).

## What a decision needs (from the code)

`Policy.Decide(ctx, pc policy.Context, tc policy.ToolCall)` (internal/rules/policyset.go line 31) selects an engine and calls `Engine.Decide`
(internal/rules/engine.go line 43). The inputs are:

- `tc.Name`: the raw tool name (`toolDeclared`, engine.go lines 146-156; `forumStyle`, lines
  191-201).
- `tc.Input`: the raw input JSON. `extract` (internal/rules/extract.go line 105) walks every string
  for hosts, path-like candidates and structured path keys (`pathKeys`, extract.go lines 31-34).
- `pc.UserText`: user-role text of the whole conversation (internal/policy/policy.go lines 49-50),
  used only by the host mention exemption (`mentionedHosts`, engine.go lines 99-115).
- `pc.AgentID` and `pc.AgentIDRejected` (policy.go lines 51-56): profile selection
  (`selectEngine`, policyset.go lines 55-74).
- Load-time options: home directory and `paths.workdir`, defaulting to the process's home and
  working directory (internal/rules/config.go lines 50-53, 150-155, 231-233). Relative paths
  resolve against workdir (`inScope`, engine.go lines 175-187).

## What an audit row holds (internal/audit/audit.go `Record`, lines 28-48; `record`, 231-253)

- `tool`: `RedactID(name)` = `policy.SafeID` (internal/policy/observe.go lines 31-48: characters
  outside `[A-Za-z0-9_.:/-]` become `_`, cut at 128 bytes) then credential redaction. Usually equal
  to the raw name; not guaranteed.
- `args_sha256`: SHA-256 of the **raw** input bytes (audit.go line 232).
- `args_preview`: `preview` (internal/audit/redact.go lines 334-349): decode with `UseNumber`,
  `redactValue` (lines 309-330: the whole value of any key matching `secretKey`, line 18, becomes
  `[REDACTED]`; every string goes through `redactWithCanaries`), re-marshal (keys sorted, compact,
  HTML characters escaped), then `truncate` to **256 bytes** with a trailing `...` (lines 351-364),
  which leaves invalid JSON. Placeholders `[too large to preview]` (input over 64 KiB, line 14) and
  `[unparseable]`. Absent entirely with `-audit-preview=false` (audit.go line 249).
- `profile`: the profile name, not redacted (audit.go line 243); empty when refused before a
  profile applied.
- `agent`: `RedactID(agent)`, omitted when there was none or the header was repeated (audit.go
  lines 246-248; docs/operations.md line 145).
- `decision`, `rule`, `reason` (redacted, 200 bytes), `event` for halt/resume/refusal rows.
- **Not stored at all**: `UserText`, `AgentIDRejected`, the raw input, the workdir/home in effect,
  any request id.

So a row holds the tool name (almost always faithfully), the profile name, and a normalized,
redacted, possibly truncated copy of the arguments.

## Usable rows

A row can be re-evaluated only if `args_preview` is present, is not a placeholder, and parses as a
JSON object. Every preview longer than 256 bytes is cut and does not parse, so in practice
`Write`, `Edit` and long `Bash` calls are skipped. Rows with `event` set (halt, resume, refusal)
and rows with a `fail-closed:*` rule (internal/proxy/guard.go lines 42-76, proxy.go lines 420, 491)
record a proxy condition, not a policy verdict, so they have no baseline to compare against.

One exact check is available: if `sha256(args_preview) == args_sha256`, the preview *is* the raw
input byte for byte (no redaction, no truncation, already compact and key-sorted), and every
input-based rule replays faithfully for that row. How often that holds on a real log is unknown
(the model's JSON spacing and key order decide it); a replay should count it.

## Per rule: faithful or not

| Rule (where) | From a usable row | Why |
|---|---|---|
| `tool-not-declared` (engine.go line 14, 80-82) | Faithful if `tool` was not altered by `SafeID`/redaction | Needs only the name. A name with a character outside the SafeID alphabet cannot be told apart from one that really had `_` |
| forum-style egress trigger (engine.go lines 53, 191-234) | Same as above | Name only |
| `path-out-of-scope` (engine.go lines 116-120) | Faithful for structured path values that were not redacted, given the same workdir and home | `pathKeys` never match `secretKey`, so their values are kept whole unless a string pass (long random word `looksRandom` redact.go line 281, 40-char base64 run) hides a segment. Workdir comes from the candidate file or the replaying process, which may differ from the original |
| `sensitive:<class>` (engine.go lines 86-95; sensitive.go) | Mostly faithful | Path/host tokens survive unless they sat under a secret-looking key or matched a redaction pattern |
| `host-not-allowed` (engine.go lines 99-115) | **Half faithful.** The allowlist part is faithful for hosts that survive redaction (URL userinfo redaction keeps the host after `@`, redact.go `userinfo`). The mention exemption cannot be replayed: `UserText` is not stored | With empty user text the replay is stricter: a new BLOCK on this rule may be a call the user had authorised by naming the host. A host inside a long mixed word can be hidden by `looksRandom` (no split on `.`, `wordSplit` line 44) |
| `egress:sensitive:<class>` (engine.go lines 63-74) | Mostly faithful | Needs the hosts and candidates above |
| `egress:canary` (engine.go lines 54-62) | **Not faithful** for canaries of the policy that wrote the log: they are replaced by `[REDACTED]` before writing (redact.go `redactWithCanaries`; canaries passed at audit.go line 58). A canary that only the candidate policy has can be found in the stored text, but its absence proves nothing: the original value may have sat under a secret-looking key or matched a credential pattern and been redacted |
| `profile-missing`, `profile-unknown` (policyset.go lines 16-17, 55-74) | **Partly.** A row with a non-empty `profile` can be replayed by profile name if the candidate has that name. A refused row cannot: `agent` is redacted, is omitted for a repeated header, and `AgentIDRejected` is not stored | Agent-to-profile mapping changes in the candidate cannot be checked reliably |
| `halt` (internal/proxy/proxy.go lines 443, 448) | Not a policy rule; skip | Depends on the halt file at that moment |
| `fail-closed:*` (internal/proxy/guard.go, proxy.go) | Skip | Proxy condition, not a verdict |
| rows with `-audit-preview=false` | Only the tool-name rules | No arguments recorded |

Conclusion: only rows whose hash matches the preview replay exactly. For every other usable row
the replay is a lossy approximation: a finding in the stored text is real, but the absence of a
finding does not prove the original had none, because redaction may have removed the evidence.
Within that limit, the tool, path-scope and sensitive rules replay well for short calls; host rules
only in the "candidate allows more" direction; canary and identity rules not reliably. A replay
must label non-hash-matching rows as approximate.
The redaction that keeps secrets out of the log is exactly what makes some rules unreplayable, and
it should stay that way.

## Open questions for the owner (recorded, not decided)

1. Is a replay subcommand wanted? Recommendation: only if a large share of real rows is usable.
   Before deciding, measure on a real log (count rows whose preview parses, and rows where the
   hash matches). If most rows are long Write/Edit/Bash calls, replay would mostly report skips.
2. If built, how are host-rule changes that depend on the mention exemption shown? Recommendation:
   a separate "uncertain: depends on user text" class, never a plain "would block".
3. Should the 256-byte preview cap be raised to make replay useful? Recommendation: no; it widens
   what a leaked log exposes. Replay should live with the cap.
4. Exit status: non-zero when any verdict changes (useful in CI) or always 0? Recommendation:
   0 no change, 1 changes found, 2 error.
5. Rows by profile name when the candidate renames a profile: skip with a reason, or accept a
   `-map old=new` flag? Recommendation: skip with a reason; no mapping flag at first.

## If approved: build outline (owner's spec; NOT to be implemented now)

`agent-guard replay -config candidate.yaml -audit audit.jsonl`

- Reads the audit log, re-runs the decision for each row with the candidate policy, and prints the
  rows whose verdict would change, with old and new rule (one TSV line: line number, `ts`, tool,
  old decision/rule, new decision/rule).
- Never contacts the network, never writes the audit log. Says which rows were skipped and why
  (counts per reason, plus line numbers), so a skip is never a silent allow.
- Bounded: a maximum file size (proposed 256 MiB) and line length (proposed 64 KiB, `bufio.Scanner`
  with an explicit buffer stops for good at the first `ErrTooLong`, so it is not enough). Use a
  bounded reader (`bufio.Reader.ReadSlice`, draining to the next newline when a line is over the
  limit) so an over-long line becomes one skipped row and reading continues.
- Opens the log read-only and rejects symlinks the way `audit.Open` does (no-follow and non-blocking
  flags, internal/audit/open_unix.go; must be a regular file), and refuses on non-Unix like `Open`.
- Implementation shape: a new package (proposed `internal/replay`) that depends on `internal/rules`
  and the audit `Record` type only; `main.go` dispatches when `os.Args[1] == "replay"`, before the
  server flags are parsed (`parseOptions`, cmd/agent-guard/main.go line 41). Single goroutine, no
  shared state; the `Policy` is immutable after load (README.md lines 229 and 236).
- Context per row: `policy.Context{UserText: nil}`; `AgentID` unset, the engine selected by the
  row's `profile` name.
- Tests (natural language, to be agreed before code):
  1. Fixture log + two small policies: the exact set of changed rows is asserted (line numbers and
     old/new rules).
  2. Skipped rows (truncated preview, placeholder, no preview, halt/refusal/fail-closed rows, unknown
     profile) are listed with their reason; none is counted as unchanged or allowed.
  3. The log is untouched: size, mode, mtime and SHA-256 equal before and after.
  4. No listener and no network: an import-graph test (`go list -deps` of the replay package has no
     `net` or `net/http`), and the subcommand accepts no `-listen` or `-upstream` flag.
  5. A symlinked log, a FIFO and an over-size file are rejected; an over-long line followed by a
     valid sentinel row: the long line is reported skipped and the sentinel row is still evaluated.
  7. A non-hash-matching row is labelled approximate; a hash-matching row is labelled exact.
  6. A host-rule change that depends on user text is reported as uncertain (if question 2 is
     accepted).
- Docs if built: docs/operations.md section, README docs table, CHANGELOG, DECISIONS.md entry.

## Plan review

`bash scripts/plan-review.sh plans/step-16.md`, provider openai, model gpt-6.1-sol, 2026-11-21
(saved under `.reviews/`, not committed). Two MEDIUM findings, both **agreed** and folded in:

1. A candidate-only canary may already be redacted, so its absence proves nothing, and the
   "faithful for short calls" conclusion was too strong. Fixed: non-hash-matching rows are
   described as lossy approximations; outline test 7 added.
2. `bufio.Scanner` stops at the first over-long line, so it cannot skip one and continue. Fixed:
   the outline uses a draining bounded reader; test 5 now has a sentinel row after the long line.

Correction to step 15 (already committed on `improve/tldr-2026-11-17`, not rewritten): its
policyset.go citations are wrong. `DefaultProfile` is line 11 (not 370) and `RuleProfileMissing` /
`RuleProfileUnknown` are lines 16-17 (not 375-376). Step 15 was corrected by follow-up commit f830bf9; nothing was rewritten.

## Files

- plans/step-16.md
