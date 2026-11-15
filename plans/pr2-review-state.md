# PR #2 review work: state at 2026-11-14

Branch: `improve/tldr-catchup-2026-11-13`. Source: `.review/findings.md` and `.review/shared-patterns.md` (local, gitignored; not in the repo).
Last `bash scripts/check.sh`: PASS (gofmt, go vet, govulncheck, `go test -race -count=1`), also
verified per commit.

## Done (three commits, plans in `plans/step-7.md` to `step-9.md`)

- `0dc9364` step 7, findings 1 and 2: single-pass URL scanner; BLOCK on unparseable or empty host.
- `f04b1b0` step 8, findings 3 and 5: bounded no-follow halt read outside the mutex;
  `Check`/`Commit`/`Abort` so a transition takes effect only after its audit record.
- `c61d67b` step 9, findings 6 to 10: halted proxy answers 503 before forwarding; `hostAllowed`
  requires a valid host; hand-written `looseIPv4`; temp+rename for the halt file; extra tests.

## Open: needs a human decision

- **Finding 4 (DECISION, untouched):** bind a profile to a listener (own port or unix socket with
  file perms) or use a per-agent secret compared in constant time and never logged. Either way the
  docs must say profiles are labels, not authentication, until then.

## Plan-review findings (reviewer: OpenAI gpt-6.1-sol; Cursor failed on the trust prompt,
set `CURSOR_REVIEW_TRUST=1`). All were agreed and applied to the plans.

- Step 7: empty-host test used `http:///x` (wrong; use `http:///`); scanner must stay linear;
  add a malformed-host test through the loopback proxy, streaming and non-streaming.
- Step 8: stale observation could overwrite newer state (generation check); pending flag needed an
  owned token plus Abort; slow-FIFO test could not prove I/O is outside the lock (use a gated
  reader seam); move `ProfileFor` test to step 9.
- Step 9: item 6 must reuse the audited transition protocol; remove the unapproved default for
  item 6; make the upstream-saw-nothing test deterministic (sentinel request).

## Behaviour changes to review

- Halted proxy: new requests get HTTP 503 and are not forwarded; no per-request audit line. The
  per-tool-call `rule: halt` refusal remains for a halt that lands mid-request. Four existing halt
  tests were rewritten for this.
- Any host that fails `validHost` now fails the input (BLOCK) instead of being ignored in URLs.
- Duplicate `X-Agent-Guard-Identity` headers: the first value wins (pinned by a test).

## Suggestions, not done

1. Network-command operands with invalid characters (`curl evil.example%2f.pypi.org`) are dropped
   by `hostToken` with no finding, so ALLOW. Make this loud (shared pattern 1).
2. Reject duplicate identity headers as unknown (related to finding 4).
3. Run `bash scripts/cross-review.sh` on steps 7 to 9; not yet run.
4. Fuzz or near-limit test for `scanURLs`; go directive check (shared pattern 10).
5. Shared patterns 1, 3, 4, 5, 6, 7 and 8 mostly concern other repos; none were applied here.
