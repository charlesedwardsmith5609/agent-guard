# Step 6: BishopFox Claude sandbox lessons (docs only)

**Status: awaiting confirmation of REQUIREMENTS item 2 and the placement question.** Docs only;
no code. One commit. Branch: `improve/tldr-2026-11-09`.

## Goal

Add a **"Lessons from BishopFox's Claude sandbox write-up"** section to the threat model:

- An agent with process-level access can read process memory and make network interfaces.
- **agent-guard is not a sandbox.**
- Cite https://bishopfox.com/blog/journey-into-claudes-sandbox (TLDR InfoSec 2026-11-09).

## Files

- `README.md` — threat model section (placement TBD: new numbered "does NOT protect" item,
  short subsection, or both).
- Optionally a one-line cross-link from `docs/operations.md` or `SECURITY.md` only if Charles
  wants it; default is README threat model only.
- `REQUIREMENTS.md` — mark item 20 done after landing; record the placement decision.
- `plans/README.md` — index this step.

## Shared state

None.

## Tests

None (docs). Still run `bash scripts/check.sh` after the commit so the gate stays green.

## Out of scope

- Any runtime sandbox, seccomp, network namespace, or memory-protection feature.
- Canary egress (step 5).
