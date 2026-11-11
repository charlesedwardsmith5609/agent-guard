# Step 6: BishopFox Claude sandbox lessons (docs only)

**Status: implemented** (placement = new numbered item 11 under “What it does NOT
protect against”). Docs only; one commit. Branch: `improve/tldr-2026-11-09`.

## Goal

Add **"Lessons from BishopFox's Claude sandbox write-up"** to the README threat model:

- An agent with process-level access can read process memory and make network interfaces.
- **agent-guard is not a sandbox.**
- Cite https://bishopfox.com/blog/journey-into-claudes-sandbox (TLDR InfoSec 2026-11-09).

## Files

- `README.md` — new item **11** under “What it does NOT protect against”.
- `REQUIREMENTS.md` — mark item done after landing.
- `plans/README.md` — already indexes this step.

## Shared state

None.

## Tests

None (docs). Run `bash scripts/check.sh` after the commit.

## Out of scope

- Runtime sandbox features; step 5 canary code.
