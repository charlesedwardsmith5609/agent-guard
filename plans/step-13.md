# Step 13: record the credential-brokering decision (docs only)

The maintainer answered the open question in `docs/credential-brokering.md`: a placeholder-token
mode is not built for now. This step records that answer. No Go code, no behavior, no new
dependency, no shared state.

## Change

- `docs/credential-brokering.md`: replace the open question with a dated decision and its reasons.
- `DECISIONS.md`: one entry.
- `CHANGELOG.md`: change the sentence that said the note ends with an open question.

## Tests (agreed list, natural language)

Prose only. The existing documentation tests (links resolve, policy examples load, flags
documented) must stay green.

## Files

- docs/credential-brokering.md
- DECISIONS.md
- CHANGELOG.md
- plans/step-13.md
