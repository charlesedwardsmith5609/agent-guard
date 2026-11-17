# Step 11: credential brokering design note (docs only, nothing built)

Covers requirement 26 only. Step 12 (redaction tests) is separate.

## Problem

Shopify's attacker-agent write-up (as summarised by TLDR InfoSec, 2026-11-16) lists four
containment measures: read-only ephemeral credentials, a credential-swapping proxy, an egress
allowlist, and an independent judge agent on a different model. `docs/operations.md` says the
agent's API key passes through the proxy unchanged, and the README threat model (item 7) says the
proxy sees it in transit. There is no written statement of where agent-guard sits against that
list, or of what a placeholder-token mode would change.

## Change

New file `docs/credential-brokering.md`, plus a README documentation-table row, a
`CHANGELOG.md` entry and the pointer from README threat-model item 7. Sections:

1. Scope and sources. State that this is a design note and nothing in it is built. State that the
   containment list is taken from the brief and the TLDR summary: the Shopify write-up itself was
   not fetched (network rule), and Shopify, 1Password for Agents and ChatGPT Wallet descriptions
   are vendor claims.
2. Comparison table, one row per containment item, with a status (has, partly, out of scope) and
   file references. Draft verdicts, each checked against the code before the note is written:
   - Read-only ephemeral credentials: out of scope. Nothing mints, scopes or expires a credential.
     The nearest controls limit what the agent may do (`internal/rules` tools, paths, hosts), not
     what a credential may do.
   - Credential-swapping proxy: out of scope today. `internal/proxy/proxy.go` (`copyHeaders`)
     copies credential headers (`Authorization`, `x-api-key`) to the upstream unchanged. The only
     other header changes in `forward` are: hop-by-hop headers and `Host` are not copied,
     `Content-Length` is dropped, `Accept-Encoding` is forced to `identity`, and
     `X-Agent-Guard-Identity` is removed.
   - Egress allowlist: partly. A host allowlist over hosts extracted from tool-call arguments
     (`internal/rules/engine.go` `hostAllowed`, `extract.go`), with the canary and sensitive
     egress rules. Separately, each proxy process routes model traffic to one configured
     `-upstream` (`cmd/agent-guard/main.go`, `proxy.go` `forward`). That is routing, not network
     egress enforcement: the transport also honours `HTTP(S)_PROXY` (`operations.md`). The guard
     does not see packets, DNS or the harness's own traffic, and a host the user names is
     allowed (README threat model 3 and 5).
   - Independent judge on a different model: out of scope. The engine is deterministic;
     REQUIREMENTS.md "Not done" lists the optional judge. The pairing-kit review scripts use a
     second provider at development time only (`scripts/review-call.sh`).
3. The API key in transit. What happens today, with citations. Then an optional placeholder
   mode, described as a sketch: the agent holds a placeholder, the proxy checks it and swaps in
   the real credential when it forwards. State the minimum behavior a mode must have to mean
   anything: reject a missing or wrong placeholder, strip every inbound credential header
   (`Authorization` and `x-api-key`) and inject exactly one on both routes (`/v1/messages` and
   `/v1/messages/count_tokens`), never follow a redirect with the credential (the client already
   refuses redirects), and require an `https` upstream. List what it adds (the proxy becomes a long-lived secret
   holder and a bigger target, a new secret source and its file permissions, same-user process
   readability, an authenticated listener becomes a prerequisite because the port would then be
   a capability, upstream error bodies that might echo credentials, `https`-only upstream) and
   what it removes (the real key in the agent's environment, config and process memory, in
   `env` output and tool results that reach the model, in anything the harness itself logs, and
   on the plaintext agent-to-proxy hop, which README threat model 7 calls out). Also an
   abuse path that stays: any local process that can reach the unauthenticated listener could
   use the stored credential as an API oracle, whether or not it holds the placeholder.
   Also state what it does not change: credentials the harness's tools use (git, cloud CLIs)
   never pass through this proxy, and the proxy cannot see them.
4. Open question for the human: does the mode belong in this project? Include a lean and the
   smaller prerequisite step, without deciding.

## Types and ownership

No Go types change and no shared state is touched. Nothing in the note adds a flag or a type. The
note names the owner of the state a future mode would add (an immutable credential value held by
the proxy after load, same as the engine), as a design statement only.

## Tests (agreed list, natural language)

Prose has no behavior to run. The existing documentation tests in `cmd/agent-guard/docs_test.go`
(relative links resolve, policy examples load, flags documented) already run over `docs/*.md` and
`README.md` and must stay green. The note's claims are checked by hand against the code before
the commit: each cited file and symbol exists (a grep per citation, recorded in the commit
message).

## Files

- docs/credential-brokering.md
- README.md
- CHANGELOG.md
- REQUIREMENTS.md
- plans/step-11.md

Edits to shared files are limited to: one documentation-table row and one threat-model pointer in
README.md; one Added entry in CHANGELOG.md; the new 2026-11-16 section (requirements 26 and 27) in
REQUIREMENTS.md.
