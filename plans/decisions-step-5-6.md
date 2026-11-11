# Design decisions (step 5–6) — locked after cross-model review

Cross-reviewer: GPT-5.6 Sol (high), agent `bc-f42a3680-26ce-57a3-b050-6651371a0ed5`.
Author assessment per finding below. **Locked** means these are the decisions for
implementation once Charles approves coding.

## Per-question outcome

| ID | Author draft | Reviewer | Taken |
|----|--------------|----------|-------|
| Q1 | Flat `canaries` / `forum_tools` | AGREE | Author (flat keys) |
| Q2 | Substring, case-sensitive, min 8 | ALTERNATIVE min **16** | **Reviewer** (important) |
| Q3 | (A) sensitive class ∧ egress → BLOCK | AGREE | Author (A) |
| Q4 | Config-only `forum_tools` | ALTERNATIVE + name heuristics | **Reviewer** (critical) |
| Q5 | Non-allowlisted host only; mention ignored | ALTERNATIVE: **any** extracted host | **Reviewer** (critical) |
| Q6 | `canary-egress`, generic reasons | ALTERNATIVE `egress:canary` / `egress:sensitive:<class>` | **Reviewer** (clearer audit) |
| Q7 | After sensitive, before host | ALTERNATIVE: egress findings **first** | **Reviewer** (important) |
| Item2 | Numbered threat-model item 11 | AGREE | Author |

### Why each pick

- **Q1:** Matches existing YAML; no need for nesting.
- **Q2:** Agree 8-byte canaries are footguns; **16-byte minimum**, reject leading/trailing
  whitespace in the configured token (token must equal YAML string with no outer trim of
  interior spaces). Length counted in **bytes**. Case-sensitive literal substring in parsed
  JSON string values only.
- **Q3:** Reuse `pathClass`/`hostClass`; no new value regexes.
- **Q4:** Config-only misses unlisted forum MCP tools (the Register scenario). Take heuristic
  **in addition to** `forum_tools`: after delimiter/CamelCase split of the tool name, a
  fragment equals (case-insensitive) one of `send`, `post`, `publish`, `message`, `comment`,
  `reply`; or a fragment in `{create,update,add}` co-occurs with one in
  `{issue,discussion,pull_request,pullrequest,pr}`. Document over-match risk (e.g. tools whose
  names contain `post`).
- **Q5:** Allowlisted GitHub/etc. are common exfil paths; brief’s “non-allowed” is too weak.
  **Egress channel** = (any extracted host, allowlist and user mention ignored) OR forum-style
  tool. Local-only calls with a canary but no host and not forum-style are not blocked by this
  rule.
- **Q6:** `egress:canary` and `egress:sensitive:<class>`; reasons name the rule class only,
  never the matched value.
- **Q7:** Collect egress findings first so equal BLOCK reports the high-signal egress rule:
  `egress:canary` → `egress:sensitive:<class>` → tool → sensitive → host → scope.
- **Item2:** New numbered item under “What it does NOT protect against”.

## Extra locks (reviewer “Missing”)

1. **Bounds:** at most 64 canaries; each 16–256 bytes; at most 64 `forum_tools` patterns
   (same prefix rules as `tools`).
2. **Audit previews:** configured canary substrings are redacted in `args_preview` / `reason`
   (pass the canary list into the audit redactor from `main` when constructing the writer, or
   equivalent; Engine remains the owner of the list, immutable copy handed to audit at startup).
3. **Decide loop:** cancellation checks while scanning string values (same spirit as extract’s
   periodic `ctx.Err()`).
4. **Ownership:** Engine immutable after Parse; canary/forum slices owned by Engine; audit
   receives a read-only copy of canary strings at construction — no new mutex.

## Deviates from brief wording (intentional)

- Host leg is **any** host, not only non-allowlisted (Q5).
- Forum tools include **heuristics**, not only a config list (Q4).

Document both in `docs/policy.md` and the README decision table.
