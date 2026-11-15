# The Ask verdict

This note describes what Ask does today, what it does not do, and a proposed approval flow for
unattended runs. It does not add a verdict or a control. Allow, Block, and Ask are already the
three verdicts in `internal/policy`.

## What Ask does now

Every tool call is judged by every rule. The strictest verdict wins: Block, then Ask, then Allow.

Ask is the default for a sensitive location (`proc_environ`, `ssh`, `dotenv`, `metadata`) when
that class is not set to `block`. A sensitive value on an egress channel is Block
(`egress:sensitive:<class>`), which outranks Ask. The metadata address is in that category, so a
call that contacts it is blocked even if the class is left at `ask`.

An Ask does not run the tool. The proxy replaces the tool call with a text notice:

```
[agent-guard] A tool call requires approval and was not executed (rule: <rule>). Ask the user to approve it.
```

The notice does not include the tool name or the arguments. The audit line records the verdict
`ASK`, the rule, the redacted reason, and the argument hash.

If every tool call in the response was replaced, a `stop_reason` of `tool_use` becomes
`end_turn`. The turn ends. The model does not see the notice until the next user message. If at
least one call in the same response was allowed, the agent runs that call and the notice is in
the same message, so the model sees it on its next step.

## Gaps

Ask is a notice, not an approval flow.

- Nothing waits. There is no timeout, no queue, and no second request that turns an Ask into an Allow.
- Nothing asks a person. The notice tells the model to ask the user. The proxy has no channel to a human.
- The model can retry the same action in another form. A retry is a new call and is judged again. It is not attached to the earlier Ask.
- There is no approval token. The tool-use id and the argument hash are in the audit log, but nothing checks them later.
- Text in the conversation cannot approve a call. User text can only satisfy the host-mention exception, and tool results are ignored for that exception. Neither is an approval of an Ask.
- An unattended run has no user to answer the notice. The model is instructed to do something it cannot do. It may stop, loop, or rephrase the call.
- A harness that shows the notice and lets a person click through has no way to tell the proxy about the click. The proxy has already replaced the call.

## Proposed flow for unattended runs

Do not add a fourth verdict. Ask already means "do not run this until someone says so." The
missing piece is what happens when nobody says so.

Proposal, not implemented:

1. On Ask, do not execute the call. Write the audit line as today, including the tool-use id and the argument hash. Those two values identify the request.
2. An approval, if one is added later, must come from a channel the model cannot write. A sentence in the transcript is not an approval. The approval must name the tool-use id and the argument hash, so a later call with different arguments does not reuse it.
3. For an unattended run, assume there is no approver. Start a short timer when the Ask is recorded. If no matching approval arrives before the timer fires, the outcome is deny. The call stays unexecuted, and a second audit line records the deny (rule `ask-timeout`, verdict Block) so a report does not show a pending Ask.
4. Fail closed. If the approval channel cannot be reached, or the timeout is unset, deny. Do not leave the call pending and do not let it run.
5. A deny is final for that tool-use id. A new model attempt is a new call and is judged from scratch. It does not inherit a previous approval.
6. Attended runs can use the same timer. A person who does not answer in time gets the same deny. That is the point of a timeout: silence is not a yes.

The timeout in this proposal is separate from `-decide-timeout`, which only bounds how long the
policy evaluation may take. Suggested default if this is built later: a few seconds, configurable,
and deny when the value is missing or not a positive duration. This document does not choose a
number, because no timer exists yet.
