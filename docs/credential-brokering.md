# Credential brokering: where agent-guard sits

This is a design note. **Nothing in it is built**, no flag or type was added, and it changes no
behavior. It compares agent-guard with a published containment list, answers what the API key's
path through the proxy means today, and evaluates an optional placeholder-token mode. It ends with
a question for the maintainer.

## Sources and how far to trust them

- The containment list comes from the brief for this note, which cites Shopify's "Cyber Chaos
  Monkey" write-up (https://shopify.engineering/cyber-chaos-monkey, via TLDR InfoSec,
  2026-11-16): read-only ephemeral credentials, a credential-swapping proxy, an egress allowlist,
  and an independent judge agent on a different model. **The write-up itself was not read for this
  note**; the four items are taken as the brief states them. Treat them as Shopify's description
  of its own system, not as verified facts.
- 1Password for Agents (an agent signs in without seeing the password,
  https://1password.com/blog/1password-for-agents-security-privacy) and ChatGPT Wallet (an agent
  buys without seeing card details, TLDR AI 2026-11-16) are vendor claims. They are used here only
  as examples of one idea: the agent holds a reference, and something else holds the secret.
- Every statement about agent-guard cites a file. A path with a symbol name (for example
  `internal/proxy/proxy.go` `copyHeaders`) names a function or type in that file. Line numbers are
  left out because they drift.

## Comparison

| Containment item | agent-guard | Where in the code |
|------------------|-------------|-------------------|
| Read-only, ephemeral credentials | **Out of scope** | Nothing mints, scopes, rotates or expires a credential. |
| Credential-swapping proxy | **Out of scope** | `internal/proxy/proxy.go` `copyHeaders`, `forward` |
| Egress allowlist | **Partly** | `internal/rules/engine.go` `hostAllowed`, `Decide`; `internal/rules/extract.go` |
| Independent judge on a different model | **Out of scope** | `internal/rules/engine.go` (deterministic); `REQUIREMENTS.md` "Not done" |

### Read-only, ephemeral credentials: out of scope

agent-guard issues, scopes, rotates and revokes no credential. The only code that touches
credential values does something else with them: `internal/audit/redact.go` removes
secret-shaped text from audit previews, and `internal/proxy/proxy.go` carries the agent's headers
through. The nearest controls limit
what the agent may *do*, not what a credential may *do*:

- the `tools`, `hosts` and `paths.allow` keys of the policy (`internal/rules/config.go`,
  [policy.md](policy.md));
- the halt switch (`internal/halt/switch.go`), which refuses tool calls and new requests. It stops
  the agent. It does not revoke any credential the agent already holds.

A read-only, short-lived credential is a property of whatever issues it (a cloud IAM role, a
GitHub app token). It would have to be arranged outside agent-guard.

### Credential-swapping proxy: out of scope today

The proxy does not rewrite credentials. `copyHeaders` copies every request header except the
hop-by-hop ones and `Host`, so a credential header such as `Authorization` or `x-api-key` reaches
the upstream unchanged. The code does not name or inspect any credential header. `forward` makes
these other header changes: `Content-Length` is dropped, `Accept-Encoding` is forced to
`identity`, and `X-Agent-Guard-Identity` is removed. This matches
[operations.md](operations.md#running-it): "agent-guard forwards request headers (including the
key) to the upstream unchanged and never records them".

### Egress allowlist: partly

What exists:

- A host allowlist over the hosts found in tool-call arguments (`hosts`, matched by `hostAllowed`
  in `internal/rules/engine.go`; the hosts come from `internal/rules/extract.go`). A host that is
  not listed is `BLOCK` unless the user named it in their own messages (`Decide`, `mentionedHosts`).
- Two egress-triggered rules: a configured canary string, or a sensitive path or host, in the
  arguments of a call that has an egress channel is `BLOCK` (`egress:canary`,
  `egress:sensitive:<class>` in `Decide`).
- The proxy sends model traffic to one `-upstream` per process (`cmd/agent-guard/main.go`,
  `internal/proxy/proxy.go` `forward`). That is routing, not enforcement: the transport also
  honours `HTTP_PROXY` and `HTTPS_PROXY` ([operations.md](operations.md#running-it)).

What does not:

- The guard reads tool arguments, not packets or DNS. A destination that never appears in the
  arguments is not checked, and shell text is parsed heuristically (README threat model, items 3
  and 5; [policy.md](policy.md#what-the-host-detection-cannot-do)).
- It does not constrain the harness's own network activity or anything outside the model's
  `tool_use` blocks (README threat model, item 2).
- A host the user mentions is allowed, including text the user pasted (README threat model, item 5).

So it is an allowlist applied to what the model asks for, not a network egress control.

### Independent judge on a different model: out of scope

`Decide` in `internal/rules/engine.go` is deterministic: rules over extracted hosts, paths and
tool names, strictest verdict wins. No model is called at run time. `REQUIREMENTS.md` ("Not
done") lists an optional judge model for ambiguous calls as not built. The only second model in
this repository reviews *development* artifacts: `scripts/plan-review.sh` and
`scripts/cross-review.sh` send a plan or a diff to another provider through
`scripts/review-call.sh`. That is not a run-time control.

## The API key in transit

### What happens today

The agent holds the real key and sends it on every request to the proxy, over plain HTTP on
loopback (`-listen`, default `127.0.0.1:8787`; nothing enforces loopback, and the listener has no
authentication: README threat model, item 1). `copyHeaders` copies it onward to the upstream.
It is never logged: the audit record has no headers ([operations.md](operations.md#audit-log))
and spans carry no headers either (`internal/telemetry`, [operations.md](operations.md#opentelemetry)).
The proxy does not store it, so it exists in proxy memory only while a request is in flight.

What that leaves exposed is the agent's side, not the proxy's. The key is wherever the agent
keeps it: its environment, its configuration, its process memory. A model that is steered into
printing the environment puts the key in a tool result, and from there into the conversation. The
policy only asks about that kind of access (`proc_environ`, `.env` and similar: `sensitive:<class>`
in `internal/rules/sensitive.go`, ASK by default), and only for the forms it can recognise in
arguments.

### Optional mode: placeholder token, swapped at forward time

Sketch only. The agent is given a placeholder instead of the real key. The proxy holds the real
key, checks the placeholder on each request, and puts the real key on the upstream request.

For the mode to mean anything it must:

- reject a request with a missing or wrong placeholder;
- strip every inbound credential header (`Authorization` and `x-api-key` both) and send exactly
  one real credential, on both routes the proxy forwards (`/v1/messages` and
  `/v1/messages/count_tokens`);
- never send the credential to a redirect target. The client already refuses redirects
  (`CheckRedirect` in `New`, `internal/proxy/proxy.go`);
- require an `https` upstream, because `-upstream` also accepts `http`
  ([operations.md](operations.md#flags)).

**What it removes**

- The real key from the agent's environment, configuration and process memory. A leaked
  environment, a crash dump or a harness log holds a placeholder.
- The key from tool results that reach the model, when the model prints `env` or reads a config
  file.
- The key from the plaintext agent-to-proxy hop (README threat model, item 7). Only the
  placeholder crosses it.
- A placeholder that leaves the machine is worth little: it works only against this proxy. (On
  the same machine it is worth more; see the listener point below.)

**What it adds**

- The proxy becomes a long-lived secret holder. Today the key is in memory only per request.
  The mode needs a source for it (an environment variable or a file), with its permissions, its
  rotation and its backups.
- A bigger target. The proxy, its configuration and its host now hold the credential. README
  threat model, item 7 ("a compromised machine, proxy host, policy file or audit file") would
  cover a real secret store, not just a transit point.
- **Same-user readability.** If the proxy runs as the agent's user, the agent can read the
  secret from `/proc/<pid>/environ` or the secret file. The policy's sensitive-location check
  is heuristic and covers tool arguments only (`internal/rules/sensitive.go`, README threat model,
  item 3), so it is not a barrier. The mode needs the proxy under a different account.
- **The unauthenticated listener becomes a capability.** The only gate in front of the real key
  would be the placeholder, and the placeholder sits wherever the agent keeps its key today,
  readable by any process running as the same user. Such a process can use the real key through
  the proxy, and the audit log would show it as the same agent (the identity is a label:
  [policy.md](policy.md#profiles-and-agents)). Authenticating the listener (a unix socket, or a
  per-agent secret) becomes a prerequisite. `plans/step-10.md` lists that as a suggestion that
  was not built.
- New leak paths to check: upstream error bodies are passed through up to 1 MiB
  (`internal/proxy/proxy.go`, `maxPassThroughBody`), and an upstream that echoes the
  credential in an error would hand it to the agent. The audit redactor's coverage of credential
  shapes is only heuristic (`internal/audit/redact.go`, README threat model, item 10).
- Configuration surface and failure modes: a missing or wrong key now fails every request. That
  fails closed, which is the project's default, but it is a new way to take the agent down.

**What it does not change**

- The credentials the agent's *tools* use (git, a cloud CLI, a database client) never pass
  through this proxy. agent-guard sits between the harness and the model API and sees tool
  *arguments*, not tool traffic. The leak path in the AntiFox reports (database and cloud
  credentials read from application configuration, then used elsewhere:
  https://thehackernews.com/2026/11/antifox-ai-pentesting-platform-linked.html, a vendor and
  press description) is the tools' credentials, and this mode does not touch it. A credential-
  swapping proxy in the sense of the containment list sits in front of *tool* egress, which is
  a different place from where agent-guard sits.
- A model-API key is worth less to an attacker than a cloud credential: its misuse is mostly
  cost and abuse of that account, though that can still be real money.
- The agent can still ask the proxy to make model calls. The mode protects the key, not the use
  of the key.

### What this note does not decide

How the real key would be loaded, whether other providers' credentials would be handled, and how
Claude Code's other authentication forms (for example a login token instead of an API key) would
work with a placeholder are not checked here. The live tests in `scripts/live-claude-test.sh`
use an API key in `ANTHROPIC_API_KEY`; nothing was tried with a placeholder.

## Decision

**Decided 2026-11-16: not now.** A placeholder-token mode does not belong in agent-guard at this
point. The maintainer agreed with the lean below. Nothing is built, and nothing changes in the
code or the policy.

Reasons (from the evaluation above):

1. It protects one credential, the model-API key, that the proxy already sees, while the
   credentials that matter in the AntiFox-style cases are the tools' and are out of reach.
2. It turns a stateless inspector into a secret holder, and it does that on a listener with no
   authentication, so the proxy becomes the capability it was meant to hide.
3. The cheaper first step is the prerequisite it needs anyway: authenticate the listener (a unix
   socket, or a per-agent secret compared in constant time and never logged). That is a separate
   suggestion (`plans/step-10.md`) and is not scheduled by this decision.

If the question is reopened, the order would be: listener authentication, then the mode, behind
an explicit flag and off by default, with the proxy run under a separate account.
