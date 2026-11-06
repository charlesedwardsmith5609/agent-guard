# Security policy

agent-guard is a security control, so bugs in it matter. Please report them.

## What counts as a vulnerability

Report anything that lets a tool call get past the behaviour documented in the
[README](README.md) and [docs/policy.md](docs/policy.md), for example:

- a tool call that the policy says to block or ask about, but that reaches the agent harness intact;
- a way to make the proxy forward a `tool_use` block without judging it (streaming and
  non-streaming), or to make an ALLOW leave the proxy without its audit record being written;
- a secret that reaches the audit log or a span despite the documented redaction;
- a crash or unbounded resource use caused by a crafted request or upstream response.

## What does not

The README's [threat model](README.md#what-it-does-not-protect-against) lists what agent-guard
does not protect against. Shell obfuscation that defeats the host and path heuristics, symlink
tricks, exfiltration through an allowlisted host, and use of a client that bypasses the proxy are
documented limitations, not vulnerabilities. Reports that show a *new* way around a documented
protection are welcome; reports that restate a documented limit are not needed.

## How to report

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Include what you did, what you expected, and what happened (a failing
test or a minimal request that shows the problem is ideal). Please do not post exploit details in
public issues.

## Supported versions

The project is pre-1.0; only the latest commit on `main` is supported.
