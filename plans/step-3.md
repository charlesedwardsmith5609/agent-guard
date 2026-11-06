# Step 3 (Phase 3): rules engine

Adds the only new dependency allowed for this phase: `gopkg.in/yaml.v3`. Everything else is the
standard library. See "Decisions made unattended" in `REQUIREMENTS.md` (items 10 to 13).

## Files
- `internal/rules/config.go`: `Config`, `Parse([]byte) (*Engine, error)`, `Load(path)`. Strict
  YAML (`KnownFields(true)`); validation errors are returned, never defaulted away.
- `internal/rules/engine.go`: `Engine` implements `policy.Decider`.
- `internal/rules/extract.go`: pull hosts and paths out of a tool call's JSON input.
- `internal/rules/sensitive.go`: sensitive path and host classification.
- `internal/rules/*_test.go`: table-driven tests.
- `cmd/agent-guard/main.go`: `-config` flag (required), `rules.Load`, replaces `DenyAll`.
- `go.mod`/`go.sum`: add `gopkg.in/yaml.v3`.

## Types
```go
type Config struct {
    Tools     []string           `yaml:"tools"`      // exact names; trailing * is a prefix
    Hosts     []string           `yaml:"hosts"`      // exact or *.suffix, case-insensitive
    Paths     PathsConfig        `yaml:"paths"`      // workdir, allow (dir prefixes, ~ expanded)
    Sensitive map[string]string  `yaml:"sensitive"`  // proc_environ|ssh|dotenv|metadata: ask|block
}
type Engine struct { /* immutable after Parse */ }
func (e *Engine) Decide(ctx, policy.Context, policy.ToolCall) (policy.Decision, error)
```

## Rules (all evaluated; strictest verdict wins; ties keep the first in this order)
1. `tool-not-declared`: tool name matches no entry of `tools` gives BLOCK.
2. `sensitive:<class>`: any extracted path or host in a sensitive class gives the configured
   verdict (default ASK). Classes: `/proc/<x>/environ` (any pid or `self`), any `.ssh` path
   segment, basename `.env` or `.env.*`, host `169.254.169.254` (dotted, decimal, hex and
   octal-dotted forms) plus `metadata.google.internal`.
3. `host-not-allowed`: an extracted host not in `hosts` and not mentioned in user text gives BLOCK.
4. `path-out-of-scope`: a structured path argument outside every `paths.allow` prefix gives BLOCK
   (an empty list allows no paths). Relative paths resolve against `paths.workdir` (default: the
   process working directory at load). `..` is resolved lexically; symlinks are not followed.
5. Otherwise ALLOW with rule `allow`.

## Review outcomes folded in
- `tools`, `hosts` and `paths.allow` must be present (an explicit empty list is valid and allows
  nothing). Omitting any is a config error, so a blank config cannot fail open.
- `paths.workdir` and every `paths.allow` entry must be absolute or start with `~`; otherwise a
  config error. `workdir` defaults to the process working directory at load.
- Tool patterns: exact names, or a trailing `*` prefix pattern (for MCP names). A bare `*` or a
  prefix shorter than 3 characters is a config error.
- Hostname-shaped tokens anywhere in any string are hosts when their last label is in a built-in
  list of common TLDs (file-like ones such as sh, py, rs, md, in, cc are excluded), in addition
  to URL, `user@host:` and network-command arguments. Heuristic; documented in the README.
- `Decide` checks `ctx.Err()` during traversal and between rules.
- README is written in the final step so it describes the finished system.
- Extra tests: unlisted network command (`ping evil.com`), host mention case-insensitivity
  (`Example.COM`), relative workdir/allow rejected, missing required keys, cancellation.

## Extraction
- Input must be a JSON object; anything else returns an error (the guard turns it into BLOCK).
- Walk every string value (nested objects and arrays, depth capped at 16, 1 MiB total).
- Hosts: `scheme://host` URLs, `user@host:` forms, IPv4 literals, and bare host tokens that
  follow a network command (`curl wget ssh scp nc ncat telnet ftp rsync git`).
- Paths: values of known path keys (`file_path path notebook_path filename directory dir cwd`)
  are structured paths. Tokens in any string that start with `/`, `~`, `./`, `../`, or whose
  basename starts with `.env`, are candidate paths for sensitive checks. Tokens are split on
  whitespace, quotes and shell operators; `--flag=value` is split at `=`.
- `~` expands to the user's home (`os.UserHomeDir` at load).

## Ownership
`Engine` is immutable after `Parse`; it has no mutex, goroutine or channel and is safe for
concurrent `Decide` calls. Nothing is shared.

## Tests (table-driven, `go test -race`)
- Config: valid; unknown key; bad sensitive class/value; bad host pattern; empty file; missing
  file.
- Tool allow/deny incl. prefix patterns.
- Hosts: allowlisted, wildcard, mentioned in prompt (whole-token only; `evil.com.attacker.net`
  does not match `evil.com`), not allowed; metadata endpoint in all numeric forms stays ASK even
  when mentioned or allowlisted.
- Sensitive paths: `/proc/self/environ`, `/proc/1234/environ`, `~/.ssh/id_rsa`, `/home/x/.ssh`,
  `.env`, `app/.env.local`, via `file_path`, via Bash command text, via flags; traversal
  (`/ok/../home/x/.ssh/id`); `sensitive.<class>: block` override.
- Scope: inside, outside, relative, `..` escape, prefix confusion (`/work` vs `/workshop`).
- Strictest wins; error inputs (non-object, invalid JSON, depth bomb) return an error.
- End to end through a real proxy listener: a blocked tool call is replaced; an allowed one
  passes (`cmd/agent-guard` test with a config file).

## Addendum: fixes from the cross-review of the rules commits
- URL authority ends at `/`, `?` or `#` (`http://evil.com?@github.com` is evil.com).
- Hosts and candidate paths are deduplicated and capped; user text is scanned once for all
  wanted hosts; `ctx` is checked in every loop.
- Relative paths are checked for sensitivity both as written and resolved against `workdir`.
- `git host:path` remotes are recognised; inside network commands, dotted tokens with file-like
  endings (`out.txt`, `file.zip`) are not hosts.
- `looseIPv4` implements all `inet_aton` forms (1 to 4 parts).
- Exactly one YAML document is accepted; `Load` reads at most 1 MiB.
