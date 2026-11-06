# Policy reference

The policy is one YAML file, passed with `-config`. It is read once at startup; to change it,
restart agent-guard. A policy that is empty, has an unknown key, has more than one YAML document,
or is missing a required key stops the proxy from starting.

```yaml
tools:                      # required
  - Read
  - Bash
  - "mcp__github__*"
hosts:                      # required
  - github.com
  - "*.githubusercontent.com"
paths:                      # required
  workdir: /home/me/project # optional; default: the directory agent-guard was started in
  allow:                    # required
    - /home/me/project
    - /tmp
sensitive:                  # optional
  ssh: block
  metadata: block
```

There is a longer commented file in [`examples/policy.yaml`](../examples/policy.yaml).

## Keys

`tools`, `hosts` and `paths.allow` are **required**. Give an empty list (`[]`) to allow nothing;
leaving a key out is an error, so a half-written file cannot silently allow everything.

### `tools`

The tool names the agent may call. Matching is exact and case-sensitive (`Bash` is not `bash`).

A name ending in `*` is a prefix pattern, meant for MCP tools such as `mcp__github__*`. The
prefix must be at least 3 characters, so `*` alone is rejected. A `*` anywhere else is an error.

You do not need to know your agent's tool names in advance: run it, then read them from the audit
log (see [operations](operations.md#audit-log)).

### `hosts`

Hosts that tool calls may contact. Case-insensitive. Entries are either:

- an exact host: `github.com`, or an IP literal such as `10.0.0.5`; or
- `*.example.com`, which matches any subdomain (`api.example.com`, `a.b.example.com`) but **not**
  `example.com` itself. List both if you want both.

Entries cannot contain a scheme, port or path (`https://x.com` and `x.com:443` are rejected).

A host that is not listed is still allowed if the user mentioned it themselves; see
[Host mentions](#host-mentions).

### `paths`

- `paths.allow`: directories that **structured path arguments** must be inside (see
  [Which arguments are checked](#which-arguments-are-checked)). Each entry must be absolute or
  start with `~`. A trailing `/**` or `/*` is ignored, so `~/code/**` means `~/code`. Matching is
  on whole path components: `/work` allows `/work/a` but not `/workshop`.
- `paths.workdir`: what relative paths are resolved against. Absolute or starting with `~`. If
  omitted, it is the directory agent-guard was started in. **This is an assumption**: agent-guard
  cannot see the agent's real working directory.

`~` means the home directory of the user running agent-guard.

### `sensitive`

What to do when a call touches a sensitive location. Each value is `ask` (the default) or
`block`:

| Key | What it matches |
|-----|-----------------|
| `proc_environ` | `/proc/<anything>/environ` and `/proc/<anything>/task/<anything>/environ`, including `self` and glob forms such as `/proc/*/environ` |
| `ssh` | any path with a `.ssh` component, such as `~/.ssh/id_rsa` or `/home/x/.ssh` |
| `dotenv` | a file named `.env` or starting with `.env.` (`.env.local`, `.env.production`, and also `.env.example`) |
| `metadata` | the cloud metadata address `169.254.169.254` in any numeric spelling (see below), `metadata.google.internal`, and `fd00:ec2::254` |

Unknown keys, or values other than `ask`/`block`, are errors.

These checks apply to **any access**, not only reads: agent-guard cannot tell a read from a write
inside a shell command.

## How a call is judged

For each `tool_use` block, in this order:

1. The tool name is checked against `tools`. A miss is BLOCK, rule `tool-not-declared`.
2. The tool's input (a JSON object) is scanned for hosts and paths. If it is not a JSON object, is
   larger than 1 MiB, is nested more than 16 levels deep, or names more than 256 distinct hosts or
   1024 distinct paths, that is an error and the call is blocked (`fail-closed:error`).
3. Every sensitive path or host found gives the verdict configured for its class, rule
   `sensitive:<class>` (`sensitive:ssh`, `sensitive:dotenv`, ...).
4. Every host found that is not in `hosts` and not mentioned by the user is BLOCK, rule
   `host-not-allowed`.
5. Every structured path outside `paths.allow` is BLOCK, rule `path-out-of-scope`.
6. If nothing matched, ALLOW, rule `allow`.

**All rules are evaluated and the strictest verdict wins** (BLOCK, then ASK, then ALLOW). The rule
reported is the first one, in the order above, that produced that verdict. So a call that reads
`~/.ssh/id_rsa` with `file_path` outside your allowed directories is BLOCK (`path-out-of-scope`),
even though `ssh` alone would only ask.

## Which arguments are checked

agent-guard does not know individual tools. It looks at **every string value** in the tool's input,
including nested objects and arrays, and treats a few argument names specially:

- **Structured paths**: the values of arguments named `file_path`, `path`, `notebook_path`,
  `filename`, `directory`, `dir`, `cwd` or `filepath` (any letter case). These get the path-scope
  check *and* the sensitive-path check.
- **Everything else**, including shell commands in a `command` argument and the contents of a
  file being written, is scanned for hosts and for sensitive path-like text, but is **not**
  checked against `paths.allow`. A shell command can mention any number of ordinary absolute
  paths (`/usr/bin/git`), so a scope check there would block nearly everything.

A tool that takes its target under a different argument name (say `target`) is therefore subject
to the host and sensitive checks but not to the path scope.

## How hosts are detected

From each string, agent-guard collects:

1. **URLs**: the host of anything shaped like `scheme://authority/...`. The authority ends at the
   first `/`, `?` or `#`, so `http://evil.com?@github.com` is `evil.com`, and
   `http://github.com@evil.com/` is `evil.com`.
2. **`user@host:` forms**, as in `git@github.com:org/repo.git`.
3. **IPv4 literals**, such as `10.0.0.5`.
4. **Words in shell-style text**. The text is split into tokens at spaces, quotes and a few
   punctuation characters; `;`, `|` and `&` end a command.
   - After a **network command** (`curl wget ssh scp sftp nc ncat netcat telnet ftp rsync ping dig
     nslookup host traceroute mtr socat http https`), a dotted operand is a host and the first
     dotless operand is a host (`localhost` always is), as is `user@host`. For `scp`, `rsync` and
     `sftp`, a bare dotted word like `build.tar.gz` is a local file; only `host:path` and
     `user@host` forms count. The values of `curl`/`wget` options that take a value (`-o`,
     `--output`, `-d`, `-H`, `-O` for wget, and similar) are skipped.
   - **Anywhere else**, a dotted word counts as a host if its last label is one of: `com net org
     io dev ai app cloud xyz info biz co us uk de fr ru cn jp br au ca nl se eu tv ly gg onion
     internal local`. File extensions such as `.py`, `.sh` or `.md` are deliberately not on the
     list, so `main.py` is not a host.
   - After `git`, a `host:path` word is a host (`git clone evil.example:org/repo.git`).
   - Words are also split at `:`, so `--connect-to github.com:443:evil.com:443` yields both hosts.
     Ports are ignored.
5. **Numeric spellings of an IPv4 address** are converted to dotted form: `2852039166`,
   `0xa9fea9fe`, `0251.0376.0251.0376` and `169.254.43518` are all `169.254.169.254`. Inside a
   network command any such number is a host. Elsewhere only the metadata address is recognised,
   so that `echo 0xa9fea9fe` is flagged but a plain number such as a port is not. IPv6 addresses
   are recognised as network-command operands.

### Host mentions

A host that is not in `hosts` is allowed if it appears in a **user** message anywhere in the
conversation. The match is on whole words, case-insensitive: the text must contain `example.com`
as a word (a trailing full stop is fine), not `notexample.com` or `example.com.attacker.net`.
Tool results are never consulted, so a web page cannot authorise its own host. The mention must
use the same spelling as the call: if the call uses `169.254.43518`, writing `169.254.169.254` in
the prompt does not authorise it.

A mention only satisfies the `hosts` rule. It never clears a `sensitive:` rule.

### What the host detection cannot do

It is a heuristic and will both miss things and over-block:

- It is not a shell parser. Variables (`$HOST`), command substitution, base64, `eval`, here-documents
  and scripts written by the agent and run later can hide a host.
- Splitting is not quote-aware: a `;` inside quotes ends the network-command context.
- Option handling is only known for `curl` and `wget`. For `ssh -l user host`, `user` may be read
  as the destination.
- An unusual top-level domain (`evil.example`) is only recognised after a network command or after
  `git`; elsewhere it is invisible.
- It can over-block: URLs inside request data (`curl --data https://x.com ...`) are counted as
  hosts, a remote file name after `ssh host cat release.zip` can be read as a host, and any
  dotted word ending in a listed TLD is a host.
- Only text inside the tool's input is examined. Nothing is resolved: a name that points at a
  forbidden address passes if the name is allowed.

## How sensitive paths are detected

Besides structured paths, every token in a string that starts with `/`, `~`, `./`, `../` or
`proc/`, or that contains a `.ssh` or `.env` component, is checked. `~` is expanded, and the path
is cleaned lexically, so `/work/../home/x/.ssh/id` is caught. A relative path is checked as
written, against `workdir`, and against `/` (the shell may have changed directory), so
`cat ../../proc/self/environ` and `cd /; cat proc/self/environ` are both caught.

Symlinks and the real filesystem are never consulted: a link called `notes` pointing at
`~/.ssh` is not detected.

## Why was this blocked?

Find the call in the audit log (`jq 'select(.decision != "ALLOW")' audit.jsonl`); its `rule` and
`reason` say why.

| Rule | Meaning | What to do |
|------|---------|------------|
| `tool-not-declared` | The tool is not in `tools` | Add it, if you want the agent to have it |
| `host-not-allowed` | A host in the call is not in `hosts` and you did not mention it | Add the host, or name it in your message. Check `reason`: it might be a file name read as a host |
| `path-out-of-scope` | A path argument is outside `paths.allow` | Add the directory, or fix `workdir` if a relative path resolved somewhere unexpected |
| `sensitive:<class>` | The call touches a sensitive location | Expected. ASK needs your say-so; set the class to `block` to refuse outright |
| `fail-closed:error` | The decision itself failed (unparseable input, input too large, a limit) | The audit `reason` and the proxy's stderr log say what failed |
| `fail-closed:timeout` | The decision took longer than `-decide-timeout` | Usually a stuck or very slow policy evaluation |
| `fail-closed:overloaded` | Too many decisions were running at once | Retry |
| `fail-closed:too-many-calls` | One response asked for more than 64 tool calls | Only the first 64 are judged normally |
| `fail-closed:audit` | The audit record could not be written | Check the disk and the audit file |
