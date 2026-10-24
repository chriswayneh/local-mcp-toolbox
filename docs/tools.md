# Tool Catalog

All current tools are read-only. Every returned response uses the common envelope with a summary, structured data, and metadata that reports redactions, truncation, and whether returned data is untrusted.

## System

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `system_info` | None | OS, architecture, Python version, CPU count, capture time | Does not return environment variables, usernames, home paths, or processes. |
| `disk_usage` | None | Aggregate bytes total, used, and free for the server working volume | Does not enumerate file paths. |
| `installed_developer_tools` | None | Availability of a fixed allowlist: Git, Docker, kubectl, Python, Node, npm, Terraform | Resolves availability only; does not execute programs or disclose executable paths. `kubectl` is a name in that list only. There is no Kubernetes client or API call. |
| `toolbox_metrics_snapshot` | None | Aggregate request counts, outcomes, modules, uptime, and latency | In-process counters only; excludes arguments, responses, request/client identifiers, and integration targets. |

## Filesystem

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `filesystem_list_directory` | Absolute `path`, optional `limit`, optional `offset` | Immediate policy-approved entry names, types, sizes, timestamps, and bounded-prefix metadata | Path resolves canonically inside an approved root; sensitive names and inaccessible entries are omitted, and traversal stops at `max_directory_entries` before sorting. |
| `filesystem_file_metadata` | Absolute `path` | Filename, type, size, and modification timestamp | Requires an approved root, extension allowlist, and sensitive-file blocklist check. |
| `filesystem_read_text_file` | Absolute `path` | UTF-8 text (replacement decoding), size, and redaction metadata | Requires all metadata checks, maximum file size, global result bound, and central secret redaction. |

Filesystem content is untrusted data. The MCP client must never interpret its contents as instructions or allow it to change permissions, configuration, or tool behavior.

## Configuration example

Filesystem tools are unavailable unless a profile contains explicit approved roots. Configure the smallest possible root set:

```yaml
profile: standard
filesystem:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-project
  allowed_extensions: [".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".ts"]
  blocked_patterns: [".env", ".env.*", "id_rsa", "id_ed25519", "*.pem", "*.key", "credentials*"]
  max_file_bytes: 240000
  max_directory_entries: 500
```

The `restricted` default includes no approved roots, so filesystem requests are denied until the operator configures one deliberately. The 240,000-byte default remains below the 262,144-byte response cap so ordinary oversized files receive the documented maximum-file error before response serialization.

## Git

**Linux only.** On macOS and Windows every Git tool returns an `UNSUPPORTED_OPERATION` error and Git is never started. Use the Linux container on those hosts. See [Git platform support](security-model.md#git-platform-support).

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `git_repository_status` | Absolute approved `repository` path | Current branch tracking metadata and bounded changed-file status | Requires Git integration, filesystem-root containment, and exact repository allowlist match. Uses `git status --porcelain=v1 --branch --ignore-submodules=dirty`, so uncommitted edits inside a submodule's own work tree are not reported (a submodule pointing at a different commit still is). |
| `git_current_branch` | Absolute approved `repository` path | Branch name or detached `HEAD` short commit | Uses fixed `git branch --show-current` / `git rev-parse --short HEAD` arguments. |
| `git_recent_commits` | Absolute approved `repository` path, optional bounded `limit` | Commit hashes, author, ISO timestamp, and subject | Uses a fixed `git log --no-show-signature` format, so no signature verifier runs. Commit messages and identities are untrusted and redacted. |
| `git_diff_summary` | Absolute approved `repository` path | Per-file added/deleted-line counts for unstaged tracked changes | Uses `git diff-files -z --raw --numstat --no-ext-diff --no-textconv --ignore-submodules=dirty`, which never rewrites `.git/index`. Raw and numstat records are matched by path, and only stat-only rows (one raw record, status M, same mode, 0/0 lines) are omitted. Never returns diff content, never runs external diff or textconv programs, and does not report uncommitted edits inside submodules. |

Each approved repository must be a main working tree with its own `.git` directory. The Git tools refuse, with a specific reason, a `.git` that is a symlink or a `gitdir:` file (linked worktrees from `git worktree add` and submodule checkouts), a `.git/commondir` file, and any `objects/info/alternates` entry, followed through the whole alternates chain, that leaves the repository (clones made with `git clone --shared` or `--reference`). A symlink at `.git/objects`, `refs`, `HEAD`, `config`, `packed-refs`, `logs`, `info`, or `worktrees` is refused too. So is a symlink at any depth under `.git/objects` or `.git/refs`, an `objects/info/http-alternates` file, and a `GIT_ALTERNATE_OBJECT_DIRECTORIES` setting in the server environment. The check is repeated after Git exits, and output is discarded if the `.git` directory changed while Git ran. Git always runs with explicit `--git-dir`/`--work-tree` and `GIT_CEILING_DIRECTORIES`, so a repository-local `core.worktree` cannot redirect it.

The Git module invokes only fixed, read-only argument templates through `subprocess` with `shell=False`, a scrubbed non-interactive environment, a configured timeout, and a configured output cap. Every command also passes `--no-lazy-fetch` plus `-c` and `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>` overrides that disable repository-chosen programs and network/helper hooks (`core.fsmonitor`, `core.hooksPath`, `diff.external`, `protocol.allow=never`, `core.sshCommand=false`, `core.askPass=false`, `core.alternateRefsCommand=false`, `credential.helper=`, and every configured `filter.<driver>` clean/smudge/process command), refuses repositories whose `.git/config` is malformed or defines a filter driver name containing `=` or non-printable characters, and sets `GIT_OPTIONAL_LOCKS=0`, `GIT_NO_LAZY_FETCH=1`, `GIT_ASKPASS=false`, and `SSH_ASKPASS=false`. It has no generic command tool.

**Escaped characters in Git output.** File names and commit subjects can hold invisible characters that change how a terminal or editor shows text, for example a color code or a right-to-left override that makes `evil\u202etxt.md` look like a different name. So every Git tool escapes them before returning anything:

- A backslash becomes two backslashes (`\\`).
- Control characters U+0000 to U+001F, U+007F, and U+0080 to U+009F become `\xNN`. A tab is `\x09` and a newline is `\x0a`.
- These invisible or reordering characters become `\uNNNN`:
  - bidi controls U+202A to U+202E and U+2066 to U+2069, and the marks U+200E, U+200F, and U+061C
  - zero-width and invisible characters U+200B to U+200D, U+2060 to U+2064, U+FEFF, the soft hyphen U+00AD, and U+180E
  - the separators U+2028 and U+2029
  - variation selectors U+FE00 to U+FE0F
  - lone surrogates U+D800 to U+DFFF
- Tag characters U+E0000 to U+E007F and variation selectors U+E0100 to U+E01EF become `\UNNNNNNNN` (eight hex digits).

Other text, including accented letters, other scripts, and most emoji, is returned as is. Emoji built with a zero-width joiner (U+200D) or a variation selector (U+FE0F) come back with those parts escaped. This list covers the characters known to hide or reorder text; it is not a promise that no other Unicode character can look misleading (for example, look-alike letters from other scripts are kept). Secrets are redacted before escaping, so redaction still sees the original text. `git_repository_status` paths with unusual characters are additionally quoted by Git itself and then escaped like any other text, so `new<BEL>file.md` comes back as `"new\\afile.md"`.

Enable Git only with an exact repository allowlist in addition to the filesystem root:

```yaml
profile: standard
filesystem:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-project
integrations:
  git: true
git:
  approved_repositories:
    - C:\\absolute\\path\\to\\approved-project
```

## GitHub

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `github_repository_summary` | Exact approved `owner/repository` | Visibility, lifecycle, branch, issue-count, license, topic, and activity metadata | Requires GitHub and external-network opt-ins plus an exact repository allowlist. |
| `github_recent_issues` | Approved repository, optional bounded `limit`, state | Issue number, title, state, author, labels, timestamps, and URL | Filters pull requests from the issues endpoint; bodies and comments are never returned. |
| `github_recent_pull_requests` | Approved repository, optional bounded `limit`, state | Pull-request number, title, state, refs, author, timestamps, and URL | Returns metadata only; patches, diffs, comments, and file contents are excluded. |

GitHub uses a fixed `https://api.github.com` origin, bounded `GET` requests, the global timeout and output limits, and central redaction. It never accepts a configurable URL or exposes mutation methods. Public repositories work without authentication; set `GITHUB_TOKEN` in the server environment for private repositories or higher API limits. The token is sent only as an authorization header and is never returned or logged.

```yaml
profile: standard
integrations:
  github: true
  external_network: true
github:
  approved_repositories:
    - owner/repository
```

## Python Environments

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `environment_audit_python_venv` | Absolute approved `environment_path`, optional bounded `limit` | Static environment facts, installed package identities, abnormal dependency findings, counts, warning codes, and completeness flags | Separate root allowlist, canonical containment, component link/junction rejection, race-aware bounded reads, central redaction, and no target execution. |

The auditor opens only root `pyvenv.cfg` and exact immediate
`.dist-info/METADATA` files in recognized Windows or POSIX layouts. It never
launches Python or Pip, imports installed code, starts a shell, uses the network,
or reads package source, `.pth`, activation, `RECORD`, or direct-URL files. A
`no_detected_issues` result describes only the inspected static metadata; it is
not a runtime-health or security claim. See the full
[environment auditor contract](environment-auditor.md).

```yaml
profile: standard
integrations:
  environment: true
environment:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-projects
```

## Docker

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `docker_list_containers` | Optional bounded `limit`, optional `include_stopped` | Container ID, name, image tag, runtime status, health status, restart count | Requires explicit Docker integration; excludes labels, mounts, environment, and command data. |
| `docker_container_details` | Validated container name or ID | Selected lifecycle and health metadata | Uses the official Docker SDK; excludes labels, mounts, environment, and command data. |
| `docker_container_logs` | Validated container name or ID, optional bounded `tail` | Bounded recent stdout/stderr log text | Returned logs are untrusted data, bounded before decoding, and centrally redacted. |
| `docker_unhealthy_containers` | Optional bounded `limit` | Safe metadata for containers reporting `unhealthy` | Deterministic filter only; it never restarts or changes a container. |

Enable Docker inspection only when needed:

```yaml
profile: standard
integrations:
  docker: true
```

Install the optional SDK with `pip install -e ".[docker]"` (or `.[dev,docker]` for development). Docker API access, including a mounted Docker socket, is a high-privilege host boundary. Keep it local, grant the smallest access possible, and never expose the socket to untrusted software. No Docker mutation, exec, image, network, volume, label, mount, environment, or command-inspection tool is registered.

## Logs

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `logs_tail_file` | Absolute approved log `path`, optional bounded `lines` | Recent log lines | Uses dedicated approved log roots, extension/blocklist checks, file-size limits, record limits, and central redaction. |
| `logs_search` | Absolute approved log `path`, single-line literal `query`, optional bounded `limit`, optional `case_sensitive` | Numbered matching lines | Queries are literal only, limited to 200 characters, and never execute a user-supplied regular expression. |
| `logs_error_summary` | Absolute approved log `path`, optional bounded line window and group `limit` | Severity counts and repeated-line evidence groups | Deterministic keyword detection and redacted fingerprints; reports observations only and never claims root cause. |

Enable log inspection with a minimal, separate root set:

```yaml
profile: standard
integrations:
  logs: true
logs:
  approved_roots:
    - C:\\absolute\\path\\to\\application-logs
  allowed_extensions: [".log", ".txt", ".jsonl", ".out"]
  blocked_patterns: [".env", ".env.*", "*.pem", "*.key", "credentials*"]
```

Log output is untrusted data and is redacted before it reaches the client or audit storage. The module has no write, rotation, deletion, or generic command capability.

## Security scanners

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `security_scanner_inventory` | None | Availability of a fixed scanner allowlist | Resolves availability only; it does not execute a scanner or disclose executable paths. |
| `security_scan_repository` | Absolute approved `repository`, optional bounded `limit`, scanner fixed to `bandit` | Normalized Bandit findings without source-code excerpts | Requires explicit opt-in and a separate approved root. Copies the approved root's Bandit source files (`.py`/`.pyw`, skipping the directories Bandit skips) into a private temporary snapshot, then runs only `bandit -q -r <snapshot> -f json` there without a shell, with timeout/output limits and central redaction. On POSIX each path component is opened relative to its parent with `O_NOFOLLOW` (no symlinks are followed at all, so a swapped directory cannot redirect the read); on Windows, which lacks that, the file is resolved, checked, opened and verified to be the same file (a narrower but not fully closed race). Only single-link regular files are copied (FIFOs, devices and hard links are skipped), at most 5 MB each and 50 MB in total; skipped files are counted in `withheld_files` and `snapshot_truncated` is set when the total cap was hit. Neither its own name nor its target may match a blocked pattern. Findings for anything not in the snapshot are dropped and counted in `withheld_findings`. |
| `security_audit_agent_configs` | Absolute approved `path` (directory or file), optional `include_globs`, optional bounded `limit`, optional bounded `max_files` | Structured findings across `hidden_unicode`, `prompt_override`, `dangerous_execution`, `credential_or_exfil`, and `mcp_config_risk`, plus severity/category counts and scan stats | Requires `security_scanners` opt-in and an approved `security` root. Static in-process inspection only; opens path components with `O_NOFOLLOW` and `O_NONBLOCK` on POSIX (and link-free resolve-and-verify on Windows), accepts only single-link regular files within `max_file_bytes`, skips blocked filenames, redacts secrets, and escapes invisible/control codepoints in snippets. |

Enable the adapter only for the smallest scan root set:

```yaml
profile: standard
integrations:
  security_scanners: true
security:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-project
```

The current Version 1 adapter supports Bandit only. Inventory can report other local scanner availability, but no unlisted scanner can be invoked, no user-controlled scanner arguments are accepted, and no remediation or fix operation is registered.

`security_audit_agent_configs` runs entirely in-process without starting a subprocess. When given a directory, it discovers common agent instruction, prompt, skill, and MCP configuration files (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `PROMPT.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.github/instructions/*.md`, `.cursor/rules/*.md`, `.cursor/rules/*.mdc`, `skills/**/SKILL.md`, `prompts/**/*.md`, `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`) or filters by `include_globs`. It can also be run directly from the CLI or CI via `local-mcp-toolbox audit-agent-configs <path> [--json] [--fail-on low|medium|high|none] [--include <glob>] [--max-files <n>] [--max-file-bytes <n>] [--limit <n>]`.


### Agent config audit rules

Each finding has a stable rule ID, a category, and a severity. The same rules run in the MCP tool and the CLI.

| Rule ID | Category | Severity | What it flags |
| --- | --- | --- | --- |
| `AGENT-UNICODE-001` | `hidden_unicode` | High | Bidirectional control characters that can make text display in a different order than it is read |
| `AGENT-UNICODE-002` | `hidden_unicode` | High | Invisible Unicode tag characters (and variation selectors) that can hide text |
| `AGENT-UNICODE-003` | `hidden_unicode` | Medium | Zero-width characters, such as zero-width spaces or a byte-order mark in the middle of a file |
| `AGENT-UNICODE-004` | `hidden_unicode` | Medium | C0 or C1 control characters in a text file |
| `AGENT-PROMPT-001` | `prompt_override` | High | Text telling the agent to ignore or replace its earlier instructions |
| `AGENT-PROMPT-002` | `prompt_override` | High | Text telling the agent to hide actions or results from the user |
| `AGENT-PROMPT-003` | `prompt_override` | High | Text telling the agent to skip confirmation, approval, or safety checks |
| `AGENT-PROMPT-004` | `prompt_override` | High | An HTML comment that hides a directive, command, credential reference, or URL |
| `AGENT-EXEC-001` | `dangerous_execution` | High | A download piped straight into a shell, such as `curl ... \| sh` |
| `AGENT-EXEC-002` | `dangerous_execution` | High | Decoding Base64 or other encoded text and running it |
| `AGENT-EXEC-003` | `dangerous_execution` | High | An inline Python or Node one-liner that both fetches from the network and runs code |
| `AGENT-EXFIL-001` | `credential_or_exfil` | High | References to local credential stores (`.env`, SSH keys, cloud credential files) or cloud metadata endpoints |
| `AGENT-EXFIL-002` | `credential_or_exfil` | High | Webhook collector domains or commands that upload files to an outside host |
| `AGENT-MCP-001` | `mcp_config_risk` | Medium | An MCP config file that is not valid JSON, is nested too deeply, or has the wrong structure |
| `AGENT-MCP-002` | `mcp_config_risk` | High or Medium | A remote MCP server URL that uses plain HTTP (High) or another remote endpoint worth reviewing (Medium) |
| `AGENT-MCP-003` | `mcp_config_risk` | High or Medium | An MCP server started from a package that is not pinned to an exact version (for example `npx pkg@latest`) |
| `AGENT-MCP-004` | `mcp_config_risk` | High | An MCP server command wrapped in a shell, or environment variables that inject code (such as `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`) |
| `AGENT-MCP-005` | `mcp_config_risk` | High | A plaintext credential written inline in an MCP server URL, headers, or environment |

A finding is a prompt to review the file, not proof that it is malicious. Snippets are redacted before they are returned.

## Infrastructure

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `infra_detect_project_types` | Absolute approved `project` | Detected project types from recognized top-level marker names | Requires explicit infrastructure opt-in and a separate approved root; reads directory-entry names only. |
| `infra_configuration_inventory` | Absolute approved `project`, optional bounded `limit` | Recognized top-level configuration names and categories | Does not read configuration contents, traverse recursively, or follow project references. |

Enable top-level infrastructure metadata only for approved project roots:

```yaml
profile: standard
integrations:
  infrastructure: true
infrastructure:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-project
```

The current inventory recognizes common Docker, project-language, Terraform, Helm/Kustomize, Ansible, and GitHub Actions markers. It deliberately returns metadata only; deeper parsing and dependency analysis remain future work.

## Incident evidence

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `incident_extract_timeline` | Absolute approved incident-log `path`, optional bounded `lines` | Trailing observed lines with source timestamp and severity when detectable | Uses separate approved log roots, extension/blocklist checks, file/record limits, and central redaction. It does not reorder or infer missing timestamps. |
| `incident_summarize_evidence` | Absolute approved incident-log `path`, optional bounded line window and group `limit` | Severity counts, grouped high-severity observations, unknowns, and next checks | Deterministic only; returns no causal hypothesis, redacts samples before grouping, and labels confidence as observed log evidence only. |

Enable incident evidence tools only for dedicated log roots:

```yaml
profile: standard
integrations:
  incident: true
incident:
  approved_roots:
    - C:\\absolute\\path\\to\\incident-logs
```

No incident tool writes files, creates tickets, sends notifications, or changes infrastructure.
