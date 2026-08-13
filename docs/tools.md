# Tool Catalog

All current tools are read-only. Every returned response uses the common envelope with a summary, structured data, and metadata that reports redactions, truncation, and whether returned data is untrusted.

## System

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `system_info` | None | OS, architecture, Python version, CPU count, capture time | Does not return environment variables, usernames, home paths, or processes. |
| `disk_usage` | None | Aggregate bytes total, used, and free for the server working volume | Does not enumerate file paths. |
| `installed_developer_tools` | None | Availability of a fixed allowlist: Git, Docker, kubectl, Python, Node, npm, Terraform | Resolves availability only; does not execute programs or disclose executable paths. |

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

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `git_repository_status` | Absolute approved `repository` path | Current branch tracking metadata and bounded changed-file status | Requires Git integration, filesystem-root containment, and exact repository allowlist match. Uses `git status --porcelain=v1 --branch`. |
| `git_current_branch` | Absolute approved `repository` path | Branch name or detached `HEAD` short commit | Uses fixed `git branch --show-current` / `git rev-parse --short HEAD` arguments. |
| `git_recent_commits` | Absolute approved `repository` path, optional bounded `limit` | Commit hashes, author, ISO timestamp, and subject | Uses a fixed `git log` format. Commit messages and identities are untrusted and redacted. |
| `git_diff_summary` | Absolute approved `repository` path | Per-file added/deleted-line counts for unstaged tracked changes | Uses `git diff --numstat`; never returns diff content. |

The Git module invokes only fixed, read-only argument templates through `subprocess` with `shell=False`, a scrubbed non-interactive environment, a configured timeout, and a configured output cap. It has no generic command tool.

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
| `security_scan_repository` | Absolute approved `repository`, optional bounded `limit`, scanner fixed to `bandit` | Normalized Bandit findings without source-code excerpts | Requires explicit opt-in and a separate approved root. Uses only `bandit -q -r <root> -f json` without a shell, timeout/output limits, and central redaction. |

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

No incident tool writes files, creates tickets, sends notifications, changes infrastructure, or invokes an AI provider.
