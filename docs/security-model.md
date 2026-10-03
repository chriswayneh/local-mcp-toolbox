# Security Model

## Limits in force

The server enforces the YAML file passed to `--config`. `config/default.yml` has the same policy values as `config/restricted.yml`. `profile: advanced` is rejected and does not enable extra tools.

### Shipped restricted profile

| Control | Value |
| --- | --- |
| Filesystem roots | None. File tools deny every path. |
| Integrations | Docker, Git, GitHub, logs, scanners, infrastructure, incidents, Python environments, and external network are off. |
| Readable extensions | `.md`, `.txt`, `.json`, `.yaml`, `.yml`, `.toml`, `.py`, `.ts` |
| Blocked names | `.env`, `.env.*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `credentials*` |
| File read | 240,000 bytes |
| Directory scan | 500 entries, then stop |
| Response records | 100 |
| Response size | 262,144 bytes |
| Subprocess and GitHub timeout | 10 seconds |
| Home-path redaction | On |
| Email and IP redaction | Off |
| Audit retention | 30 days, closed segments only |
| Audit event | 8,192 bytes, fixed in code |
| Audit segment | 8,388,608 bytes, fixed in code |
| HTTP | Disabled |

A relative `audit.path` is resolved from the configuration file's directory, not the process working directory. The first audit write creates that directory. `doctor` does not.

### Schema ceilings

These are the maximums a profile may set. They are not the running limits.

| Setting | Ceiling | Shipped value |
| --- | --- | --- |
| `max_file_bytes` on filesystem, log, security, infrastructure, and incident sections | 104,857,600 | 240,000 on the filesystem section |
| `max_directory_entries` | 10,000 | 500 on the filesystem section |
| `limits.max_records` | 10,000 | 100 |
| `limits.max_output_bytes` | 10,485,760 | 262,144 |
| `limits.timeout_seconds` | 300 | 10 |
| `audit.retention_days` | 3,650 | 30 |
| `http.max_request_body_bytes` | 4,194,304 | 262,144, and HTTP is off |
| `http.session_idle_seconds` | 3,600 | 300 |
| `http.max_sessions` | 256 | 16 |
| `http.host` | `127.0.0.1` or `::1` only | `127.0.0.1` |

### Defaults that apply only after an integration is enabled

Omitting a section does not turn the integration on.

| Section | Default when the section is omitted |
| --- | --- |
| Logs and incidents, `max_file_bytes` | 5,242,880 |
| Logs and incidents, extensions | `.jsonl`, `.log`, `.out`, `.txt` |
| Scanners and infrastructure, `max_file_bytes` | 240,000. `config/standard.yml` sets 1,048,576, leaves the integrations off, and leaves their roots empty. |
| Python environments | 1,000 directory entries, 500 metadata files, 32,768 config bytes, 262,144 metadata bytes, 5,000 dependency records, and 500 dependencies per distribution. The integration is still off. |

Blocked-name lists are operator policy. Removing a pattern removes that filename block. Redaction does not replace it.

## Principles

1. **Least privilege:** integration, directory, module, and result-size permissions are independently checked.
2. **Fail closed:** missing configuration, invalid canonical paths, unavailable integrations, and unrecognized profiles produce safe denials.
3. **Read-only first:** The toolbox cannot make commits, restart containers, modify files, or apply remote resources.
4. **No ambient authority:** each external integration is opt-in; no Docker socket, network, or token is assumed. There is no Kubernetes or cluster client.
5. **Treat retrieved content as hostile:** logs, source files, commit messages, labels, and issue content remain data, never instructions.

## Permission profiles

| Profile | Filesystem | Integrations | Network | Writes |
| --- | --- | --- | --- | --- |
| Restricted (default) | Explicit roots only | None | None | Never |
| Standard | Explicit roots only | Each read-only integration stays off until its own switch and allowlist are set | None until `external_network` is enabled. GitHub then calls only `https://api.github.com` | Never |
| `advanced` | Not accepted | Not accepted | Not accepted | The name is rejected at load time. It does not grant extra tools or skip checks. |

## Data protections

Filesystem access resolves the canonical target before checking it against approved canonical roots. Symbolic links and Windows junctions that escape those roots are denied. Sensitive filename patterns, including alternate data streams, trailing-dot aliases, and potential 8.3 aliases, are enforced before directory or file access. Directory traversal and file reads are bounded before results are serialized.

Redaction recognizes PEM private-key blocks, API/service credentials, authorization headers, connection strings, bearer tokens, cookies, and common cloud-token formats. A non-reversible fingerprint may be provided only for correlation. Audit events record sanitized argument shape, client identifier, actual result decision, duration, counts, and redaction count. Events are size-bounded and durably appended to strict JSONL. Daily or size-based rotation closes immutable timestamped segments instead of rewriting the active file. Retention deletes only expired closed segments.

## Command and integration policy

There is no `exec`, `shell`, `terminal`, or `run_command` MCP tool. The shipped Git and Bandit adapters use fixed command templates, scrubbed environments, time limits, output caps, and audit events with `shell=False`. Read-only does not mean no subprocesses; it means clients cannot supply arbitrary commands or request mutations.

Docker socket access is equivalent to high host privilege in many deployments. Containerized Docker inspection is opt-in; the shipped socket-proxy profile is recommended, while direct socket mounting is documented only as an advanced, high-risk configuration.

GitHub inspection requires the GitHub integration, external-network access, and an exact case-insensitive `owner/repository` allowlist. Requests use `GET` only against the fixed `https://api.github.com` origin. Tokens are read from `GITHUB_TOKEN`, used only as an authorization header, and excluded from responses and audit records.

Version 1.5 removed Kubernetes inspection after review showed that ambient kubeconfig credential providers can execute commands and persist refreshed credentials. It also removed generation capabilities because they do not meet a strict inspection-only definition. Neither surface is registered or configurable.

Authenticated HTTP is separately disabled by default, binds only to a literal
loopback address, requires one strict bearer token on every request, and enforces
exact Host and Origin allowlists. The token is referenced by environment-variable
name, hashed immediately at startup, and never retained as plaintext. Request
bodies, sessions, and idle time are bounded. See [HTTP transport](http-transport.md).

Python environment auditing uses a separate approved-root policy and reads only
fixed-shape `pyvenv.cfg` and `.dist-info/METADATA` paths. The target interpreter,
Pip, activation scripts, package source, imports, subprocesses, and network are
never used. Incomplete evidence can produce only `partial` or `unverifiable`
absence results, never a false missing-dependency claim.

Runtime metrics contain only aggregate counts and duration totals grouped by sanitized module and outcome. They never retain argument values, response content, request identifiers, client identifiers, filesystem paths, repository names, model prompts, or generated text.
