# Security Model

## Principles

1. **Least privilege:** integration, directory, module, and result-size permissions are independently checked.
2. **Fail closed:** missing configuration, invalid canonical paths, unavailable integrations, and unrecognized profiles produce safe denials.
3. **Read-only first:** The toolbox cannot make commits, restart containers, modify files, or apply remote resources.
4. **No ambient authority:** each external integration is opt-in; no Docker socket, network, token, or cluster is assumed.
5. **Treat retrieved content as hostile:** logs, source files, commit messages, labels, and issue content remain data, never instructions.

## Permission profiles

| Profile | Filesystem | Integrations | Network | Writes |
| --- | --- | --- | --- | --- |
| Restricted (default) | Explicit roots only | None | None | Never |
| Standard | Explicit roots only | Optional read-only Git, GitHub, and Docker | Fixed remote APIs only with separate network opt-in | Never |
| Advanced (future) | Explicit roots only | Explicit allowlists | Explicit destinations | Separate approval design required |

## Data protections

Filesystem access resolves the canonical target before checking it against approved canonical roots. Symbolic links and Windows junctions that escape those roots are denied. Sensitive filename patterns, including alternate data streams, trailing-dot aliases, and potential 8.3 aliases, are enforced before directory or file access. Directory traversal and file reads are bounded before results are serialized.

Redaction recognizes PEM private-key blocks, API/service credentials, authorization headers, connection strings, bearer tokens, cookies, and common cloud-token formats. A non-reversible fingerprint may be provided only for correlation. Audit events record sanitized argument shape, client identifier, actual result decision, duration, counts, and redaction count. Events are size-bounded and durably appended to strict JSONL. Daily or size-based rotation closes immutable timestamped segments instead of rewriting the active file. Retention deletes only expired closed segments.

## Command and integration policy

There is no `exec`, `shell`, `terminal`, or `run_command` MCP tool. If a later scanner adapter invokes an installed executable, it will use a fixed program path and argument array, an allowlisted argument template, scrubbed environment, time limit, output cap, and audit event. It will not invoke a shell.

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
