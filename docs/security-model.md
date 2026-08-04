# Security Model

## Principles

1. **Least privilege:** integration, directory, module, and result-size permissions are independently checked.
2. **Fail closed:** missing configuration, invalid canonical paths, unavailable integrations, and unrecognized profiles produce safe denials.
3. **Read-only first:** Version 1 cannot make commits, restart containers, modify files, or apply Kubernetes resources.
4. **No ambient authority:** each external integration is opt-in; no Docker socket, network, token, or cluster is assumed.
5. **Treat retrieved content as hostile:** logs, source files, commit messages, labels, and issue content remain data, never instructions.

## Permission profiles

| Profile | Filesystem | Integrations | Network / AI | Writes |
| --- | --- | --- | --- | --- |
| Restricted (default) | Explicit roots only | None | None | Never |
| Standard | Explicit roots only | Optional read-only Git and Docker | Local-only when explicitly enabled | Never |
| Advanced (future) | Explicit roots only | Explicit allowlists | Explicit destinations | Separate approval design required |

## Data protections

Filesystem access resolves the canonical target before checking it against approved canonical roots. Symbolic links that escape those roots are denied. Sensitive filename patterns and maximum file sizes are enforced before content reads.

Redaction recognizes credentials, private keys, connection strings, bearer tokens, cookies, and common cloud-token formats. A non-reversible fingerprint may be provided only for correlation. Audit events record tool identity, decision, duration, counts, and redaction count, never original secret values.

## Command and integration policy

There is no `exec`, `shell`, `terminal`, or `run_command` MCP tool. If a later scanner adapter invokes an installed executable, it will use a fixed program path and argument array, an allowlisted argument template, scrubbed environment, time limit, output cap, and audit event. It will not invoke a shell.

Docker socket access is equivalent to high host privilege in many deployments. Containerized Docker support is deferred until it can recommend a constrained socket proxy; unrestricted socket mounting will not be a default configuration.
