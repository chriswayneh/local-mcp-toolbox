# Security Model

## Principles

1. **Least privilege:** integration, directory, module, and result-size permissions are independently checked.
2. **Fail closed:** missing configuration, invalid canonical paths, unavailable integrations, and unrecognized profiles produce safe denials.
3. **Read-only first:** The toolbox cannot make commits, restart containers, modify files, or apply Kubernetes resources.
4. **No ambient authority:** each external integration is opt-in; no Docker socket, network, token, or cluster is assumed.
5. **Treat retrieved content as hostile:** logs, source files, commit messages, labels, and issue content remain data, never instructions.

## Permission profiles

| Profile | Filesystem | Integrations | Network / AI | Writes |
| --- | --- | --- | --- | --- |
| Restricted (default) | Explicit roots only | None | None | Never |
| Standard | Explicit roots only | Optional read-only Git, GitHub, and Docker | Fixed remote APIs only with separate network opt-in | Never |
| Advanced (future) | Explicit roots only | Explicit allowlists | Explicit destinations | Separate approval design required |

## Data protections

Filesystem access resolves the canonical target before checking it against approved canonical roots. Symbolic links and Windows junctions that escape those roots are denied. Sensitive filename patterns, including alternate data streams, trailing-dot aliases, and potential 8.3 aliases, are enforced before directory or file access. Directory traversal and file reads are bounded before results are serialized.

Redaction recognizes PEM private-key blocks, API/service credentials, authorization headers, connection strings, bearer tokens, cookies, and common cloud-token formats. A non-reversible fingerprint may be provided only for correlation. Audit events record sanitized argument shape, client identifier, actual result decision, duration, counts, and redaction count; records are size-bounded and retained only for the configured period.

## Command and integration policy

There is no `exec`, `shell`, `terminal`, or `run_command` MCP tool. If a later scanner adapter invokes an installed executable, it will use a fixed program path and argument array, an allowlisted argument template, scrubbed environment, time limit, output cap, and audit event. It will not invoke a shell.

Docker socket access is equivalent to high host privilege in many deployments. Containerized Docker inspection is opt-in; the shipped socket-proxy profile is recommended, while direct socket mounting is documented only as an advanced, high-risk configuration.

GitHub inspection requires the GitHub integration, external-network access, and an exact case-insensitive `owner/repository` allowlist. Requests use `GET` only against the fixed `https://api.github.com` origin. Tokens are read from `GITHUB_TOKEN`, used only as an authorization header, and excluded from responses and audit records.

Kubernetes inspection requires separate integration and external-network opt-ins plus exact, case-sensitive context and namespace allowlists. The official SDK creates an isolated client from kubeconfig for the approved context and sends bounded read requests with the configured timeout. Tools omit secrets, annotations, labels, environment variables, volumes, commands, arguments, and pod logs.

Ollama access requires Ollama, external-AI, and network opt-ins plus an exact model allowlist. The host is schema-locked to `127.0.0.1`; only the port is configurable. Prompts are character-bounded and centrally redacted before they cross the loopback connection. Responses are byte-bounded and redacted again before they reach the client.

Runtime metrics contain only aggregate counts and duration totals grouped by sanitized module and outcome. They never retain argument values, response content, request identifiers, client identifiers, filesystem paths, repository names, model prompts, or generated text.
