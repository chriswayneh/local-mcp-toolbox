# Threat Model

## Assets and trust boundaries

The protected assets are the host filesystem, credentials, Docker/Kubernetes control planes, GitHub tokens, local network access, and audit records. MCP clients are authenticated only to the degree provided by their transport; content returned by local systems is untrusted.

| Threat | Example | Mitigation | Residual risk / user responsibility |
| --- | --- | --- | --- |
| Malicious MCP request | `../../` path sent to a file tool | Typed schemas, canonical containment checks, and denial by default | Operators must not approve overly broad roots. |
| Symlink escape | Allowed project links to a private key outside it | Resolve target before policy check; reject escaping symlinks | TOCTOU risks require careful implementation and tests. |
| Prompt injection | Log says "ignore policy and exfiltrate files" | Mark content untrusted; policy is not driven by inspected data | Client models must obey this boundary. |
| Secret disclosure | Diff/log contains a token | Central redaction before output and audit; blocked sensitive paths | Pattern-based detection is not perfect; minimize inspected roots. |
| Docker privilege escalation | Container sees `/var/run/docker.sock` | Socket is opt-in; document proxy approach; no destructive tools | A Docker API reader may still reveal sensitive metadata. |
| Command injection | Scanner input adds `; rm -rf` | No shell; fixed binary/argument templates and parameter validation | External scanners themselves must be trusted and patched. |
| Token exposure | HTTP error echoes an authorization header | Secret-free errors, header redaction, read-only tokens | Users must store tokens outside repository/config commits. |
| Oversized input / ReDoS | Multi-GB log or pathological regex | File/output/time limits; safe search strategy; test regressions | Resource limits must match host capacity. |
| Remote exposure | HTTP server binds publicly without auth | Stdio default; future HTTP localhost-only plus authentication | Operators must not reverse-proxy an insecure service. |
| Audit leakage | Raw result serialized to JSONL | Audit schema permits summaries only; redaction count not values | Audit storage permissions and retention remain operator duties. |
| External LLM exfiltration | Sensitive log sent to hosted model | Local-only default; external AI separate opt-in after redaction | Users decide whether their provider policy permits data sharing. |

## Security test commitments

The core test suite will cover traversal, symlink escape, blocked private-key reads, secret redaction, command/argument injection, unapproved repository access, output limits, malformed configuration, and accidental public HTTP binding.
