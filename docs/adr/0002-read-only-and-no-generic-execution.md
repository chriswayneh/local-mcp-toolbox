# ADR 0002: Read-only tools and no generic command execution in Version 1

- **Status:** Accepted
- **Date:** 2026-08-03

## Decision

Version 1 exposes only read-only, narrowly scoped tools. It will not register generic shell, terminal, or command execution tools, and it will not mutate files, Git, Docker, or Kubernetes.

## Rationale

A broad execution tool makes prompt injection, command injection, and accidental destructive actions difficult to contain and audit. Narrow read-only operations have clear input contracts and can be independently authorized.

## Consequences

Some troubleshooting tasks require operators to run remediation themselves. Future controlled actions require a separate threat model, explicit operator approval, dry-run behavior, and signed/auditable decision records.
