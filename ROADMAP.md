# Roadmap

## Phase 1 — Discovery and Architecture

- [x] Inspect empty workspace and establish a Git repository
- [x] Select Python 3.12 and official MCP SDK v2
- [x] Define Version 1 scope, architecture, security model, and threat model
- [x] Create configuration profiles and package/test scaffold
- [x] Review architecture before core implementation

## Phase 2 — Secure Core Foundation

- [x] Implement typed settings, safe YAML loading, and fail-closed profile invariants
- [x] Implement centralized permission checks for approved paths and integrations
- [x] Implement centralized secret redaction and non-reversible fingerprints
- [x] Implement structured response and error contracts
- [x] Implement sanitized JSONL audit logging
- [x] Add unit and adversarial security regression tests
- [x] Validate with tests, formatting, lint, typing, Bandit, and dependency audit

## Phase 3 — MCP Server

- [x] Configure the official MCP SDK and stdio transport
- [x] Register safe server metadata, resources, and reusable prompts
- [x] Add server startup validation and MCP integration tests

## Version 1.0 — Secure Read-Only Core

- [x] Typed settings, permission service, redaction, audit records, contracts, and safe errors
- [x] MCP stdio server, resources, prompts, and startup validation
- [x] System metadata and approved-root filesystem inspection
- [ ] Git, Docker, logs, scanners, infrastructure, and incident modules
- [ ] CLI, doctor, Docker packaging, docs, demo, and security regressions

## Version 1.5 — Connected Integrations

- [ ] Read-only GitHub and Kubernetes integrations
- [ ] Local Ollama provider, metrics, authenticated localhost HTTP

## Version 2.0 — Operations Intelligence

- [ ] Correlation, AI-assisted narratives, architecture/runbook generation, optional dashboard

## Version 3.0 — Controlled Actions

- [ ] Explicitly approved, dry-run-capable scoped actions with signed records

## Version 4.0 — Enterprise

- [ ] Multi-user auth, OIDC, centralized audit, policy-as-code, and enterprise integrations
