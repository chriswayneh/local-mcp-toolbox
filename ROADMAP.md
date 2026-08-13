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

## Phase 4 — Version 1 Tools

- [x] Typed settings, permission service, redaction, audit records, contracts, and safe errors
- [x] MCP stdio server, resources, prompts, and startup validation
- [x] System metadata and approved-root filesystem inspection
- [x] Approved-repository, read-only Git inspection
- [x] Opt-in Docker metadata, health, and bounded-log inspection
- [x] Dedicated approved-root log tails, search, and deterministic error summaries
- [x] Security-scanner inventory and fixed-command Bandit adapter with normalized findings
- [x] Top-level infrastructure project detection and configuration inventory
- [x] Incident timeline extraction and deterministic evidence summaries

## Phase 5 — CLI and Docker Deployment

- [x] Add operator doctor checks
- [x] Add cross-platform task commands
- [x] Add production and development Dockerfiles
- [x] Add Docker Compose profiles, health checks, non-root runtime, and an audit volume
- [x] Document native execution, socket-proxy use, and direct-socket risk
- [x] Test native and containerized startup

## Phase 6 — Documentation and Demo

- [x] Add complete client-configuration examples and operator troubleshooting guides
- [x] Add a safe demo application, logs, and intentionally insecure test fixtures
- [x] Add architecture, permission, and deployment diagrams plus a walkthrough

## Phase 7 — CI and Release Preparation

- [x] Add GitHub Actions for quality, security, documentation, and build validation
- [x] Add Dependabot, issue and pull-request templates, release controls, and SBOM generation
- [x] Validate documentation commands and publish the Version 1 release checklist

## Version 1.0 — Stable Release

- [x] Complete the secure read-only Version 1 feature scope
- [x] Validate on Python 3.12 and 3.13 with quality, security, documentation, and package checks
- [x] Publish release documentation, SBOM generation, and protected release controls

## Version 1.5 — Connected Integrations

- [ ] Read-only GitHub and Kubernetes integrations
- [ ] Local Ollama provider, metrics, authenticated localhost HTTP

## Version 2.0 — Operations Intelligence

- [ ] Correlation, AI-assisted narratives, architecture/runbook generation, optional dashboard

## Version 3.0 — Controlled Actions

- [ ] Explicitly approved, dry-run-capable scoped actions with signed records

## Version 4.0 — Enterprise

- [ ] Multi-user auth, OIDC, centralized audit, policy-as-code, and enterprise integrations
