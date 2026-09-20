# Roadmap

## Phase 1: Discovery and Architecture

- [x] Inspect empty workspace and establish a Git repository
- [x] Select Python 3.12 and official MCP SDK v2
- [x] Define Version 1 scope, architecture, security model, and threat model
- [x] Create configuration profiles and package/test scaffold
- [x] Review architecture before core implementation

## Phase 2: Secure Core Foundation

- [x] Implement typed settings, safe YAML loading, and fail-closed profile invariants
- [x] Implement centralized permission checks for approved paths and integrations
- [x] Implement centralized secret redaction and non-reversible fingerprints
- [x] Implement structured response and error contracts
- [x] Implement sanitized JSONL audit logging
- [x] Add unit and adversarial security regression tests
- [x] Validate with tests, formatting, lint, typing, Bandit, and dependency audit

## Phase 3: MCP Server

- [x] Configure the official MCP SDK and stdio transport
- [x] Register safe server metadata, resources, and reusable prompts
- [x] Add server startup validation and MCP integration tests

## Phase 4: Version 1 Tools

- [x] Typed settings, permission service, redaction, audit records, contracts, and safe errors
- [x] MCP stdio server, resources, prompts, and startup validation
- [x] System metadata and approved-root filesystem inspection
- [x] Approved-repository, read-only Git inspection
- [x] Opt-in Docker metadata, health, and bounded-log inspection
- [x] Dedicated approved-root log tails, search, and deterministic error summaries
- [x] Security-scanner inventory and fixed-command Bandit adapter with normalized findings
- [x] Top-level infrastructure project detection and configuration inventory
- [x] Incident timeline extraction and deterministic evidence summaries

## Phase 5: CLI and Docker Deployment

- [x] Add operator doctor checks
- [x] Add cross-platform task commands
- [x] Add production and development Dockerfiles
- [x] Add Docker Compose profiles, health checks, non-root runtime, and an audit volume
- [x] Document native execution, socket-proxy use, and direct-socket risk
- [x] Test native and containerized startup

## Phase 6: Documentation and Demo

- [x] Add complete client-configuration examples and operator troubleshooting guides
- [x] Add a safe demo application, logs, and intentionally insecure test fixtures
- [x] Add architecture, permission, and deployment diagrams plus a walkthrough

## Phase 7: CI and Release Preparation

- [x] Add GitHub Actions for quality, security, documentation, and build validation
- [x] Add Dependabot, issue and pull-request templates, release controls, and SBOM generation
- [x] Validate documentation commands and publish the Version 1 release checklist

## Version 1.0: Stable Release

- [x] Complete the secure read-only Version 1 feature scope
- [x] Validate on Python 3.12 and 3.13 with quality, security, documentation, and package checks
- [x] Publish release documentation, SBOM generation, and protected release controls

## Version 1.5: Connected Integrations

The v1.5 feature scope is complete. The v1.5.2 closeout fixes default request
limits and the documented container/proxy deployment. The supported contract,
acceptance evidence, and operational limits are recorded in
[release and operations](docs/release-1.5.md).

- [x] Read-only GitHub integration
- [x] Aggregate runtime metrics
- [x] Read-only Python virtual-environment metadata auditor
- [x] Authenticated localhost HTTP
- [x] Remove integrations that cannot enforce the inspection-only contract
- [x] Harden audit rotation and release provenance controls

## Optional future proposals, not release requirements

The ideas below are not committed deliverables, scheduled releases, or gaps in
v1.5 acceptance. Maintenance of v1.5 remains focused on defects, dependency
security, documentation, and preserving the existing read-only contract.

### Possible Version 2: Operational Analysis

- Deterministic correlation, architecture and runbook generation, optional dashboard.

### Possible Version 3: Separate Action Surface

- Explicitly approved, dry-run-capable scoped actions with signed records would
  require a separate product/security decision and trust boundary. No mutation
  capability is part of the supported v1.5 server or its completion criteria.

### Possible Version 4: Enterprise

- Multi-user auth, OIDC, centralized audit, policy-as-code, and enterprise integrations.
