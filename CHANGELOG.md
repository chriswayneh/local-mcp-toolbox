# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

- Add an opt-in read-only GitHub integration for allowlisted repository,
  issue, and pull-request metadata through bounded API requests.
- Require separate GitHub, external-network, and exact repository allowlist
  authorization before any GitHub request is made.
- Add metadata-only Kubernetes cluster, namespace, pod, and deployment tools
  using the official SDK, bounded reads, and exact context/namespace allowlists.
- Combine the pending checkout, Python setup, and artifact upload updates to
  version 7, plus the reviewed development and optional dependency ranges.
- Clarify the README, installation steps, manual startup behavior, and client
  connection process. Keep zero trust and least privilege explicit.

## [1.0.0] - 2026-08-13

First stable release of the secure, local-first, read-only MCP toolbox.

### Added

- MCP stdio server with typed tools, resources, prompts, startup validation,
  safe response contracts, and sanitized audit middleware.
- Deny-by-default profiles, canonical approved-root checks, integration
  allowlists, bounded outputs, and centralized secret redaction.
- Read-only system, filesystem, Git, Docker, log, security, infrastructure,
  and incident evidence tools.
- Native and hardened container workflows, socket-proxy guidance, operator
  diagnostics, and cross-platform task commands.
- Client configuration examples for Codex, Claude Desktop, Claude Code, and
  Visual Studio Code.
- Synthetic demo services, logs, and explicitly non-production insecure
  inventory fixtures.
- GitHub Actions quality, security, documentation, package, SBOM, and protected
  release workflows plus Dependabot and contribution templates.

### Security

- Version 1 exposes no generic shell, mutation, container lifecycle, or remote
  network tool.
- Tool results are treated as untrusted evidence, bounded, redacted, and
  represented through structured contracts.
- GitHub private vulnerability reporting is enabled for confidential reports.

[1.0.0]: https://github.com/chriswayneh/local-mcp-toolbox/releases/tag/v1.0.0
