# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## [1.5.1] - 2026-09-13

- Restore the CycloneDX UUID serial number required by GitHub's SBOM
  attestation parser.
- Validate the SBOM format, specification version, and UUID serial number in
  the build job before the immutable release bundle reaches the protected
  publish job.

## [1.5.0] - 2026-09-12

- Add an opt-in read-only GitHub integration for allowlisted repository,
  issue, and pull-request metadata through bounded API requests.
- Require separate GitHub, external-network, and exact repository allowlist
  authorization before any GitHub request is made.
- Add thread-safe, content-free aggregate request and latency metrics populated
  through the existing audit middleware.
- Add an opt-in Python virtual-environment auditor that reads only bounded
  `pyvenv.cfg` and installed distribution metadata, never executes the target,
  and refuses false missing-dependency claims when evidence is incomplete.
- Combine the pending checkout, Python setup, and artifact upload updates to
  version 7, plus the reviewed development and optional dependency ranges.
- Clarify the README, installation steps, manual startup behavior, and client
  connection process. Keep zero trust and least privilege explicit.
- Remove Kubernetes inspection because kubeconfig credential providers can
  execute commands or persist refreshed credentials outside the tool boundary.
- Remove generation capabilities because they are not read-only inspection.
- Collapse unknown metrics labels into a fixed bucket and apply the central
  response-size boundary to metrics snapshots.
- Reject every authenticated GitHub redirect to keep credentials bound to the
  fixed API origin.
- Add authenticated loopback HTTP with strict host, origin, token, session, and
  request-size controls.

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

[1.5.1]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/chriswayneh/local-mcp-toolbox/releases/tag/v1.0.0
