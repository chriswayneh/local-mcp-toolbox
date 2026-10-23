# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- `security_scan_repository` no longer reports findings for files outside the
  approved scan root or files that match a blocked pattern. Bandit follows
  symlinks on its own, so a link inside the root could pull in a file from
  elsewhere, and the result used to show it by file name. Those findings are
  now left out, and the response has a `withheld_findings` count so you can
  see that some were skipped.
- Bandit now scans a private copy of only the `.py`/`.pyw` files that are
  authorized when the scan starts, instead of the live directory. Before, the
  path check ran after Bandit had read the files, so a symlink swapped during or
  after the scan could slip an outside file's finding through, and a link
  retargeted between checks could make the whole scan return an error. Findings
  are now matched back to the copied files, so neither can happen.
- The security scan snapshot also refuses a symlink whose own name matches a
  blocked pattern, even when it points at an allowed file.
- The security scan snapshot now opens every path component without following
  symlinks (POSIX), so a directory swapped between check and open cannot leak
  an outside file; Windows keeps a resolve-and-verify fallback. FIFOs, devices
  and hard-linked files are skipped (a FIFO no longer hangs the scan), files
  over 5 MB or past a 50 MB total are withheld, and the response reports
  `withheld_files` and `snapshot_truncated`.
- Over-long or post-redaction-expanded audit identifiers (`request_id`,
  `tool_name`, `tool_module`, `client_identifier`) and argument keys no longer
  break the request or drop the audit record; values exceeding their field limit
  before or after redaction are stored as a deterministic `sha256:` digest, and
  dictionary keys in audit summaries and `Redactor.redact_value` are redacted
  and counted alongside values.

## [1.5.3] - 2026-10-04

- Reject `profile: advanced` when configuration is loaded. It is not an elevated
  mode.
- Document the shipped restricted-profile limits, schema ceilings, inactive
  integration defaults, and the fact that email and IP redaction are off unless
  enabled. The 1.0.0 tag is not a security-fix line.
- Make `doctor` report `attention` when any check warns, instead of `ready`.

## [1.5.2] - 2026-09-20

- Align log-summary and incident default windows with the existing 100-record
  policy limit. Explicit oversized requests remain rejected.
- Repair the Docker proxy image reference, pin its digest, and provide bounded
  temporary storage without removing read-only or capability restrictions.
- Include and select the existing Docker-only container policy in opt-in profiles.
- Read image names from container metadata instead of triggering a disallowed
  image API request through the SDK.
- Add real stdio/HTTP acceptance tests, reproducible container acceptance, and
  release operations documentation with explicit verification limitations.
- Separate completed v1.5 scope from optional future roadmap proposals.

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
[1.5.2]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.1...v1.5.2
[1.5.0]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/chriswayneh/local-mcp-toolbox/releases/tag/v1.0.0
