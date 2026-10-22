# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- Git tools now pin Git to the approved repository: they pass explicit
  `--git-dir=<repo>/.git` and `--work-tree=<repo>`, set
  `GIT_CEILING_DIRECTORIES`, and refuse a repository whose `.git` is a file
  (`gitdir: ...`) or a symlink. Before, a repository-local `core.worktree` or a
  `.git` file could point Git at a directory or repository outside the
  allowlist. Linked worktrees and submodule checkouts can no longer be approved
  directly; approve the main working tree instead.
- Git tools also refuse a `.git` directory that contains a `commondir` file, or
  whose `objects/info/alternates` points outside the approved repository, since
  either makes Git read refs, objects, or config from somewhere else.
- The alternates check follows the whole alternates chain, including relative
  entries, so a store inside the repository cannot forward to one outside.
  Every refusal now names its reason (symlinked `.git`, `gitdir:` file from a
  linked worktree or submodule checkout, `commondir`, or outside alternates such
  as `git clone --shared`/`--reference`).
- A symlink at `.git/objects`, `refs`, `HEAD`, `config`, `packed-refs`, `logs`,
  `info`, or `worktrees` is refused, and `objects` and `refs` must resolve
  inside the repository. The containment check runs again right before Git
  starts and after it exits, and if the `.git` directory, its object or ref
  store, `commondir`, or alternates changed in between, the output is discarded
  and the call is refused.
- A symlink anywhere under `.git/objects` or `.git/refs` (for example a loose
  object fan-out directory or `objects/pack`) is refused. `http-alternates` and a
  `GIT_ALTERNATE_OBJECT_DIRECTORIES` setting in the server environment each get
  their own refusal reason.
- Git runs with `GIT_COMMON_DIR` and `GIT_OBJECT_DIRECTORY` pinned. On Linux it
  reads objects through a private view of descriptors opened without following
  links, closing the race where `objects/pack` was swapped for a symlink while
  Git ran. The full containment check now runs once per call; before and after
  exec a cheap fingerprint of object and ref directories must still match, and
  the cost does not grow with the number of packs. Accepted risks (hardlinked packs or objects, and alternate
  stores inside the repository) are documented in the security model.
- A symlinked loose object anywhere under `.git/objects/<hh>/` is refused, and
  repositories with more than 50,000 loose objects are refused with a
  "run `git gc`" message. Anything in `objects/pack` that is not a regular file
  (for example a FIFO) is refused; pack entries are opened non-blocking, so such
  a file can no longer hang the server.
- **Git tools are now Linux-only.** On macOS and Windows they refuse with
  `UNSUPPORTED_OPERATION` and never start Git, because there a `.git` folder
  swapped and quickly swapped back while Git runs could go unnoticed and leak
  another repository's data. Run the toolbox in the Linux container to use them
  on those hosts. Tracked in [#44](https://github.com/chriswayneh/local-mcp-toolbox/issues/44).

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
